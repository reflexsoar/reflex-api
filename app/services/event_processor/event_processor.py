''' 
/app/services/event_processor/event-processor.py
EventProcessor maintains an ingest Queue that stores Events as dictionaries
upon which a set of Event processing workers handle the task of pushing the 
Event into the Reflex system.  Events that are done processing are pushed to the
Pusher queue of the EventPusher service.
'''

import os
import copy
import time
import hashlib
import datetime
import logging
from multiprocessing import Process
from app.api_v2.model import (
    Event,
    EventRule,
    CloseReason,
    Case
)
from app.api_v2.rql import (
    QueryParser,
    RQLSearch
)

# Elastic or Opensearch
if os.getenv('REFLEX_ES_DISTRO') == 'opensearch':
    from opensearch_dsl import connections
else:
    from elasticsearch_dsl import connections

class EventProcessor(object):
    ''' EventProcessor maintains an ingest Queue that stores Events as dictionaries
    upon which a set of Event processing workers handle the task of pushing the 
    Event into the Reflex system.  Events that are done processing are pushed to the
    Pusher queue of the EventPusher service.

    >>> event_processor = EventProcessor(app, queue=QueueObject)

    If building Flask apps on the fly

    >>> event_processor = EventProcessor()
    >>> event_processor.init_app(app, queue=QueueObject)
    '''


    def __init__(self, app=None, log_level="DEBUG", event_queue=None, pusher_queue=None, *args, **defaults):
        ''' Initialize the EventProcessor '''

        log_levels = {
            'DEBUG': logging.DEBUG,
            'ERROR': logging.ERROR,
            'INFO': logging.INFO
        }

        ch = logging.StreamHandler()
        ch.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
        
        self.logger = logging.getLogger(self.__class__.__name__)
        self.logger.addHandler(ch)
        self.logger.setLevel(log_levels[log_level])
        
        if app:
            self.init_app(app, **defaults)

        self.worker_count = 10
        self.event_queue = event_queue
        self.pusher_queue = pusher_queue
        self.workers = []
        self.event_cache = {}


    def init_app(self, app, **defaults):
        ''' Initialize the EventProcessor from within an application factory '''
        self.app = app
        config = self.app.config.get('EVENT_PROCESSOR', {})

        logging.info('EventProcessor Started')

        # Process default settings
        for k in defaults:
            if hasattr(self, k):
                setattr(self, k, defaults[k])

        # Override via configuration items
        if 'MAX_QUEUE_SIZE' in config:
            self.max_queue_size = config['MAX_QUEUE_SIZE']

        if 'WORKER_COUNT' in config:
            self.worker_count = config['WORKER_COUNT']

    def spawn_workers(self):
        for i in range(0, self.worker_count):
            w = EventWorker(app_config=self.app.config,
                            event_queue=self.event_queue,
                            pusher_queue=self.pusher_queue,
                            event_cache=self.event_cache
                        )
            w.start()
            self.workers.append(w)


class EventWorker(Process):
    ''' EventWorker performs all the event processing.  EventWorker will monitor the
    event queue for new events and process them into the EventPusher queue for ingest
    in to Reflex
    '''

    def __init__(self, app_config, event_queue, pusher_queue, event_cache):
        super(EventWorker, self).__init__()
        self.app_config = app_config
        self.event_queue = event_queue
        self.pusher_queue = pusher_queue
        self.event_cache = event_cache
        self.sleep_interval = 10
        self.rules = []
        self.cases = []
        self.reasons = []
        self.es = None


    def build_elastic_connection(self):
        elastic_connection = {
            'hosts': self.app_config['ELASTICSEARCH_URL'],
            'verify_certs': self.app_config['ELASTICSEARCH_CERT_VERIFY'],
            'use_ssl': self.app_config['ELASTICSEARCH_SCHEME'],
            'ssl_show_warn': self.app_config['ELASTICSEARCH_SHOW_SSL_WARN']
        }

        username = self.app_config['ELASTICSEARCH_USERNAME'] if 'ELASTICSEARCH_USERNAME' in self.app_config else os.getenv('REFLEX_ES_USERNAME') if os.getenv('REFLEX_ES_USERNAME') else "elastic"
        password = self.app_config['ELASTICSEARCH_PASSWORD'] if 'ELASTICSEARCH_PASSWORD' in self.app_config else os.getenv('REFLEX_ES_PASSWORD') if os.getenv('REFLEX_ES_PASSWORD') else "password"
        if self.app_config['ELASTICSEARCH_AUTH_SCHEMA'] == 'http':
            elastic_connection['http_auth'] = (username,password)

        elif self.app_config['ELASTICSEARCH_AUTH_SCHEMA'] == 'api':
            elastic_connection['api_key'] = (username,password)

        if self.app_config['ELASTICSEARCH_CA']:
            elastic_connection['ca_certs'] = self.app_config['ELASTICSEARCH_CA']

        return connections.create_connection(**elastic_connection)

    def load_rules(self):
        '''
        Fetches all the Event Rules in the system to prevent many requests to
        Elasticsearch
        '''
        search = EventRule.search()
        search = search.filter('term', active=True)
        rules = search.scan()
        rules = list(rules)
        
        for rule in rules:
            rule.parse_rule()

        self.rules = rules

    def load_cases(self):
        '''
        Fetches all the Cases in the system to prevent many requests to
        Elasticsearch
        '''
        search = Case.search()
        search = search.source(includes=['uuid','_id'])
        cases = search.scan()
        self.cases = list(cases)

    def load_close_reasons(self):
        '''
        Fetches all the Closure Reasons in the system to prevent many requests to
        Elasticsearch
        '''
        search = CloseReason.search()
        reasons = search.scan()
        self.reasons = list(reasons)

    def check_cache(self, reference):
        raise NotImplementedError

    def reload_meta_info(self):
        self.load_rules()
        self.load_cases()
        self.load_close_reasons()

    def run(self):
        ''' Processes events from the Event Queue '''

        self.build_elastic_connection()
        
        self.reload_meta_info()
        events_processed = 0
        while True:           

            if self.event_queue.empty():
                time.sleep(1)
            else:
                # pull all event rules
                event = self.event_queue.get()
                self.process_event(event)
                events_processed += 1

                if events_processed == 250:
                    self.reload_meta_info()
                    events_processed = 0

    def process_event(self, raw_event):
        
        organization = raw_event['organization']
        
        if 'signature' not in raw_event or raw_event['signature'] == '':         
            hasher = hashlib.md5()               
            date_string = datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
            hasher.update(f"{raw_event['title']}{date_string}".encode('utf-8'))
            raw_event['signature'] = hasher.hexdigest()
        
        # Add the current users organization to the event signature
        hasher_b = hashlib.md5()
        hasher_b.update(raw_event['signature'].encode('utf-8')+organization.encode('utf-8'))
        raw_event['signature'] = hasher_b.hexdigest()

        # Process Global Event Rules
        for rule in self.rules:
            matched = False
            if rule.global_rule:
                #print('Matched', rule.uuid, raw_event['reference'])
                matched = rule.check_rule(raw_event)
                #matched = rule.process_rql(raw_event)
          
            if rule.organization == organization and not matched:
                matched = rule.check_rule(raw_event)
            else:
                pass
                #print('Skipping rule already matched', rule.uuid, raw_event['reference'])

            if matched:
                pass
                #print('updating event data with rule information', rule.uuid, raw_event['reference'])

        '''
        event = Event.get_by_reference(raw_event['reference'], organization=organization)

        if not event:

            # Generate a default signature based off the rule name and the current time
            # signatures are required in the system but user's don't need to supply them
            # these events will remain ungrouped            

            observables = []

            original_payload = copy.copy(raw_event)

            if 'observables' in raw_event:
                observables = raw_event.pop('observables')

            event = Event(**raw_event, organization=organization)
            #event.save()

            if observables:
                event.add_observable(observables)

            event_rules = EventRule.get_all(organization=organization)
            if event_rules:
            
                matched = False
                for event_rule in event_rules:

                    matches = []

                    # If the event matches the event rule criteria perform the rule actions
                    try:
                        matched = event_rule.process_rql(original_payload)
                    except Exception as e:
                        print(e)
                        #log_event(organization=organization, event_type='Event Rule Processing', source_user="System", event_reference=event.reference, time_taken=0, status="Failed", message=f"Failed to process event rule. {e}")

                    # If the rule matched, process the event
                    if matched:
                        event_rule.process_event(event)
                        matches.append(event.uuid)
                        
                        # TODO: Allow for matching on multiple rules that don't have overlapping
                        # actions, e.g. one rule to move it to a case but a different rule to apply
                        # tags to the event
                        # Break out of the loop, we don't want to match on any more rules
                        if hasattr(event_rule,'global_rule') and not event_rule.global_rule:
                            break

                    if matches:
                        event_rule.last_matched_date = datetime.datetime.utcnow()
                        if event_rule.hit_count != None:
                            event_rule.hit_count += len(matches)
                        else:
                            event_rule.hit_count = len(matches)
                        event_rule.save()
                
                if not event.dismissed_by_rule:
                    event.set_new()

            else:
                event.set_new()
            #log_event(event_type='Bulk Event Insert', source_user="System", request_id=request_id, event_reference=event.reference, time_taken=event_process_time, status="Success", message="Event Inserted.", event_id=event.uuid)
        #else:
        #    log_event(organization=organization, event_type='Bulk Event Insert', source_user="System", request_id=request_id, event_reference=event.reference, time_taken=0, status="Failed", message="Event Already Exists.")
        '''

