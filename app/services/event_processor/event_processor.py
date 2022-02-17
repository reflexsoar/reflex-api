''' 
/app/services/event_processor/event-processor.py
EventProcessor maintains an ingest Queue that stores Events as dictionaries
upon which a set of Event processing workers handle the task of pushing the 
Event into the Reflex system.  Events that are done processing are pushed to the
Pusher queue of the EventPusher service.
'''

import re
import os
import json
import uuid
import copy
import time
import hashlib
import datetime
import logging
from multiprocessing import Process
import multiprocessing
from app.api_v2.model import (
    Event,
    EventRule,
    CloseReason,
    Case
)
from app.api_v2.model.event import EventStatus
from app.api_v2.model.threat import ThreatList
from app.api_v2.rql import (
    QueryParser,
    RQLSearch
)
from ..utils import execution_timer

# Elastic or Opensearch
if os.getenv('REFLEX_ES_DISTRO') == 'opensearch':
    from opensearch_dsl import connections
    from opensearchpy.helpers import streaming_bulk
else:
    from elasticsearch_dsl import connections
    from elasticsearch.helpers import streaming_bulk

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
        self.logger.info('Spawning Event Processing workers')
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
        self.config = self.app_config.get('EVENT_PROCESSOR', {})
        self.event_queue = event_queue
        self.pusher_queue = pusher_queue
        self.event_cache = event_cache
        self.sleep_interval = 10
        self.rules = []
        self.cases = []
        self.reasons = []
        self.statuses = []
        self.lists = []
        self.es = None

    
    def build_elastic_connection(self):
        elastic_connection = {
            'hosts': self.app_config['ELASTICSEARCH_URL'],
            'verify_certs': self.app_config['ELASTICSEARCH_CERT_VERIFY'],
            'use_ssl': self.app_config['ELASTICSEARCH_SCHEME'],
            'ssl_show_warn': self.app_config['ELASTICSEARCH_SHOW_SSL_WARN']
        }

        username = self.app_config['ELASTICSEARCH_USERNAME']
        password = self.app_config['ELASTICSEARCH_PASSWORD']
        if self.app_config['ELASTICSEARCH_AUTH_SCHEMA'] == 'http':
            elastic_connection['http_auth'] = (username,password)

        elif self.app_config['ELASTICSEARCH_AUTH_SCHEMA'] == 'api':
            elastic_connection['api_key'] = (username,password)

        if self.app_config['ELASTICSEARCH_CA']:
            elastic_connection['ca_certs'] = self.app_config['ELASTICSEARCH_CA']

        return connections.create_connection(**elastic_connection)

   
    def load_intel_lists(self):
        '''
        Fetches all the Intel Lists in the system to prevent too many requests
        to Elasticsearch
        '''
        search = ThreatList.search()
        search = search.filter('term', active=True)
        lists = search.scan()
        self.lists = list(lists)

    
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

    def load_statuses(self):
        '''
        Fetches all the Event Statuses in the system to prevent many requests to
        Elasticsearch
        '''
        search = EventStatus.search()
        statuses = search.scan()
        self.statuses = list(statuses)

    
    def check_cache(self, reference):
        raise NotImplementedError

    
    def reload_meta_info(self):
        self.load_rules()
        self.load_cases()
        self.load_close_reasons()
        self.load_statuses()
        self.load_intel_lists()
        self.last_meta_refresh = datetime.datetime.utcnow()

    
    def run(self):
        ''' Processes events from the Event Queue '''

        connection = self.build_elastic_connection()        
        self.reload_meta_info()
        events = []
        successful_inserts = 0
        failed_inserts = 0

        while True:           

            if self.event_queue.empty():
                time.sleep(1)
            else:

                # Reload all the event rules and other meta information if the refresh timer
                # has expired
                if ((datetime.datetime.utcnow() - self.last_meta_refresh).total_seconds() > self.config['META_DATA_REFRESH_INTERVAL']):
                    self.reload_meta_info()

                # pull all event rules
                event = self.event_queue.get()
                events.append(self.process_event(event))

                if len(events) >= self.config["ES_BULK_SIZE"] or self.event_queue.empty():
                    self.prepare_case_updates(events)
                    # Send Events
                    for ok, action in streaming_bulk(client=connection, chunk_size=self.config['ES_BULK_SIZE'], actions=self.prepare_events(events)):
                        pass

                    # Update Cases
                    for ok, action in streaming_bulk(client=connection, chunk_size=self.config['ES_BULK_SIZE'], actions=self.prepare_case_updates(events)):
                        pass
                    events = []


    def check_threat_list(self, observable, organization):
        '''
        Checks an observable against a threat list and tags the observable
        accordingly if it matches
        '''
        lists = [l for l in self.lists if l.organization == organization]
        for l in lists:

            # Assume it doesn't match by default
            matched = False

            # If dealing with a CSV list
            if l.list_type == 'csv':
                if l.check_value(observable['value'], observable['data_type']) > 0:
                    matched = True

            else:
                if l.check_value(observable['value']) > 0:
                    matched = True

            # If there were matches and the list calls for tagging the observable
            if matched and l.tag_on_match:
                if 'tags' in observable:
                    observable['tags'].append(f"list: {l.name}")
                else:
                    observable['tags'] = [f"list: {l.name}"]

        return observable


    def prepare_events(self, events):
        '''
        Prepares the dictionary for bulk push to Elasticsearch
        '''
        for event in events:
            event['created_at'] = datetime.datetime.utcnow()
            if 'observables' in event:
                event['event_observables'] = event.pop('observables')
            else:
                event['event_observables'] = []
            yield {'_source': event, '_index': 'reflex-events', '_type': '_doc'}


    def prepare_case_updates(self, events):
        '''
        If any cases had their cases updated update the case as well
        '''
        updated_cases = {}
        for event in events:
            uuid = str(event['uuid'])
            if 'case' in event:
                case = next((c for c in self.cases if c.uuid == event['case']))
                if case:
                    _id = case.meta.id

                    if _id not in updated_cases:
                        updated_cases[_id] = []
                        if hasattr(case, 'events') and case.events:
                            updated_cases[_id] = case.events
                        else:
                            updated_cases[_id].append(uuid)
                    else:
                        updated_cases[_id].append(uuid)
        
        for case in updated_cases:
            yield {
                "_id": case,
                "_type": "_doc",
                "_index": "reflex-cases",
                "_op_type": "update",
                "upsert": {},
                "scripted_upsert": True,
                "script": {
                    "source": "if(ctx._source.events == null) { ctx._source.events = []; } ctx._source.events.add(params.events)",
                    "params": {
                        "events": updated_cases[case]
                    }
                }
            }
                

    def mutate_event(self, rule, raw_event):
        '''
        Mutates the initial event document to contain all the required
        information
        '''

        # Append or initialize the event_rules field and watermark the event
        # with this rules UUID
        if 'event_rules' in raw_event:
            raw_event['event_rules'].append(rule.uuid)
        else:
            raw_event['event_rules'] = [rule.uuid]

        # If the rule says to add tags
        if rule.add_tags:
            if 'tags' in raw_event:
                raw_event['tags'] += list(rule.tags_to_add)
            else:
                if len(rule.tags_to_add) > 1:
                    raw_event['tags'] = list(rule.tags_to_add)
                else:
                    raw_event['tags'] = [rule.tags_to_add]
            
            # Deduplicate tags
            raw_event['tags'] = list(set(raw_event['tags']))

        # If the rule says to dismiss
        if rule.dismiss:
            reason = next((r for r in self.reasons if r.uuid == rule.dismiss_reason))
            if rule.dismiss_comment:
                raw_event['dismiss_comment'] = rule.dismiss_comment

            raw_event['dismissed_at'] = datetime.datetime.utcnow()            
            raw_event['dismiss_reason'] = reason.title
            raw_event['dismissed_by_rule'] = True
            raw_event['time_to_dismiss'] = 0

            status = next((s for s in self.statuses if s.organization == raw_event['organization'] and s.name == 'Dismissed'))
            raw_event['status'] = status.to_dict()
            
        # If the rule says to merge in to case
        if rule.merge_into_case:
            raw_event['case'] = rule.target_case_uuid

        if rule.update_severity:
            raw_event['severity'] = rule.target_severity

        return raw_event


    def push_event(self, raw_event):
        ''' 
        Prepares an event and sends it to the pusher queue
        '''
        raise NotImplementedError
    
    def process_event(self, raw_event):
        
        organization = raw_event['organization']
        
        if 'signature' not in raw_event or raw_event['signature'] == '':         
            hasher = hashlib.md5()               
            date_string = datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
            hasher.update(f"{raw_event['title']}{date_string}".encode('utf-8'))
            raw_event['signature'] = hasher.hexdigest()

        if 'uuid' not in raw_event:
            raw_event['uuid'] = uuid.uuid4()

        if 'observables' in raw_event:
            raw_event['observables'] = [self.check_threat_list(observable, organization) for observable in raw_event['observables']]
        
        # Add the current users organization to the event signature
        hasher_b = hashlib.md5()
        hasher_b.update(raw_event['signature'].encode('utf-8')+organization.encode('utf-8'))
        raw_event['signature'] = hasher_b.hexdigest()
        raw_event['status'] = next((s for s in self.statuses if s.organization == raw_event['organization'] and s.name == 'New'))

        # Process Global Event Rules
        for rule in self.rules:
            matched = False
            if rule.global_rule:
                matched = rule.check_rule(raw_event)
          
            if rule.organization == organization and not matched:
                matched = rule.check_rule(raw_event)
            else:
                pass

            if matched:
                raw_event = self.mutate_event(rule, raw_event)
                pass

        return raw_event