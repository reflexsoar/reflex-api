''' 
/app/services/event_processor/event-processor.py
EventProcessor maintains an ingest Queue that stores Events as dictionaries
upon which a set of Event processing workers handle the task of pushing the 
Event into the Reflex system.  Events that are done processing are pushed to the
Pusher queue of the EventPusher service.
'''

import re
import json
import os
import uuid
import time
import hashlib
import datetime
import logging
import threading
from itertools import chain
from multiprocessing import Queue
#from queue import Queue
from multiprocessing import Process, get_context, Event as mpEvent
from app.api_v2.model import (
    EventRule,
    CloseReason,
    Case,
    DataType,
    EventStatus,
    Task,
    ThreatList
)

# Elastic or Opensearch
if os.getenv('REFLEX_ES_DISTRO') == 'opensearch':
    from opensearch_dsl import connections
    from opensearchpy.helpers import streaming_bulk
else:
    from elasticsearch_dsl import connections
    from elasticsearch.helpers import streaming_bulk          


class EventProcessor: 
    ''' EventProcessor maintains an ingest Queue that stores Events as dictionaries
    upon which a set of Event processing workers handle the task of pushing the 
    Event into the Reflex system.  Events that are done processing are pushed to the
    Pusher queue of the EventPusher service.

    >>> event_processor = EventProcessor(app, queue=QueueObject)

    If building Flask apps on the fly

    >>> event_processor = EventProcessor()
    >>> event_processor.init_app(app, queue=QueueObject)
    '''

    # pylint: disable=too-many-instance-attributes

    def __init__(self, app=None, log_level="DEBUG", **defaults):
        ''' Initialize the EventProcessor '''

        if app:
            self.init_app(app, **defaults)

        log_levels = {
            'DEBUG': logging.DEBUG,
            'ERROR': logging.ERROR,
            'INFO': logging.INFO
        }

        log_handler = logging.StreamHandler()
        log_handler.setFormatter(logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'))

        self.logger = logging.getLogger(self.__class__.__name__)
        self.logger.addHandler(log_handler)
        self.logger.setLevel(log_levels[log_level])
        self.log_level = log_level

        self.worker_count = 10
        self.event_queue = Queue()
        self.workers = []
        self.event_cache = []


    def set_log_level(self, log_level):
        '''Allows for changing the log level after initialization'''

        log_levels = {
            'DEBUG': logging.DEBUG,
            'ERROR': logging.ERROR,
            'INFO': logging.INFO
        }

        self.logger.setLevel(log_levels[log_level])
        self.log_level = log_level


    def init_app(self, app, **defaults):
        ''' Initialize the EventProcessor from within an application factory '''
        self.app = app
        config = self.app.config.get('EVENT_PROCESSOR', {})
        self.config = config

        self.logger.info('EventProcessor Started')

        # Process default settings
        for key, value in defaults.items():
            if hasattr(self, key):
                setattr(self, key, value)

        # Override via configuration items
        if 'MAX_QUEUE_SIZE' in config:
            self.max_queue_size = config['MAX_QUEUE_SIZE']

        if 'WORKER_COUNT' in config:
            self.worker_count = config['WORKER_COUNT']

        self.worker_monitor = threading.Thread(target=self.monitor_workers, args=(), daemon=True)
        self.worker_monitor.start()


    def enqueue(self, item):
        '''
        Adds an item to the queue for Event Workers to work on
        '''
        self.event_queue.put(item)
    
    def qsize(self):
        '''
        Returns the current queue size
        '''
        return self.event_queue.qsize()

    def spawn_workers(self):
        '''
        Creates a set of workers to process incoming Events
        '''
        self.logger.info('Spawning Event Processing workers')
        for i in range(0, self.worker_count):
            w = EventWorker(app_config=self.app.config,
                            event_queue=self.event_queue,
                            event_cache=self.event_cache,
                            log_level=self.log_level
                            )
            w.start()
            self.workers.append(w)

    def monitor_workers(self):
        '''
        Monitors the workers to see if they are alive
        If they are dead start a new worker in their place
        '''
        
        while True:            
            self.logger.info('Checking Event Worker health')
            for worker in list(self.workers):
                if worker.is_alive() == False:
                    self.logger.error(f"Event Worker {worker._sentinel} died, starting new worker")
                    self.workers.remove(worker)
                    w = EventWorker(app_config=self.app.config,
                            event_queue=self.event_queue,
                            event_cache=self.event_cache,
                            log_level=self.log_level
                            )
                    w.start()
                    self.workers.append(w)

            time.sleep(self.config['WORKER_CHECK_INTERVAL'])

    def restart_workers(self):
        '''
        Forces all the Event workers to finish processing their current event
        and restart
        '''
        self.logger.info('Restarting Event Processing workers')
        for worker in self.workers:
            worker.force_reload()

        return True


class EventWorker(Process):
    ''' EventWorker performs all the event processing.  EventWorker will monitor the
    event queue for new events and process them into the EventPusher queue for ingest
    in to Reflex
    '''

    # pylint: disable=too-many-instance-attributes

    def __init__(self, app_config, event_queue, event_cache, log_level='ERROR'):
        
        super(EventWorker, self).__init__()

        log_levels = {
            'DEBUG': logging.DEBUG,
            'ERROR': logging.ERROR,
            'INFO': logging.INFO
        }

        log_handler = logging.StreamHandler()
        log_handler.setFormatter(logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'))

        self.logger = logging.getLogger(self.__class__.__name__)
        self.logger.addHandler(log_handler)
        self.logger.setLevel(log_levels[log_level])

        self.app_config = app_config
        self.config = self.app_config.get('EVENT_PROCESSOR', {})
        self.event_queue = event_queue
        self.event_cache = event_cache
        self.sleep_interval = 10
        self.rules = []
        self.cases = []
        self.reasons = []
        self.statuses = []
        self.data_types = []
        self.events = []
        self.last_meta_refresh = None
        self.should_restart = mpEvent()

    def force_reload(self):
        self.logger.debug('Reload triggered by EventProcessor')
        self.should_restart.set()

    def build_elastic_connection(self):
        '''
        Generates an elasticsearch connection client to be used for
        pulling and sending data to elasticsearch
        '''
        elastic_connection = {
            'hosts': self.app_config['ELASTICSEARCH_URL'],
            'verify_certs': self.app_config['ELASTICSEARCH_CERT_VERIFY'],
            'use_ssl': self.app_config['ELASTICSEARCH_SCHEME'],
            'ssl_show_warn': self.app_config['ELASTICSEARCH_SHOW_SSL_WARN'],
            'timeout': self.app_config['ELASTICSEARCH_TIMEOUT']
        }

        username = self.app_config['ELASTICSEARCH_USERNAME'] if 'ELASTICSEARCH_USERNAME' in self.app_config else os.getenv(
            'REFLEX_ES_USERNAME') if os.getenv('REFLEX_ES_USERNAME') else "elastic"
        password = self.app_config['ELASTICSEARCH_PASSWORD'] if 'ELASTICSEARCH_PASSWORD' in self.app_config else os.getenv(
            'REFLEX_ES_PASSWORD') if os.getenv('REFLEX_ES_PASSWORD') else "password"
        if self.app_config['ELASTICSEARCH_AUTH_SCHEMA'] == 'http':
            elastic_connection['http_auth'] = (username, password)

        elif self.app_config['ELASTICSEARCH_AUTH_SCHEMA'] == 'api':
            elastic_connection['api_key'] = (username, password)

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

    
    def load_rules(self, rule_id=None):
        '''
        Fetches all the Event Rules in the system to prevent many requests to
        Elasticsearch
        '''
        
        search = EventRule.search()
        search = search.filter('term', active=True)
        if rule_id:
            search = search.filter('term', uuid=rule_id)
        rules = search.scan()
        rules = list(rules)

        # Only load rules that parse correctly
        loaded_rules = []

        for rule in rules:
            try:
                rule.parse_rule()
                loaded_rules.append(rule)
            except Exception as e:
                rule.update(active=False, disable_reason=f"Invalid RQL query. {e}")
                self.logger.error(f"Failed to parse Event Rule {rule.name}, rule has been disabled.  Invalid RQL query. {e}.")

        if not rule_id:
            self.rules = loaded_rules
        else:
            [self.rules.append(r) for r in loaded_rules]


    def load_cases(self):
        '''
        Fetches all the Cases in the system to prevent many requests to
        Elasticsearch
        '''
        search = Case.search()
        search = search.source(includes=['uuid', '_id'])
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


    def load_data_types(self):
        '''
        Fetches all the data types in the system
        '''
        search = DataType.search()
        data_types = search.scan()
        self.data_types = list(data_types)


    def check_cache(self, reference):
        '''
        Determines if the event is already in the Event Processor cache,
        if it is, return True so that it knows not to send the event again
        if it isn't add it to the cache and return False
        '''
        raise NotImplementedError


    def reload_meta_info(self, clear_reload_flag=False):
        '''
        Reloads information from Elasticsearch so that it can be used
        during Event processing.  This lowers the number of calls
        that need to be sent to Elasticsearch
        '''
        #time.sleep(5)
        self.logger.debug('Reloading configuration information')
        self.load_rules()
        self.load_cases()
        self.load_close_reasons()
        self.load_statuses()
        self.load_data_types()
        self.load_intel_lists()
        self.last_meta_refresh = datetime.datetime.utcnow()
        
        if clear_reload_flag:
            self.should_restart.clear()


    def get_meta_info(self):
        '''
        Returns the currently loaded meta information'''
        return {
            'rules': self.rules
        }

    def pop_events_by_action(self, events, action):
        return [e for e in events if '_meta' in e and e['_meta']['action'] == action]


    def run(self):
        ''' Processes events from the Event Queue '''

        connection = self.build_elastic_connection()
        self.reload_meta_info()
        self.logger.debug(f"Running")

        while True:

            if self.event_queue.empty():

                if self.should_restart.is_set():
                    #exit()
                    self.reload_meta_info(clear_reload_flag=True)

                time.sleep(1)

            else:

                # Reload all the event rules and other meta information if the refresh timer
                # has expired
                if (datetime.datetime.utcnow() - self.last_meta_refresh).total_seconds() > self.config['META_DATA_REFRESH_INTERVAL']:
                    self.reload_meta_info()

                # Interrupt this flow if the worker is scheduled for restart
                if self.should_restart.is_set():
                    self.reload_meta_info(clear_reload_flag=True)

                event = self.event_queue.get()

                # Process the event
                event = self.process_event(event)

                # If returned value is not None add the event to the list of events to be pushed
                # via _bulk
                if event:
                    self.events.append(event)

                if len(self.events) >= self.config["ES_BULK_SIZE"] or self.event_queue.empty():

                    # Perform bulk dismiss operations on events resubmitted to the Event Processor with _meta.action == "dismiss"
                    bulk_dismiss = [e for e in self.events if '_meta' in e and e['_meta']['action'] == 'dismiss']
                    add_to_case = [e for e in self.events if '_meta' in e and e['_meta']['action'] == 'add_to_case']
                    retro_apply_event_rule = [e for e in self.events if '_meta' in e and e['_meta']['action'] == 'retro_apply_event_rule']
                    
                    task_end = self.pop_events_by_action(self.events, 'task_end')

                    for ok, action in streaming_bulk(client=connection, chunk_size=self.config['ES_BULK_SIZE'], actions=self.prepare_add_to_case(add_to_case)):
                        pass

                    for ok, action in streaming_bulk(client=connection, chunk_size=self.config['ES_BULK_SIZE'], actions=self.prepare_dismiss_events(bulk_dismiss)):
                        pass

                    for ok, action in streaming_bulk(client=connection, actions=self.prepare_retro_events(retro_apply_event_rule)):
                        pass

                    self.events = [e for e in self.events if e not in chain(bulk_dismiss, add_to_case, task_end, retro_apply_event_rule)]

                    self.prepare_case_updates(self.events)

                    # Send Events
                    for ok, action in streaming_bulk(client=connection, chunk_size=self.config['ES_BULK_SIZE'], actions=self.prepare_events(self.events)):
                        pass

                    # Update Cases
                    for ok, action in streaming_bulk(client=connection, chunk_size=self.config['ES_BULK_SIZE'], actions=self.prepare_case_updates(self.events)):
                        pass

                    if task_end:
                        for item in task_end:
                            
                            task = Task.get_by_uuid(uuid=item['_meta']['task_id'])

                            # If the task_type is one that should be broadcast
                            # set the broadcast flag
                            if task.task_type in ['bulk_dismiss_events']:
                                task.broadcast = True

                            task.finish()

                    self.events = []


    def check_threat_list(self, observable, organization, MEMCACHED_CONFIG=None):
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
                matched = l.check_value(
                    observable['value'], observable['data_type'], MEMCACHED_CONFIG=MEMCACHED_CONFIG)

            else:
                if observable['data_type'] == l.data_type.name:
                    matched = l.check_value(
                        observable['value'], MEMCACHED_CONFIG=MEMCACHED_CONFIG)

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

            # If the original_date field is not provided
            if 'original_date' not in event:

                event['original_date'] = datetime.datetime.utcnow()

            if 'observables' in event:
                event['event_observables'] = event.pop('observables')
            else:
                event['event_observables'] = []

            yield {
                '_source': event,
                '_index': 'reflex-events'
                #'_type': '_doc'
            }


    def prepare_retro_events(self, events):
        '''
        Prepares the dictionary for bulk push to Elasticsearch
        '''
        for event in events:
            if '_meta' in event:
                event_meta_data = event.pop('_meta')

                yield {
                    'doc': event,
                    '_index': 'reflex-events',
                    '_op_type': 'update',
                    '_id': event_meta_data['_id']
                }

    def prepare_add_to_case(self, events):
        '''
        Prepares events that are being added to a case for bulk push to Elasticsearch
        '''
        now = datetime.datetime.utcnow()
        for event in events:

            if '_meta' in event:
                event_meta_data = event.pop('_meta')
                payload = {}

                status = next((s for s in self.statuses if s.organization ==
                              event['organization'] and s.name == 'Open'), None)
                payload['status'] = status.to_dict()
                payload['case'] = event_meta_data['case']
                payload['updated_at'] = now

            yield {
                'doc': payload,
                '_index': 'reflex-events',
                #'_type': '_doc',
                '_op_type': 'update',
                '_id': event_meta_data['_id']
            }


    def prepare_dismiss_events(self, events):
        '''
        Prepares events that are being dismissed for a bulk push to Elasticsearch
        '''
        now = datetime.datetime.utcnow()
        for event in events:

            if '_meta' in event:
                event_meta_data = event.pop('_meta')

                payload = {}

                # Find the reason and set it
                reason = next((r for r in self.reasons if r.uuid ==
                              event_meta_data['dismiss_reason']), None)
                if reason:
                    payload['dismiss_reason'] = reason.title
                    payload['dismiss_comment'] = event_meta_data['dismiss_comment']
                    payload['dismissed_at'] = now
                    payload['time_to_dismiss'] = (
                        now - event['created_at']).total_seconds()

                status = next((s for s in self.statuses if s.organization ==
                              event['organization'] and s.name == 'Dismissed'), None)
                payload['status'] = status.to_dict()

                payload['updated_at'] = now
                payload['updated_by'] = event_meta_data['updated_by']

            yield {
                'doc': payload,
                '_index': 'reflex-events',
                #'_type': '_doc',
                '_op_type': 'update',
                '_id': event_meta_data['_id']
            }

    def prepare_case_updates(self, events):
        '''
        If any cases had their cases updated update the case as well
        '''
        updated_cases = {}
        for event in events:
            event_uuid = str(event['uuid'])
            if 'case' in event:
                case = next((c for c in self.cases if c.uuid == event['case']), None)
                if case:
                    _id = case.meta.id

                    if _id not in updated_cases:
                        updated_cases[_id] = []
                        if hasattr(case, 'events') and case.events:
                            updated_cases[_id] = case.events
                        else:
                            updated_cases[_id].append(event_uuid)
                    else:
                        updated_cases[_id].append(event_uuid)

        for case, case_events in updated_cases.items():
            yield {
                "_id": case,
                #"_type": "_doc",
                "_index": "reflex-cases",
                "_op_type": "update",
                "upsert": {},
                "scripted_upsert": True,
                "script": {
                    "source": "if(ctx._source.events == null) { ctx._source.events = []; } ctx._source.events.add(params.events)",
                    "params": {
                        "events": case_events
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
                raw_event['tags'] += rule.tags_to_add
            else:
                if len(rule.tags_to_add) > 1:
                    raw_event['tags'] = list(rule.tags_to_add)
                else:
                    raw_event['tags'] = [rule.tags_to_add]

            # Deduplicate tags
            tags = []
            for t in raw_event['tags']:
                if isinstance(t, str) and t not in tags:
                    tags.append(t)
            raw_event['tags'] = tags

        # If the rule says to merge in to case
        if rule.merge_into_case:
            raw_event['case'] = rule.target_case_uuid

            status = next((s for s in self.statuses if s.organization ==
                          raw_event['organization'] and s.name == 'Open'), None)
            raw_event['status'] = status.to_dict()

        # If the rule says to dismiss
        if rule.dismiss:
            reason = next(
                (r for r in self.reasons if r.uuid == rule.dismiss_reason), None)
            if rule.dismiss_comment:
                raw_event['dismiss_comment'] = rule.dismiss_comment

            raw_event['dismissed_at'] = datetime.datetime.utcnow()
            raw_event['dismiss_reason'] = reason.title
            raw_event['dismissed_by_rule'] = True
            raw_event['time_to_dismiss'] = 0

            status = next((s for s in self.statuses if s.organization ==
                          raw_event['organization'] and s.name == 'Dismissed'), None)
            raw_event['status'] = status.to_dict()


        if rule.update_severity:
            raw_event['severity'] = rule.target_severity

        return raw_event

    def push_event(self, raw_event):
        '''
        Prepares an event and sends it to the pusher queue
        '''
        raise NotImplementedError

    def process_event(self, raw_event):
        '''
        Processes events and performs RQL checking against them if they are not
        reprocessed events.  Reprocessed events have a _meta attribute with
        reprocessing information
        '''

        organization = raw_event['organization']

        if not '_meta' in raw_event:

            if 'signature' not in raw_event or raw_event['signature'] == '':
                hasher = hashlib.md5()
                date_string = datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
                hasher.update(
                    f"{raw_event['title']}{date_string}".encode('utf-8'))
                raw_event['signature'] = hasher.hexdigest()

            if 'uuid' not in raw_event:
                raw_event['uuid'] = uuid.uuid4()

            if 'observables' in raw_event:
                raw_event['observables'] = [o for o in raw_event['observables'] if o['value'] not in [None,'','-']]

            for observable in raw_event['observables']:
                if observable['data_type'] == "auto":
                    matched = False
                    for dt in [data_type for data_type in self.data_types if data_type.organization == raw_event['organization']]:
                        if dt.regex:
                            if dt.regex.startswith('/') and dt.regex.endswith('/'):
                                expression = dt.regex.lstrip('/').rstrip('/')
                            else:
                                expression = dt.regex
                            try:
                                pattern = re.compile(expression)
                                matches = pattern.findall(observable['value'])
                            except Exception as error:
                                observable['data_type'] = "generic"
                                print(dt.regex, error)
                            if len(matches) > 0:
                                observable['data_type'] = dt.name
                                matched = True

            if 'observables' in raw_event:
                if self.app_config['THREAT_POLLER_MEMCACHED_ENABLED']:
                    MEMCACHED_CONFIG = (
                        self.app_config['THREAT_POLLER_MEMCACHED_HOST'],
                        self.app_config['THREAT_POLLER_MEMCACHED_PORT']
                    )

                obs = [self.check_threat_list(observable,
                                              organization,
                                              MEMCACHED_CONFIG=MEMCACHED_CONFIG
                                            ) for observable in raw_event['observables']]
                raw_event['observables'] = obs

            if 'tags' in raw_event:
                raw_event['tags'] = [t for t in raw_event['tags'] if not t.endswith(': None')]
                
            # Add the current users organization to the event signature
            hasher_b = hashlib.md5()
            hasher_b.update(raw_event['signature'].encode(
                'utf-8')+organization.encode('utf-8'))
            raw_event['signature'] = hasher_b.hexdigest()
            raw_event['status'] = next(
                (s for s in self.statuses if s.organization == raw_event['organization'] and s.name == 'New'), None)

            # Process Global Event Rules
            for rule in self.rules:
                
                try:
                    matched = False
                    if rule.global_rule:
                        matched = rule.check_rule(raw_event)

                    if rule.organization == organization and not matched:
                        matched = rule.check_rule(raw_event)
                    else:
                        pass

                    if matched:
                        raw_event = self.mutate_event(rule, raw_event)
                except Exception as e:
                    self.logger.error(f"Failed to process rule {rule.uuid} ({rule.name}). Reason: {e}")

        else:
            if 'action' in raw_event['_meta'] and raw_event['_meta']['action'] == 'retro_apply_event_rule':
                event_meta_data = raw_event['_meta']

                rule = next((r for r in self.rules if r.uuid == event_meta_data['rule_id']), None)
                
                # If the rule is not in the Workers rule list try to fetch it
                if not rule:
                    
                    attempts = 0
                    while attempts != 10:
                        if not rule:
                            self.load_rules(rule_id=event_meta_data['rule_id'])
                            rule = next((r for r in self.rules if r.uuid == event_meta_data['rule_id']), None)
                            if not rule:
                                attempts += 1
                                self.logger.error(f"No rule found for {event_meta_data['rule_id']}. Attempt {attempts}/10.")
                            else:
                                break
                    
                matched = False
                
                if rule:
                    try:                        
                        if hasattr(rule, 'global_rule') and rule.global_rule:
                            matched = rule.check_rule(raw_event)

                        if rule.organization == organization and not matched:
                            matched = rule.check_rule(raw_event)
                        else:
                            pass

                        if matched:
                            raw_event = self.mutate_event(rule, raw_event)
                    except Exception as e:
                        self.logger.error(f"Failed to process rule {rule.uuid}. Reason: {e}")
                else:
                    self.logger.error(f"No rule found for {event_meta_data['rule_id']}")
                    self.logger.debug(event_meta_data)

                if 'observables' in raw_event:
                    raw_event['event_observables'] = raw_event.pop('observables')

                if not matched:
                    return None

        return raw_event
