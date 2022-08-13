import base64
import copy
import math
import time
import hashlib
import json
import datetime
import threading
from queue import Queue

from app.api_v2.model.system import ObservableHistory, Settings
from app.api_v2.model.user import Organization
from flask import current_app
from flask_restx import Resource, Namespace, fields, inputs as xinputs
from ..model import Event, Observable, EventRule, CloseReason, Q, Task, UpdateByQuery, EventStatus
from ..model.exceptions import EventRuleFailure
from ..utils import token_required, user_has, log_event
from .shared import ISO8601, JSONField, ObservableCount, IOCCount, mod_pagination, mod_observable_list, mod_observable_list_paged, mod_user_list
from ... import ep, memcached_client

api = Namespace('Events', description='Event related operations', path='/event')

mod_bulk_event_uuids = api.model('BulkEventUUIDs', {
    'events': fields.List(fields.String),
    'organizations': JSONField(attribute='organizations')
})

mod_raw_log = api.model('RawLog', {
    'source_log': fields.String
})

mod_event_status = api.model('EventStatusString', {
    'name': fields.String,
    'closed': fields.Boolean
})

mod_observable_create = api.model('ObservableCreate', {
    'value': fields.String(required=True),
    'ioc': fields.Boolean,
    'tlp': fields.Integer,
    'spotted': fields.Boolean,
    'safe': fields.Boolean,
    'data_type': fields.String(required=True),
    'tags': fields.List(fields.String),
    'source_field': fields.String,
    'original_source_field': fields.String
})

mod_event_create = api.model('EventCreate', {
    'title': fields.String(required=True),
    'reference': fields.String(required=True),
    'description': fields.String(required=True),
    'tags': fields.List(fields.String),
    'tlp': fields.Integer,
    'severity': fields.Integer,
    'source': fields.String,
    'signature': fields.String,
    'observables': fields.List(fields.Nested(mod_observable_create)),
    'raw_log': fields.String,
    'detection_id': fields.String
})

mod_event_list = api.model('EventList', {
    'uuid': fields.String,
    'organization': fields.String,
    'title': fields.String(required=True),
    'reference': fields.String(required=True),
    'description': fields.String(required=True),
    'tlp': fields.Integer,
    'severity': fields.Integer,
    'status': fields.Nested(mod_event_status),
    'source': fields.String,
    'tags': fields.List(fields.String),
    'created_at': ISO8601(attribute='created_at'),
    'updated_at': ISO8601(attribute='updated_at'),
    'observables': fields.List(fields.Nested(mod_observable_list)),
    'case': fields.String,
    'signature': fields.String,
    'related_events_count': fields.Integer,
    'raw_log': fields.Nested(mod_raw_log, attribute='_raw_log'),
    'event_rules': fields.List(fields.String),
    'original_date': ISO8601(attribute='original_date'),
    'detection_id': fields.String
})

mod_event_paged_list = api.model('PagedEventList', {
   'events': fields.List(fields.Nested(mod_event_list)),
   'pagination': fields.Nested(mod_pagination)
})

mod_related_events = api.model('RelatedEvents', {
    'events': fields.List(fields.String),
    'count': fields.Integer
})

mod_event_create_bulk = api.model('EventCreateBulk', {
    'events': fields.List(fields.Nested(mod_event_create))
})

mod_event_bulk_dismiss = api.model('EventBulkDismiss', {
    'events': fields.List(fields.String),
    'dismiss_reason_uuid': fields.String,
    'dismiss_comment': fields.String,
})

mod_event_bulk_dismiss_by_filter = api.model('EventBulkDismissByFilter', {
    'filter': fields.String,
    'dismiss_reason_uuid': fields.String,
    'dismiss_comment': fields.String,
    'uuids': fields.List(fields.String)
})

mod_event_details = api.model('EventDetails', {
    'uuid': fields.String,
    'title': fields.String(required=True),
    'reference': fields.String(required=True),
    'description': fields.String(required=True),
    'tlp': fields.Integer,
    'severity': fields.Integer,
    'status': fields.Nested(mod_event_status),
    'source': fields.String,
    'tags': fields.List(fields.String),
    'observables': fields.List(fields.Nested(mod_observable_list)),
    'observable_count': ObservableCount(attribute='observables'),
    'ioc_count': IOCCount(attribute='observables'),
    'case': fields.String,
    'created_at': ISO8601(attribute='created_at'),
    'modified_at': ISO8601(attribute='updated_at'),
    'raw_log': fields.String,
    'signature': fields.String,
    'dismiss_reason': fields.String,
    'dismiss_comment': fields.String,
    'event_rules': fields.List(fields.String),
    'original_date': ISO8601(attribute='original_date'),
    'detection_id': fields.String,
    'dismissed_by': fields.Nested(mod_user_list)
})

mod_observable_update = api.model('ObservableUpdate', {
    'tags': fields.List(fields.String),
    'ioc': fields.Boolean,
    'tlp': fields.Integer,
    'spotted': fields.Boolean,
    'safe': fields.Boolean,
    'data_type': fields.String
})

event_list_parser = api.parser()
event_list_parser.add_argument('status', location='args', default=[
], type=str, action='split', required=False)
event_list_parser.add_argument('tags', location='args', default=[
], type=str, action='split', required=False)
event_list_parser.add_argument('observables', location='args', default=[
], type=str, action='split', required=False)
event_list_parser.add_argument('signature', location='args', required=False)
event_list_parser.add_argument('source', action='split', location='args', required=False)
event_list_parser.add_argument('event_rule', location='args', default=[
], type=str, action='split', required=False)
event_list_parser.add_argument(
    'severity', action='split', location='args', required=False)
event_list_parser.add_argument(
    'grouped', type=xinputs.boolean, location='args', required=False)
event_list_parser.add_argument(
    'case_uuid', type=str, location='args', required=False)
event_list_parser.add_argument('search', type=str, action='split', default=[
], location='args', required=False)
event_list_parser.add_argument(
    'title__like', type=str, location='args', required=False
)
event_list_parser.add_argument(
    'title', type=str, location='args', action='split', required=False)
event_list_parser.add_argument(
    'page', type=int, location='args', default=1, required=False)
event_list_parser.add_argument(
    'page_size', type=int, location='args', default=10, required=False)
event_list_parser.add_argument(
    'sort_by', type=str, location='args', default='created_at', required=False)
event_list_parser.add_argument(
    'sort_direction', type=str, location='args', default="desc", required=False)
event_list_parser.add_argument('start', location='args', type=str, required=False)
event_list_parser.add_argument('end', location='args',  type=str, required=False)
event_list_parser.add_argument('organization', location='args', action='split', required=False)


@api.route("")
class EventListAggregated(Resource):

    @api.doc(security="Bearer")
    @api.marshal_with(mod_event_paged_list)
    @api.expect(event_list_parser)
    @token_required
    @user_has('view_events')
    def get(self, current_user):

        args = event_list_parser.parse_args()

        # Set default start/end date filters if they are not set above
        # We do this here because default= on add_argument() is only calculated when the API is initialized
        if not args.start:
            args.start = (datetime.datetime.utcnow()-datetime.timedelta(days=7)).strftime('%Y-%m-%dT%H:%M:%S')
        if not args.end:
            args.end = (datetime.datetime.utcnow()+datetime.timedelta(days=1)).strftime('%Y-%m-%dT%H:%M:%S')

        start = (args.page - 1)*args.page_size
        end = (args.page * args.page_size)

        search_filters = []

        if args.title__like and args.title__like != '':
            search_filters.append({
                'type': 'wildcard',
                'field': 'title',
                'value': "*"+args.title__like+"*"
            })

        if args.status and args.status != ['']:
            search_filters.append({
                    'type': 'terms',
                    'field': 'status.name__keyword',
                    'value': args.status
                })

        if args.source and args.source != ['']:
            search_filters.append({
                'type': 'terms',
                'field': 'source__keyword',
                'value': args.source
            })

        if args.event_rule and args.event_rule != ['']:
            search_filters.append({
                'type': 'terms',
                'field': 'event_rules',
                'value': args.event_rule
            })

        for arg in ['severity','title','tags','organization']:
            if arg in args and args[arg] not in ['', None, []]:
                search_filters.append({
                    'type': 'terms',
                    'field': arg,
                    'value': args[arg]
                })
        
        if args.signature:
            search_filters.append({
                    'type': 'term',
                    'field': 'signature',
                    'value': args.signature
                })

        if args.case_uuid:
            search_filters.append({
                'type': 'match',
                'field': 'case',
                'value': args.case_uuid
            })

        if args.start and args.end:
            search_filters.append({
                'type': 'range',
                'field': 'original_date',
                'value': {
                    'gte': args.start,
                    'lte': args.end
                }
            })

        observables = {}

        raw_event_count = 0
        
        # If not filtering by a signature
        if not args.signature:
           
            search = Event.search()

            search = search[:0]

            # Apply all filters
            for _filter in search_filters:
                search = search.filter(_filter['type'], **{_filter['field']: _filter['value']})

            if args.observables:
                search = search.query('nested', path='event_observables', query=Q({"terms": {"event_observables.value.keyword": args.observables}}))           
                
            raw_event_count = search.count()

            search.aggs.bucket('signature', 'terms', field='signature', order={'max_date': args.sort_direction}, size=100000)
            search.aggs['signature'].metric('max_date', 'max', field='original_date')

            events = search.execute()

            event_uuids = []
            sigs = []

            # Sort the signatures based on what the user has in the sorting options
            reverse_sort = False
            if args.sort_direction == 'desc':
                reverse_sort = True

            sigs = [s['key'] for s in events.aggs.signature.buckets] 

            # START: Second aggregation based on signatures to find first UUID for card display purposes
            # performance necessary
            search = Event.search()
            search = search[:0]

            # Apply all filters
            for _filter in search_filters:
                search = search.filter(_filter['type'], **{_filter['field']: _filter['value']})

            if args.observables:
                search = search.query('nested', path='event_observables', query=Q({"terms": {"event_observables.value.keyword": args.observables}}))

            paged_sigs = sigs[start:end]
           
            search = search.filter('terms', signature=paged_sigs)

            number_of_sigs = len(paged_sigs)
            if number_of_sigs == 0:
                number_of_sigs = 10000

            search.aggs.bucket('signature', 'terms', field='signature', order={'max_date': args.sort_direction}, size=100000)
            search.aggs['signature'].metric('max_date', 'max', field='original_date')
            search.aggs['signature'].bucket('uuid', 'terms', field='uuid', order={'max_date': 'desc'}, size=number_of_sigs)
            search.aggs['signature']['uuid'].metric('max_date', 'max', field='original_date')

            events = search.execute()

            #sigs2 = sorted(events.aggs.signature.buckets, key=lambda sig: sig['max_date']['value'])
            sigs2 = events.aggs.signature.buckets
            for signature in sigs2:
                event_uuids.append(signature.uuid.buckets[0]['key'])

            # END: Second aggregation based on signatures to find first UUID for card display purposes
            # performance necessary

            search = Event.search()

            if args.sort_direction:
                if args.sort_direction == "desc":
                    args.sort_by = f"-{args.sort_by}"
                else:
                    args.sort_by = f"{args.sort_by}"

            search = search.sort(args.sort_by)
            search = search.filter('terms', uuid=event_uuids)
            search = search[0:len(event_uuids)]

            total_events = search.count()
            pages = math.ceil(float(len(sigs) / args.page_size))
            
            events = search.execute()

            # Apply search filters to the event for performing related event calcuations
            [e.set_filters(filters=search_filters) for e in events]
       
        # If filtering by a signature
        else:

            search = Event.search()
            search = search[start:end]

            # Apply all filters
            for _filter in search_filters:
                search = search.filter(_filter['type'], **{_filter['field']: _filter['value']})

            if args.sort_direction:
                if args.sort_direction == "asc":
                    args.sort_by = f"-{args.sort_by}"
                else:
                    args.sort_by = f"{args.sort_by}"

            search = search.sort(args.sort_by)
            search = search.filter('term', signature=args.signature)

            total_events = search.count()

            raw_event_count = total_events

            pages = math.ceil(float(total_events / args.page_size))

            events = search.execute()
        
        for event in events:
            observables[event.uuid] = event.observables
                   
        response = {
            'events': events,
            'observables': json.loads(json.dumps(observables, default=str)),
            'pagination': {
                'total_results': raw_event_count,
                'pages': pages,
                'page': args['page'],
                'page_size': args['page_size']
            }
        }

        return response


    @api.doc(security="Bearer")
    @api.expect(mod_event_create)
    @token_required
    @user_has('add_event')
    def post(self, current_user):
        ''' Creates a new event '''

        observables = []

        original_payload = copy.copy(api.payload)

        # If the event has an observables pop them off the request payload
        # so that the Event can be generated using the remaining dictionary values
        if 'observables' in api.payload:
            observables = api.payload.pop('observables')

        event = Event.get_by_reference(api.payload['reference'])

        if not event:

            # Generate a default signature based off the rule name and the current time
            # signatures are required in the system but user's don't need to supply them
            # these events will remain ungrouped
            hasher = hashlib.md5()
            if 'signature' not in api.payload or api.payload['signature'] == '':
                
                date_string = datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
                hasher.update(f"{api.payload['title']}{date_string}".encode('utf-8'))
                api.payload['signature'] = hasher.hexdigest()

            # Add the current users organization to the event signature
            api.payload['signature'] = hasher.update(api.payload['signature']+current_user.organization).hexdigest()

            event = Event(**api.payload)
            event.save()

            if observables:
                event.add_observable(observables)

            event_rules = EventRule.get_all(organization=current_user.organization)
            if event_rules:
               
                matched = False
                for event_rule in event_rules:

                    matches = []

                    # If the event matches the event rule criteria perform the rule actions
                    try:
                        matched = event_rule.process_rql(original_payload)
                    except EventRuleFailure as e:
                        log_event(organization=current_user.organization, event_type='Event Rule Processing', source_user="System", event_reference=event.reference, time_taken=0, status="Failed", message=f"Failed to process event rule. {e}")

                    # If the rule matched, process the event
                    if matched:
                        event_rule.process_event(event)
                        matches.append(event.uuid)
                        
                        # TODO: Allow for matching on multiple rules that don't have overlapping
                        # actions, e.g. one rule to move it to a case but a different rule to apply
                        # tags to the event
                        # Break out of the loop, we don't want to match on any more rules
                        break
                    
                    if matches:
                        event_rule.last_matched_date = datetime.datetime.utcnow()
                        event_rule.hit_count += len(matches)
                        event_rule.save()
                
                if not matched:
                    event.set_new()
            else:
                event.set_new()

            return {'message': 'Successfully created the event.'}
        else:
            return {'message': 'Event already exists'}, 409


def fetch_observables_from_history(observables):

    search = ObservableHistory.search()
    search = search.filter('terms', value=[o['value'] for o in observables])
    search = search[0:0]
    search.aggs.bucket('values', 'terms', field='value', order={'max_date': 'desc'})
    search.aggs['values'].bucket('max_date', 'max', field='created_at')
    search.aggs['values'].bucket('by_uuid', 'terms', field='uuid', order={'max_date': 'desc'}, size=1)
    search.aggs['values']['by_uuid'].bucket('max_date', 'max', field='created_at')
    search.aggs['values']['by_uuid'].bucket('source', 'top_hits')
   
    history = search.execute()
    observable_history = [bucket['by_uuid'].buckets[0]['source']['hits']['hits'][0]['_source'].to_dict() for bucket in history.aggs.values.buckets]
    in_history = [o['value'] for o in observable_history]
    _observables = observable_history
    [_observables.append(o) for o in observables if o['value'] not in in_history]

    # Maintain the source_field data from the original observable
    for observable in _observables:
        source_observable = [x for x in observables if x['value'] == observable['value']][0]

        if 'source_field' not in observable:            
            if 'source_field' in source_observable:
                observable['source_field'] = source_observable['source_field']
        
        # Merge the latest historical tags with the tags on this current observable
        if 'tags' in observable:
            observable['tags'] = list(set([t for t in source_observable['tags']] + [t for t in observable['tags']]))
        else:
            if 'tags' in source_observable:
                observable['tags'] = source_observable['tags']
        

    return _observables


@api.route('/<uuid>/observables/<value>')
class EventObservable(Resource):

    @api.doc(security="Bearer")
    @api.response('200', 'Success')
    @api.response('400', 'Observable not found')
    @api.expect(mod_observable_update)
    @api.marshal_with(mod_observable_list)
    @token_required
    @user_has('update_event')
    def put(self, uuid, value, current_user):
        ''' Updates an events observable '''

        observable = None
        value = base64.b64decode(value).decode()
        search = Event.search()
        search = search[0:1]
        search = search.filter('term', uuid=uuid)
        search = search.query('nested', path='event_observables', query=Q({"term": {"event_observables.value.keyword": value}}))
        event = search.execute()[0]
        if event:
            search = ObservableHistory.search()
            search = search.filter('term', value=value)
            search = search.filter('term', organization=event.organization)
            search = search.sort({'created_at': {'order': 'desc'}})
            search = search[0:1]
            history = search.execute()

            if history:
                if len(history) >= 1:
                    observable = history[0]
                else:
                    observable = history
            else:
                observable = [o for o in event.event_observables if o['value'] == value][0]

        if observable:

            # Can not flag an observable as safe if it is also flagged as an ioc
            if 'safe' in api.payload:
                observable.safe = api.payload['safe']

            if 'ioc' in api.payload:
                observable.ioc = api.payload['ioc']

            if 'spotted' in api.payload:
                observable.spotted = api.payload['spotted']

            if getattr(observable,'ioc') and getattr(observable,'safe'):
                api.abort(400, 'An observable can not be an ioc if it is flagged safe.')

            observable_dict = observable.to_dict()
            if 'created_at' in observable_dict:
                del observable_dict['created_at']
            if 'created_by' in observable_dict:
                del observable_dict['created_by']
            observable_dict['organization'] = event.organization

            observable_history = ObservableHistory(**observable_dict)
            observable_history.save()

            return observable
        else:
            return api.abort(404, 'Observable not found.')


@api.route("/observables_by_case/<uuid>")
class EventObservablesByCase(Resource):
    '''
    Returns a list of observables for a specific case UUID by querying 
    all the Events for that case and returning a deduplicated list
    '''

    @api.doc(security="Bearer")
    @api.marshal_with(mod_observable_list_paged)
    @token_required
    @user_has('view_case_events')
    def get(self, uuid, current_user):

        search = Event.search()
        search = search.filter('term', case=uuid)
        search = search[:0]
        search.aggs.bucket('observables', 'nested', path="event_observables")
        search.aggs['observables'].metric('unique_values', 'cardinality', field="event_observables.value.keyword")
        search.aggs['observables'].bucket('values', 'top_hits', _source={"includes": [ "event_observables.value",
                          "event_observables.data_type",
                          "event_observables.tlp",
                          "event_observables.ioc",
                          "event_observables.spotted",
                          "event_observables.safe",
                          "event_observables.tags"]}, size=10000)
        events = search.execute()
        exists = set()
        observables = [o.to_dict() for o in events.aggs.observables.values if [(o.value, o.data_type) not in exists and hasattr(o, 'value'), exists.add((o.value, o.data_type))][0]]
        observables = fetch_observables_from_history(observables)
        #observables = []
        #
        #for event in events:
        #    observables += [o for o in event.observables if [(o.value, o.data_type) not in exists, exists.add((o.value, o.data_type))][0]]
        return {
            'observables': list(observables),
            'total_observables': events.aggs.observables.unique_values.value,
            'pagination': {
                'total_results': len(observables),
                'pages': 1,
                'page': 1,
                'page_size': 25
            }
        }


@api.route("/case_events/<uuid>")
class EventsByCase(Resource):
    '''
    Returns only the events for a specified case the user must have the 
    "view_case_events" permission.  This is useful for having user Roles that 
    only have access to Cases and the related Events for that case
    '''

    @api.doc(security="Bearer")
    @api.expect(event_list_parser)
    @api.marshal_with(mod_event_paged_list)
    @token_required
    @user_has('view_case_events')
    def get(self, uuid, current_user):

        args = event_list_parser.parse_args()

        start = (args.page - 1)*args.page_size
        end = (args.page * args.page_size)

        search = Event.search()
        search = search.filter('term', case=uuid)

        search = search[start:end]

        total_events = search.count()

        raw_event_count = total_events

        pages = math.ceil(float(total_events / args.page_size))

        events = search.execute() 
        observables = {}

        for event in events:
            observables[event.uuid] = [o.to_dict() for o in event.observables]

        response = {
            'events': events,
            'observables': json.loads(json.dumps(observables, default=str)),
            'pagination': { 
                'total_results': raw_event_count,
                'pages': pages,
                'page': args['page'],
                'page_size': args['page_size']
            }
        }

        return response


def check_cache(reference, client):
    '''
    Checks memcached to see if the Event has already been sent
    Falls back to Elasticsearch.  If an event is found in Elasticsearch, add
    it back to memcached
    '''

    if reference is None:
        return False

    found = False

    memcached_enabled = current_app.config['THREAT_POLLER_MEMCACHED_ENABLED']
    memcached_key = f"event-processing-{reference}"

    if memcached_enabled:

        # Check memcached first        
        if not found:
            try:
                result = client.get(memcached_key)
                if result:
                    found = True
            except Exception as e:
                found = False

    # If the item was not found in memcached check Elasticsearch
    if not found:
        events = Event.search()
        events = events.filter('term', reference=reference)

        if events.count() > 0:
            found = True

            # We found it, we should probably rehydrate memcached with it
            if memcached_enabled:
                try:
                    client.set(memcached_key, True, expire=1440)
                except Exception as e:
                    current_app.logger.error(f'Failed to set event processing record in memcached for {reference}. {e}')
        else:
            # It did not exist in memcached or Elasticsearch, set it but 
            # mark it as not found
            found = False
            if memcached_enabled:
                try:
                    client.set(memcached_key, True, expire=1440)
                except Exception as e:
                    current_app.logger.error(f'Failed to set event processing record in memcached for {reference}. {e}')

    return found


@api.route('/_bulk')
class CreateBulkEvents(Resource):

    # TODO: This needs some serious love but it should work let's test it

    @api.doc(security="Bearer")
    @api.expect(mod_event_create_bulk)
    @token_required
    @user_has('add_event')
    def post(self, current_user):
        event_queue = Queue()

        workers = []

        task = Task()
        request_id = task.create(task_type='bulk_event_create')
      
        def process_event(queue, request_id, organization=None):
            while not queue.empty():
                raw_event = queue.get()
                event = Event.get_by_reference(raw_event['reference'], organization=organization)

                if not event:

                    # Generate a default signature based off the rule name and the current time
                    # signatures are required in the system but user's don't need to supply them
                    # these events will remain ungrouped
                    
                    if 'signature' not in raw_event or raw_event['signature'] == '':         
                        hasher = hashlib.md5()               
                        date_string = datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
                        hasher.update(f"{raw_event['title']}{date_string}".encode('utf-8'))
                        raw_event['signature'] = hasher.hexdigest()
                    
                    # Add the current users organization to the event signature
                    hasher_b = hashlib.md5()
                    hasher_b.update(raw_event['signature'].encode('utf-8')+current_user.organization.encode('utf-8'))
                    raw_event['signature'] = hasher_b.hexdigest()

                    observables = []
                    #added_observables = []

                    # Start clocking event creation
                    start_event_process_dt = datetime.datetime.utcnow().timestamp()

                    original_payload = copy.copy(raw_event)

                    if 'observables' in raw_event:
                        observables = raw_event.pop('observables')

                    event = Event(**raw_event, organization=organization)
                    event.save()

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
                            except EventRuleFailure as e:
                                log_event(organization=organization, event_type='Event Rule Processing', source_user="System", event_reference=event.reference, time_taken=0, status="Failed", message=f"Failed to process event rule. {e}")

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

                    end_event_process_dt = datetime.datetime.utcnow().timestamp()
                    event_process_time = end_event_process_dt - start_event_process_dt
                    #log_event(event_type='Bulk Event Insert', source_user="System", request_id=request_id, event_reference=event.reference, time_taken=event_process_time, status="Success", message="Event Inserted.", event_id=event.uuid)
                else:
                    log_event(organization=organization, event_type='Bulk Event Insert', source_user="System", request_id=str(request_id), event_reference=event.reference, time_taken=0, status="Failed", message="Event Already Exists.")


        if not current_app.config['NEW_EVENT_PIPELINE']:
            start_bulk_process_dt = datetime.datetime.utcnow().timestamp()

            if 'events' in api.payload and len(api.payload['events']) > 0:
                [event_queue.put(e) for e in api.payload['events']]

            for i in range(0,current_app.config['EVENT_PROCESSING_THREADS']):
                p = threading.Thread(target=process_event, daemon=True, args=(event_queue,str(request_id),current_user.organization))
                workers.append(p)
            [t.start() for t in workers]

            end_bulk_process_dt = datetime.datetime.utcnow().timestamp()
            total_process_time = end_bulk_process_dt - start_bulk_process_dt

            log_event(event_type="Bulk Event Insert", request_id=str(request_id), time_taken=total_process_time, status="Success", message="Bulk request finished.")

            return {"request_id": str(request_id), "response_time": total_process_time}
        else:
            start_bulk_process_dt = datetime.datetime.utcnow().timestamp()

            #client = Client(f"{current_app.config['THREAT_POLLER_MEMCACHED_HOST']}:{current_app.config['THREAT_POLLER_MEMCACHED_PORT']}")
            client = memcached_client.client

            for event in api.payload['events']:
                event['organization'] = current_user.organization
                if not check_cache(event['reference'], client=client):
                    ep.enqueue(event)
            
            # Signal the end of the task
            # The Event Processor will use this event to close the running task
            ep.enqueue({'organization': current_user.organization, '_meta':{'action': 'task_end', 'task_id': str(task.uuid)}})

            end_bulk_process_dt = datetime.datetime.utcnow().timestamp()
            total_process_time = end_bulk_process_dt - start_bulk_process_dt
            #client.close()
            return {"task_id": str(request_id), "response_time": total_process_time}


@api.route("/dismiss_by_filter")
class EventBulkDismiss(Resource):

    @api.doc(security="Bearer")
    @api.expect(mod_event_bulk_dismiss_by_filter)
    @token_required
    @user_has('update_event')
    def put(self, current_user):
        '''
        Dismiss multiple events at a time by supplying a query to select
        the events to dismiss
        '''

        task_id = None

        event_list = []

        settings = Settings.load(organization=current_user.organization)
        if settings.require_event_dismiss_comment and 'dismiss_comment' not in api.payload:
            api.abort(400, 'A dismiss comment is required.')
        
        if settings.require_event_dismiss_comment and 'dismiss_comment' in api.payload and api.payload['dismiss_comment'] in [None, '']:
            api.abort(400, 'A dismiss comment is required.')

        if 'dismiss_reason_uuid' in api.payload:
            reason = CloseReason.get_by_uuid(uuid=api.payload['dismiss_reason_uuid'])
            if not reason:
                api.abort(400, 'A dismiss reason is required.')
        else:
            api.abort(400, 'A dismiss reason is required.')

        # Translate filter types to actual field names
        field_names = {
            'tag': 'tags',
            'title': 'title',
            'status': 'status.name__keyword',
            'organization': 'organization',
            'data_type': 'data_type',
            'severity': 'severity',
            'event_rule': 'event_rules',
            'source': 'source'
        }

        ubq = UpdateByQuery(index='reflex-events')

        # Calculate all the values for the specified field
        fields = {}
        if 'filter' in api.payload:
            filters = json.loads(api.payload['filter'])
            
            for f in filters:
                if f['filter_type'] not in fields:
                    fields[f['filter_type']] = [f['value']]
                else:
                    fields[f['filter_type']].append(f['value'])

        if 'start' not in fields:
            fields['start'] = [(datetime.datetime.utcnow()-datetime.timedelta(days=7)).strftime('%Y-%m-%dT%H:%M:%S')]

        if 'end' not in fields:
            fields['end'] = [(datetime.datetime.utcnow()+datetime.timedelta(days=1)).strftime('%Y-%m-%dT%H:%M:%S')]

        # Set the default state of "include_related"
        # If there is a signature filter never include related
        include_related = True

        uuids = []
        if 'uuids' in api.payload:
            uuids = api.payload['uuids']
       
        # Start building the event query
        search = Event.search()
        
        # If there is a signature filter do NOT include related events
        if 'signature' in fields:
            include_related = False
            if not uuids:
                search = search.query('terms', signature=fields['signature'])
                ubq = ubq.query('terms', signature=fields['signature'])
        
        if uuids:
            search = search.query('terms', uuid=api.payload['uuids'])
            ubq = ubq.query('terms', uuid=api.payload['uuids'])
            
        # Apply all the filters to the event query
        if not 'signature' in fields:
            for field in fields:
                if field not in ['start', 'end', 'observable', 'signature', 'data type', 'title__like']:
                    search = search.filter('terms', **{field_names[field]: fields[field]})
                    ubq = ubq.filter('terms', **{field_names[field]: fields[field]})

                if field == 'title__like':
                    search = search.filter('wildcard', title=f"*{fields[field][0]}*")
                    ubq = ubq.filter('wildcard', title=f"*{fields[field][0]}*")

                if field == 'observable':
                    search = search.query('nested', path='event_observables', query=Q({"terms": {"event_observables.value.keyword": fields[field]}}))
                    ubq = ubq.query('nested', path='event_observables', query=Q({"terms": {"event_observables.value.keyword": fields[field]}}))

                if field == 'data type':
                    search = search.query('nested', path='event_observables', query=Q({"terms": {"event_observables.data_type.keyword": fields['data type']}}))
                    ubq = ubq.query('nested', path='event_observables', query=Q({"terms": {"event_observables.data_type.keyword": fields['data type']}}))

        if 'start' in fields and 'end' in fields:
            search = search.filter('range', original_date={
                    'gte': fields['start'][0],
                    'lte': fields['end'][0]
                })
            ubq = ubq.filter('range', original_date={
                    'gte': fields['start'][0],
                    'lte': fields['end'][0]
                })

        status = EventStatus.get_by_name(name='Dismissed', organization=reason.organization)
        reason = CloseReason.get_by_uuid(api.payload['dismiss_reason_uuid'])

        ubq = ubq.script(
            source="ctx._source.dismiss_comment = params.dismiss_comment;ctx._source.dismiss_reason = params.dismiss_reason;ctx._source.status.name = params.status_name;ctx._source.status.uuid = params.uuid;ctx._source.dismissed_at = params.dismissed_at;if(ctx._source.dismissed_by == null) { ctx._source.dismissed_by = [:];}\nctx._source.dismissed_by.username = params.dismissed_by_username;ctx._source.dismissed_by.organization = params.dismissed_by_organization;ctx._source.dismissed_by.uuid = params.dismissed_by_uuid;",
            #source="ctx._source.dismiss_comment = params.dismiss_comment;ctx._source.dismiss_reason = params.dismiss_reason;ctx._source.status.name = params.status_name;ctx._source.status.uuid = params.uuid;ctx._source.dismissed_at = params.dismissed_at;DateTimeFormatter dtf = DateTimeFormatter.ofPattern(\"yyyy-MM-dd'T'HH:mm:ss.SSSSSS\").withZone(ZoneId.of('UTC'));ZonedDateTime zdt = ZonedDateTime.parse(params.dismissed_at, dtf);ZonedDateTime zdt2 = ZonedDateTime.parse(ctx._source.created_at, dtf);Instant Currentdate = Instant.ofEpochMilli(zdt.getMillis());Instant Startdate = Instant.ofEpochMilli(zdt2.getMillis());ctx._source.time_to_dismiss = ChronoUnit.SECONDS.between(Startdate, Currentdate);",
            params={
                'dismiss_comment': api.payload['dismiss_comment'],
                'dismiss_reason': reason.title if reason else api.payload['dismiss_reason_uuid'],
                'status_name': status.name,
                'uuid': status.uuid,
                'dismissed_at': datetime.datetime.utcnow(),
                'dismissed_by_username': current_user.username,
                'dismissed_by_organization': current_user.organization,
                'dismissed_by_uuid': current_user.uuid
            }
        )
        
        ubq = ubq.params(slices='auto', refresh=True)

        events = list(search.scan())
        
        # Check to see if the user is trying to bulk dismiss across organizations/tenants
        orgs = []
        [orgs.append(e.organization) for e in events if e.organization not in orgs]
        if len(orgs) > 1:
            api.abort(400, 'Bulk dismissal actions organizations is unsupported')

        x = ubq.execute()

        signatures = [e.signature for e in events]
        
        # If we need to include related events, 
        related_events = []
        if include_related and len(uuids) > 0:
            related_search = Event.search()
            rubq = UpdateByQuery(index='reflex-events')

            # Apply all the filters to the event query
            for field in fields:
                if field not in ['start', 'end', 'observable', 'signature', 'data type', 'title__like']:
                    related_search = related_search.filter('terms', **{field_names[field]: fields[field]})
                    rubq = rubq.filter('terms', **{field_names[field]: fields[field]})

                if field == 'title__like':
                    related_search = related_search.filter('wildcard', title=f"*{fields[field][0]}*")
                    rubq = rubq.filter('wildcard', title=f"*{fields[field][0]}*")

                if field == 'observable':
                    related_search = related_search.query('nested', path='event_observables', query=Q({"terms": {"event_observables.value.keyword": fields[field]}}))
                    rubq = rubq.query('nested', path='event_observables', query=Q({"terms": {"event_observables.value.keyword": fields[field]}}))

                if field == 'data type':
                    related_search = related_search.query('nested', path='event_observables', query=Q({"terms": {"event_observables.data_type.keyword": fields['data type']}}))
                    rubq = rubq.query('nested', path='event_observables', query=Q({"terms": {"event_observables.data_type.keyword": fields['data type']}}))

            if 'start' in fields and 'end' in fields:
                related_search = related_search.filter('range', original_date={
                    'gte': fields['start'][0],
                    'lte': fields['end'][0]
                })
                rubq = rubq.filter('range', original_date={
                    'gte': fields['start'][0],
                    'lte': fields['end'][0]
                })

            related_search = related_search.filter('terms', signature=signatures)
            rubq = rubq.filter('terms', signature=signatures)
            rubq = rubq.filter('bool', must_not=[Q('terms', uuid=api.payload['uuids'])])
            
            related_events = list(related_search.scan())
            orgs = []

            [orgs.append(e.organization) for e in related_events if e.organization not in orgs]
            if len(orgs) > 1:
                api.abort(400, 'Bulk actions across organizations is unsupported')

            rubq = rubq.script(
                source="ctx._source.dismiss_comment = params.dismiss_comment;ctx._source.dismiss_reason = params.dismiss_reason;ctx._source.status.name = params.status_name;ctx._source.status.uuid = params.uuid;ctx._source.dismissed_at = params.dismissed_at;if(params.tuning_advice != null) { if (ctx._source.tuning_advice == null) { ctx._source.tuning_advice = '';}ctx._source.tuning_advice = params.tuning_advice;}if(ctx._source.dismissed_by == null) { ctx._source.dismissed_by = [:];}\nctx._source.dismissed_by.username = params.dismissed_by_username;ctx._source.dismissed_by.organization = params.dismissed_by_organization;ctx._source.dismissed_by.uuid = params.dismissed_by_uuid;",
                #source="ctx._source.dismiss_comment = params.dismiss_comment;ctx._source.dismiss_reason = params.dismiss_reason;ctx._source.status.name = params.status_name;ctx._source.status.uuid = params.uuid;ctx._source.dismissed_at = params.dismissed_at;DateTimeFormatter dtf = DateTimeFormatter.ofPattern(\"yyyy-MM-dd'T'HH:mm:ss.SSSSSS\").withZone(ZoneId.of('UTC'));ZonedDateTime zdt = ZonedDateTime.parse(params.dismissed_at, dtf);ZonedDateTime zdt2 = ZonedDateTime.parse(ctx._source.created_at, dtf);Instant Currentdate = Instant.ofEpochMilli(zdt.getMillis());Instant Startdate = Instant.ofEpochMilli(zdt2.getMillis());ctx._source.time_to_dismiss = ChronoUnit.SECONDS.between(Startdate, Currentdate);",
                params={
                    'dismiss_comment': api.payload['dismiss_comment'],
                    'dismiss_reason': reason.title if reason else api.payload['dismiss_reason_uuid'],
                    'status_name': status.name,
                    'uuid': status.uuid,
                    'dismissed_at': datetime.datetime.utcnow(),
                    'dismissed_by_username': current_user.username,
                    'dismissed_by_organization': current_user.organization,
                    'dismissed_by_uuid': current_user.uuid,
                    'tuning_advice': api.payload['tuning_advice'] if 'tuning_advice' in api.payload else None
                }
            )
            rubq = rubq.params(slices='auto', refresh=True)

            x = rubq.execute()

        """[event_list.append(e) for e in events if len(events) > 0 and e not in event_list]
        [event_list.append(e) for e in related_events if len(related_events) > 0 and e not in event_list]

        if len(event_list) > 0:
            task = Task()
            task_id = task.create(task_type='bulk_dismiss_events')
            event_count = 0
            for event in event_list:
                event_dict = event.to_dict()

                event_dict['_meta'] = {
                                'action': 'dismiss',
                                'dismiss_reason': api.payload['dismiss_reason_uuid'],
                                'dismiss_comment': api.payload['dismiss_comment'],
                                '_id': event.meta.id,
                                'updated_by': {
                                    'organization': current_user.organization,
                                    'username': current_user.username,
                                    'uuid': current_user.uuid
                                }
                            }
                ep.enqueue(event_dict)
                event_count += 1
            
            task.set_message(f'{event_count} Events marked for bulk dismissal')
            ep.enqueue({'organization': current_user.organization, '_meta':{'action': 'task_end', 'task_id': str(task.uuid)}})"""

        # Give ES time to do it's thing
        time.sleep(1)
            
        return 200
        

@api.route("/bulk_dismiss")
class EventBulkUpdate(Resource):

    @api.doc(security="Bearer")
    @api.expect(mod_event_bulk_dismiss)
    @token_required
    @user_has('update_event')
    def put(self, current_user):
        ''' Dismiss multiple events at the same time '''

        task_id = None

        settings = Settings.load(organization=current_user.organization)
        if settings.require_event_dismiss_comment and 'dismiss_comment' not in api.payload:
            api.abort(400, 'A dismiss comment is required.')

        if settings.require_event_dismiss_comment and 'dismiss_comment' in api.payload and api.payload['dismiss_comment'] in [None, '']:
            api.abort(400, 'A dismiss comment is required.')

        if 'dismiss_reason_uuid' in api.payload:
            reason = CloseReason.get_by_uuid(uuid=api.payload['dismiss_reason_uuid'])
            if not reason:
                api.abort(400, 'A dismiss reason is required.')                
        else:
            api.abort(400, 'A dismiss reason is required.')

        if 'events' in api.payload:

            task = Task()
            task_id = task.create(task_type='bulk_dismiss_events')
            event_count = 0

            comment = api.payload['dismiss_comment'] if api.payload['dismiss_comment'] != "" else None

            for event in api.payload['events']:
                e = Event.get_by_uuid(uuid=event)

                related_events = Event.get_by_signature_and_status(signature=e.signature, status='New', all_events=True)

                event_dict = e.to_dict()

                event_dict['_meta'] = {
                                'action': 'dismiss',
                                'dismiss_reason': api.payload['dismiss_reason_uuid'],
                                'dismiss_comment': comment,
                                '_id': e.meta.id,
                                'updated_by': {
                                    'organization': current_user.organization,
                                    'username': current_user.username,
                                    'uuid': current_user.uuid
                                }
                            }

                ep.enqueue(event_dict)
                event_count += 1
                if related_events:
                    for related in related_events:
                        if hasattr(related, 'uuid') and related.uuid not in api.payload['events']:
                            related_dict = related.to_dict()
                            related_dict['_meta'] = {
                                'action': 'dismiss',
                                'dismiss_reason': api.payload['dismiss_reason_uuid'],
                                'dismiss_comment': comment,
                                '_id': related.meta.id,
                                'updated_by': {
                                    'organization': current_user.organization,
                                    'username': current_user.username,
                                    'uuid': current_user.uuid
                                }
                            }
                            ep.enqueue(related_dict)
                            event_count += 1

            # Signal the end of the task
            # The Event Processor will use this event to close the running task
            task.set_message(f'{event_count} Events marked for bulk dismissal')
            ep.enqueue({'organization': current_user.organization, '_meta':{'action': 'task_end', 'task_id': str(task.uuid)}})

        return {'task_id': str(task_id)}


@api.route("/<uuid>")
class EventDetails(Resource):

    @api.doc(security="Bearer")
    @api.marshal_with(mod_event_details)
    @token_required
    @user_has('view_events')
    def get(self, uuid, current_user):

        event = Event.get_by_uuid(uuid)
        if event:
            event.event_observables = fetch_observables_from_history(event.event_observables)
            return event
        else:
            api.abort(404, 'Event not found.')

    @api.doc(security="Bearer")
    @token_required
    @user_has('update_event')
    def put(self, uuid, current_user):
        '''Updates an event

        Parameters:
            uuid (str): The unique identifier of the Event
            current_user (User): The current user making the API request
        '''

        if 'dismiss_reason_uuid' in api.payload:
            reason = CloseReason.get_by_uuid(uuid=api.payload['dismiss_reason_uuid'])
            event = Event.get_by_uuid(uuid=uuid)

            comment = None
            if 'dismiss_comment' in api.payload and api.payload['dismiss_comment'] != '':
                comment = api.payload['dismiss_comment']
            
            event.set_dismissed(reason, comment=comment)
            return {'message':'Successfully dismissed event'}, 200
        else:
            return {}

    @api.doc(security="Bearer")
    @token_required
    @user_has('delete_event')
    def delete(self, uuid, current_user):
        '''
        Deletes an event and any related artifacts from the system

        Parameters:
            uuid (str): The unique identifier of the Event
            current_user (User): The current user making the API request
        '''

        event = Event.get_by_uuid(uuid=uuid)

        # Only support deleting events that are not in cases right now
        if event:
            if event.case:
                api.abort(400, 'Event is associated with a case and cant not be deleted.')
            else:
                # Delete any observables from the observables index related to this event
                observables = Observable.get_by_event_uuid(uuid=uuid)
                for observable in observables:
                    observable.delete()

                # Delete the event
                event.delete()

                return {'message': 'Successfully deleted the event.', 'uuid': uuid}, 200
        else:
            api.abort(404, 'Event not found')

event_stats_parser = api.parser()
event_stats_parser.add_argument('status', location='args', default=[
], type=str, action='split', required=False)
event_stats_parser.add_argument('tags', location='args', default=[
], type=str, action='split', required=False)
event_stats_parser.add_argument('signature', location='args', required=False)
event_stats_parser.add_argument(
    'severity', action='split', location='args', required=False)
event_stats_parser.add_argument(
    'title', type=str, location='args', action='split', required=False)
event_stats_parser.add_argument(
    'title__like', type=str, location='args', required=False
)
event_stats_parser.add_argument('observables', location='args', default=[
], type=str, action='split', required=False)
event_stats_parser.add_argument('source', location='args', default=[
], type=str, action='split', required=False)
event_stats_parser.add_argument('event_rule', location='args', default=[
], type=str, action='split', required=False)
event_stats_parser.add_argument('top', location='args', default=10, type=int, required=False)
event_stats_parser.add_argument('start', location='args', type=str, required=False)
event_stats_parser.add_argument('end', location='args', type=str, required=False)
event_stats_parser.add_argument('interval', location='args', default='day', required=False, type=str)
event_stats_parser.add_argument('metrics', location='args', action='split', default=['title','observable','source','tag','status','severity','data_type','event_rule','signature'])
event_stats_parser.add_argument('organization', location='args', action='split', required=False)

@api.route("/stats")
class EventStats(Resource):

    @api.doc(security="Bearer")
    @api.expect(event_stats_parser)
    @token_required
    @user_has('view_events')
    def get(self, current_user):
        '''
        Returns metrics about events that can be used for easier filtering
        of events on the Events List page
        '''

        args = event_stats_parser.parse_args()

        # Set default start/end date filters if they are not set above
        # We do this here because default= on add_argument() is only calculated when the API is initialized
        if not args.start:
            args.start = (datetime.datetime.utcnow()-datetime.timedelta(days=7)).strftime('%Y-%m-%dT%H:%M:%S')
        if not args.end:
            args.end = datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S')
        
        search_filters = []

        # Prevent sub-tenants from seeing the organization metric
        if 'organization' in args.metrics and not hasattr(current_user,'default_org'):
            args.metrics.remove('organization')

        if args.title__like and args.title__like != '':
            search_filters.append({
                'type': 'wildcard',
                'field': 'title',
                'value': "*"+args.title__like+"*"
            })

        if args.status and args.status != ['']:
            search_filters.append({
                'type': 'terms',
                'field': 'status.name__keyword',
                'value': args.status
            })

        if args.source and args.source != ['']:
            search_filters.append({
                'type': 'terms',
                'field': 'source.keyword',
                'value': args.source
            })

        if args.event_rule and args.event_rule != ['']:
            search_filters.append({
                'type': 'terms',
                'field': 'event_rules',
                'value': args.event_rule
            })

        for arg in ['severity','title','tags','organization']:
            if arg in args and args[arg] not in ['', None, []]:
                search_filters.append({
                    'type': 'terms',
                    'field': arg,
                    'value': args[arg]
                })
        
        if args.signature:
            search_filters.append({
                'type': 'term',
                'field': 'signature',
                'value': args.signature
            })

        if args.start and args.end:
            search_filters.append({
                'type': 'range',
                'field': 'original_date',
                'value': {
                    'gte': args.start,
                    'lte': args.end
                }
            })

        search = Event.search()

        # Apply all filters
        for _filter in search_filters:
            search = search.filter(_filter['type'], **{_filter['field']: _filter['value']})

        if args.observables:
            search = search.query('nested', path='event_observables', query=Q({"terms": {"event_observables.value.keyword": args.observables}}))  

        search.aggs.bucket('range', 'filter', range={'original_date': {
                        'gte': args.start,
                        'lte': args.end
                    }})

        if 'title' in args.metrics:
            max_title = args.top if args.top != 10 else 100
            search.aggs['range'].bucket('title', 'terms', field='title', size=max_title)

        if 'tag' in args.metrics:
            max_tags = args.top if args.top != 10 else 100
            search.aggs['range'].bucket('tags', 'terms', field='tags', size=max_tags)

        if 'dismiss_reason' in args.metrics:
            max_reasons = args.top if args.top != 10 else 100
            search.aggs['range'].bucket('dismiss_reason', 'terms', field='dismiss_reason.keyword', size=max_reasons)

        if 'status' in args.metrics:
            max_status = args.top if args.top != 10 else 100
            search.aggs['range'].bucket('status', 'terms', field='status.name.keyword', size=max_status)

        if 'severity' in args.metrics:
            max_severity = args.top if args.top != 10 else 100
            search.aggs['range'].bucket('severity', 'terms', field='severity', size=max_severity)

        if 'signature' in args.metrics:
            max_signature = args.top if args.top != 50 else 100
            search.aggs['range'].bucket('signature', 'terms', field='signature', size=max_signature)

        if 'source' in args.metrics:
            max_source = args.top if args.top != 10 else 100
            search.aggs['range'].bucket('source', 'terms', field='source.keyword', size=max_source)

        if 'event_rule' in args.metrics:
            max_event_rule = args.top if args.top != 10 else 100
            search.aggs['range'].bucket('event_rule', 'terms', field='event_rules', size=1000)

        if 'organization' in args.metrics:
            max_organizations = args.top if args.top != 10 else 100
            search.aggs['range'].bucket('organization', 'terms', field='organization', size=max_organizations)

        if 'observable' in args.metrics:
            max_observables = args.top if args.top != 10 else 100
            search.aggs['range'].bucket('observables', 'nested', path="event_observables")
            search.aggs['range']['observables'].bucket('data_type', 'terms', field='event_observables.data_type.keyword', size=max_observables)
            search.aggs['range']['observables'].bucket('value', 'terms', field='event_observables.value.keyword', size=max_observables)

        if 'time_per_status' in args.metrics:
            search.aggs['range'].buckets('time_per_status', 'terms', field='status.name.keyword', size=max_status)

        search = search[0:0]

        events = search.execute()

        """if 'observable' in args.metrics:
            observable_search = Observable.search()
            observable_search = observable_search.filter('exists', field='events')

            observable_search = observable_search.filter('terms', **{'events': [v['key'] for v in events.aggs.range.uuids.buckets]})

            observable_search.aggs.bucket('data_type', 'terms', field='data_type.keyword', size=50)
            observable_search.aggs.bucket('value', 'terms', field='value', size=100)

            observable_search = observable_search.execute()"""

        events_by_day_by_org_series = []

        if 'events_over_time' in args.metrics and hasattr(current_user, 'default_org') and current_user.default_org:
            events_over_time_by_org = Event.search()

            events_over_time_by_org = events_over_time_by_org[0:0]

            events_over_time_by_org.aggs.bucket('range', 'filter', range={'original_date': {
                'gte': (datetime.datetime.utcnow()-datetime.timedelta(days=30)).strftime('%Y-%m-%dT%H:%M:%S'),
                'lte': datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S')
            }})

            events_over_time_by_org.aggs['range'].bucket('organizations', 'terms', field='organization')
            events_over_time_by_org.aggs['range']['organizations'].bucket('events_per_day', 'date_histogram', field='original_date', format='yyyy-MM-dd', calendar_interval=args.interval, min_doc_count=0)

            events_over_time_by_org = events_over_time_by_org.execute()

            organizations = Organization.search()
            organizations = organizations.scan()
            organization_list = {o.uuid: o.name for o in organizations}

            data = {v['key']: [] for v in events_over_time_by_org.aggs.range.organizations.buckets}
            for k, v in data.items():
                for bucket in events_over_time_by_org.aggs.range.organizations:
                    for b in bucket.events_per_day.buckets:
                        data[bucket['key']].append({
                            'x': b['key_as_string'],
                            'y': b['doc_count']})

            events_by_day_by_org_series = [{'name': organization_list[k], 'data': v} for k, v in data.items()]            

        if 'events_over_time' in args.metrics:
            events_over_time = Event.search()
       
            events_over_time = events_over_time[0:0]

            events_over_time.aggs.bucket('range', 'filter', range={'original_date': {
                        'gte': args.start,
                        'lte': args.end
                    }})

            events_over_time.aggs['range'].bucket('events_per_day', 'date_histogram', field='original_date', format='yyyy-MM-dd', calendar_interval=args.interval, min_doc_count=0)

            events_over_time = events_over_time.execute()

            

        if 'time_per_status_over_time' in args.metrics:
            time_per_status_over_time = Event.search()

            time_per_status_over_time = time_per_status_over_time[0:0]
            
            time_per_status_over_time.aggs.bucket('range', 'filter', range={'original_date': {
                        'gte': args.start,
                        'lte': args.end
                    }})
            
            time_per_status_over_time.aggs['range'].bucket('per_day', 'date_histogram', field='original_date', format='yyyy-MM-dd', calendar_interval=args.interval, min_doc_count=0)
            time_per_status_over_time.aggs['range']['per_day'].bucket('status', 'terms', field='status.name.keyword', size=10)
            time_per_status_over_time.aggs['range']['per_day']['status'].bucket('avg_time_to_dismiss', 'avg', field='time_to_dismiss')
            time_per_status_over_time.aggs['range']['per_day']['status'].bucket('avg_time_to_act', 'avg', field='time_to_act')
            time_per_status_over_time.aggs['range']['per_day']['status'].bucket('avg_time_to_close', 'avg', field='time_to_close')

            time_per_status_over_time = time_per_status_over_time.execute()

        data = {}

        if 'title' in args.metrics:
            data['title'] = {v['key']: v['doc_count'] for v in events.aggs.range.title.buckets}

        if 'severity' in args.metrics:
            data['severity'] = {v['key']: v['doc_count'] for v in events.aggs.range.severity.buckets}

        if 'observable' in args.metrics:
            data['observable value'] = {v['key']: v['doc_count'] for v in events.aggs.range.observables.value.buckets}
            data['data type'] = {v['key']: v['doc_count'] for v in events.aggs.range.observables.data_type.buckets}
            #data['observable value'] = {v['key']: v['doc_count'] for v in observable_search.aggs.value.buckets}
            #data['data type'] = {v['key']: v['doc_count'] for v in observable_search.aggs.data_type.buckets}

        if 'tag' in args.metrics:
            data['tag'] = {v['key']: v['doc_count'] for v in events.aggs.range.tags.buckets}

        if 'event_rule' in args.metrics:
            data['event rule'] = {v['key']: v['doc_count'] for v in events.aggs.range.event_rule.buckets}

        if 'organization' in args.metrics:
            data['organization'] = {v['key']: v['doc_count'] for v in events.aggs.range.organization.buckets}

        if 'status' in args.metrics:
            data['status'] = {v['key']: v['doc_count'] for v in events.aggs.range.status.buckets}

        if 'dismiss_reason' in args.metrics:
            data['dismiss reason'] = {v['key']: v['doc_count'] for v in events.aggs.range.dismiss_reason.buckets}

        if 'source' in args.metrics:
            data['source'] = {v['key']: v['doc_count'] for v in events.aggs.range.source.buckets}        

        if 'signature' in args.metrics:
            data['signature'] = {v['key']: v['doc_count'] for v in events.aggs.range.signature.buckets}

        #if 'time_per_status' in args.metrics:
        #    data['time_per_status'] = {v['key']: v['doc_count'] for v in observable_search.aggs.time_per_status.buckets}
            
        if 'events_over_time' in args.metrics:
            data['events_over_time'] = {v['key_as_string']: v['doc_count'] for v in events_over_time.aggs.range.events_per_day.buckets}

        if 'time_per_status_over_time' in args.metrics:
            data['avg_time_to_act']  = {v['key_as_string']: {x['key']: x['avg_time_to_act']['value'] for x in v.status.buckets} for v in time_per_status_over_time.aggs.range.per_day.buckets}
            data['avg_time_to_dismiss']  = {v['key_as_string']: {x['key']: x['avg_time_to_dismiss']['value'] for x in v.status.buckets} for v in time_per_status_over_time.aggs.range.per_day.buckets}
            data['avg_time_to_close']  = {v['key_as_string']: {x['key']: x['avg_time_to_close']['value'] for x in v.status.buckets} for v in time_per_status_over_time.aggs.range.per_day.buckets}

        if 'events_over_time' in args.metrics and hasattr(current_user, 'default_org') and current_user.default_org:
            data['events_by_day_by_org_series'] = events_by_day_by_org_series

        return data

@api.route("/bulk_delete")
class BulkDeleteEvent(Resource):

    @api.doc(security="Bearer")
    @api.expect(mod_event_bulk_dismiss)
    @token_required
    @user_has('delete_event')
    def delete(self, current_user):
        '''
        Deletes an event and any related artifacts from the system

        Parameters:
            uuid (str): The unique identifier of the Event
            current_user (User): The current user making the API request
        '''

        if api.payload['events']:
            for _event in api.payload['events']:

                event = Event.get_by_uuid(uuid=_event)

                related_events = Event.get_by_signature_and_status(signature=event.signature, status='New', all_events=True)
                if len(related_events) > 0:
                    for evt in related_events:
                        if hasattr(evt, 'uuid') and evt.uuid not in api.payload['events']:
                            evt.delete()
                event.delete()

        time.sleep(1)

        return {'message': 'Successfully deleted Events.'}, 200

"""
@api.route("/<uuid>/update_case")
class EventUpdateCase(Resource):

    @api.doc(security="Bearer")
    @api.marshal_with(mod_event_update_case)
    @api.response('200', 'Success')
    @token_required
    @user_has('update_event')
    def put(self, uuid, current_user):

        if 'action' in api.payload:
            action = api.payload.pop('action')

            if action in ['remove','transfer']:

                event = Event.get_by_uuid()

                if action == 'remove':
                    
                    event.remove_from_case()

                if action == 'transfer':
                    if 'target_case_uuid' in api.payload:
                        event.set_case()
                    else:
                        api(400, 'Missing target case details.')
            
                print('a')
            else:
                api.abort(400, 'Missing or invalid action.')
        else:
            api.abort(400, 'Missing or invalid action.')
"""


event_bulk_select_parser = api.parser()
event_bulk_select_parser.add_argument('status', location='args', default=[
], type=str, action='split', required=False)
event_bulk_select_parser.add_argument('tags', location='args', default=[
], type=str, action='split', required=False)
event_bulk_select_parser.add_argument('observables', location='args', default=[
], type=str, action='split', required=False)
event_bulk_select_parser.add_argument('signature', location='args', required=False)
event_bulk_select_parser.add_argument('source', action='split', location='args', required=False)
event_bulk_select_parser.add_argument(
    'severity', action='split', location='args', required=False)
event_bulk_select_parser.add_argument(
    'grouped', type=xinputs.boolean, location='args', required=False)
event_bulk_select_parser.add_argument(
    'case_uuid', type=str, location='args', required=False)
event_bulk_select_parser.add_argument('search', type=str, action='split', default=[
], location='args', required=False)
#event_list_parser.add_argument('rql', type=str, default="", location="args", required=False)
event_bulk_select_parser.add_argument(
    'title', type=str, location='args', action='split', required=False)
event_bulk_select_parser.add_argument(
    'title__like', type=str, location='args', required=False
)
event_bulk_select_parser.add_argument('organization', location='args', action='split', required=False)
event_bulk_select_parser.add_argument('start', location='args', type=str, required=False)
event_bulk_select_parser.add_argument('end', location='args', type=str, required=False)

@api.route("/bulk_select_all")
class BulkSelectAll(Resource):

    @api.doc(security="Bearer")
    @api.marshal_with(mod_bulk_event_uuids)
    @api.expect(event_bulk_select_parser)
    @api.response('200','Success')
    @token_required
    @user_has('view_events')
    def get(self, current_user):
        args = event_bulk_select_parser.parse_args()
        search_filters = []

        # Set default start/end date filters if they are not set above
        # We do this here because default= on add_argument() is only calculated when the API is initialized
        if not args.start:
            args.start = (datetime.datetime.utcnow()-datetime.timedelta(days=7)).strftime('%Y-%m-%dT%H:%M:%S')
        if not args.end:
            args.end = (datetime.datetime.utcnow()+datetime.timedelta(days=1)).strftime('%Y-%m-%dT%H:%M:%S')

        if args.title__like and args.title__like != '':
            search_filters.append({
                'type': 'wildcard',
                'field': 'title',
                'value': "*"+args.title__like+"*"
            })
        
        if args.status and args.status != ['']:
            search_filters.append({
                    'type': 'terms',
                    'field': 'status.name__keyword',
                    'value': args.status
                })

        if args.source and args.source != ['']:
            search_filters.append({
                'type': 'terms',
                'field': 'source__keyword',
                'value': args.source
            })

        for arg in ['severity','title','tags','organization']:
            if arg in args and args[arg] not in ['', None, []]:
                search_filters.append({
                    'type': 'terms',
                    'field': arg,
                    'value': args[arg]
                })
        
        if args.signature:
            search_filters.append({
                    'type': 'term',
                    'field': 'signature',
                    'value': args.signature
                })

        if args.case_uuid:
            search_filters.append({
                'type': 'match',
                'field': 'case',
                'value': args.case_uuid
            })

        if args.start and args.end:
            search_filters.append({
                'type': 'range',
                'field': 'original_date',
                'value': {
                    'gte': args.start,
                    'lte': args.end
                }
            })
        
        search = Event.search()

         # OBSERVABLESFIX
        if args.observables:
            search = search.query('nested', path='event_observables', query=Q({"terms": {"event_observables.value.keyword": args.observables}}))  

        search = search[:0]

        org_uuids = {}

        # Apply all filters
        for _filter in search_filters:
            search = search.filter(_filter['type'], **{_filter['field']: _filter['value']})

        if not args.signature:
            search.aggs.bucket('signature', 'terms', field='signature', order={'max_date': 'desc'}, size=1000000)
            search.aggs['signature'].metric('max_date', 'max', field='original_date')
            search.aggs['signature'].bucket('uuid', 'terms', field='uuid', size=1, order={'max_date': 'desc'})
            search.aggs['signature']['uuid'].metric('max_date', 'max', field='original_date')
            if hasattr(current_user,'default_org') and current_user.default_org:
                search.aggs['signature']['uuid'].bucket('organization', 'terms', field='organization', size=1)

            events = search.execute()
            event_uuids = []
            for signature in events.aggs.signature.buckets:
                
                event_uuids.append(signature.uuid.buckets[0]['key'])
                if hasattr(current_user,'default_org') and current_user.default_org:
                    org_uuid = signature.uuid.buckets[0].organization.buckets[0]['key']
                    if org_uuid not in org_uuids:
                        org_uuids[org_uuid] = {}
                        org_uuids[org_uuid]['events'] = [signature.uuid.buckets[0]['key']]
                    else:
                        org_uuids[org_uuid]['events'].append(signature.uuid.buckets[0]['key'])

        else:
            events = list(search.scan())
            event_uuids = [e.uuid for e in events]
            org_uuids = {e.organization: {'events': [evt.uuid for evt in events if evt.organization == e.organization]} for e in events}

        if hasattr(current_user,'default_org') and current_user.default_org:
            return {
                'events': event_uuids,
                'organizations': {
                    uuid: {
                        'events': org_uuids[uuid]['events'],
                        'dismiss_reason': '',
                        'dismiss_comment': ''
                    } for uuid in org_uuids
                }
                
            }
        else:
            return {
                'events': event_uuids,
                'organizations': {
                    current_user.organization: {
                        'events': event_uuids,
                        'dismiss_reason': '',
                        'dismiss_comment': ''
                    }
                }
            }

related_events_parser = api.parser()
related_events_parser.add_argument(
    'count', type=xinputs.boolean, location='args', default=False, required=False)
related_events_parser.add_argument(
    'status', type=str, location='args', default='New', required=False
)
@api.route("/<signature>/new_related_events")
class EventNewRelatedEvents(Resource):

    @api.doc(security="Bearer")
    @api.expect(related_events_parser)
    @api.marshal_with(mod_related_events)
    @api.response('200', 'Success')
    @api.response('404', 'Event not found')
    @token_required
    @user_has('view_events')
    def get(self, signature, current_user):
        ''' Returns the UUIDs of all related events that are Open '''

        args = related_events_parser.parse_args()

        if args.count:
            events = Event.search()
            events = events.filter('term', signature='signature')
            return {
                'events': [],
                'count': events.count()
            }
        
        events = Event.get_by_signature_and_status(signature=signature, status='New', all_events=True)        
        related_events = [e.uuid for e in events if hasattr(e.status,'name') and e.status.name == 'New']
        return {
            "events": related_events,
            "count": len(related_events)
        }


@api.route("/queue_stats")
class EventQueueStats(Resource):

    @api.doc(security="Bearer")
    def get(self):
        worker_info = []
        worker_info = ep.worker_info()
        return {"size": ep.qsize(), "workers": worker_info}
