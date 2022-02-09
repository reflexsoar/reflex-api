from re import search
import uuid
import copy
import math
import time
import hashlib
import json
import datetime
import threading
from queue import Queue
from flask import current_app
from flask_restx import Resource, Namespace, fields, inputs as xinputs
from ..model import Event, Observable, EventRule, CloseReason
from ..model.exceptions import EventRuleFailure
from ..utils import check_org, token_required, user_has, log_event
from .shared import ISO8601, JSONField, ObservableCount, IOCCount, mod_pagination, mod_observable_list

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

mod_observable_list = api.model('ObservableList', {
    'uuid': fields.String(),
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
    'raw_log': fields.String
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
    'raw_log': fields.Nested(mod_raw_log, attribute='_raw_log')
})

mod_event_paged_list = api.model('PagedEventList', {
   'events': fields.List(fields.Nested(mod_event_list)),
   'pagination': fields.Nested(mod_pagination)
})

mod_related_events = api.model('RelatedEvents', {
    'events': fields.List(fields.String)
})

mod_event_create_bulk = api.model('EventCreateBulk', {
    'events': fields.List(fields.Nested(mod_event_create))
})

mod_event_bulk_dismiss = api.model('EventBulkDismiss', {
    'events': fields.List(fields.String),
    'dismiss_reason_uuid': fields.String,
    'dismiss_comment': fields.String,
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
    'dismiss_comment': fields.String
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
event_list_parser.add_argument('start', location='args', default=(datetime.datetime.utcnow()-datetime.timedelta(days=7)).strftime('%Y-%m-%dT%H:%M:%S'), type=str, required=False)
event_list_parser.add_argument('end', location='args', default=(datetime.datetime.utcnow()+datetime.timedelta(days=1)).strftime('%Y-%m-%dT%H:%M:%S'), type=str, required=False)
event_list_parser.add_argument('organization', location='args', action='split', required=False)

@api.route("")
class EventListAggregated(Resource):

    @api.doc(security="Bearer")
    @api.marshal_with(mod_event_paged_list)
    @api.expect(event_list_parser)
    @token_required
    @user_has('view_events')
    def get(self, current_user):

        #start_request = datetime.datetime.utcnow()

        args = event_list_parser.parse_args()

        start = (args.page - 1)*args.page_size
        end = (args.page * args.page_size)

        search_filters = []

        #start_filters = datetime.datetime.utcnow()

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
                'field': 'created_at',
                'value': {
                    'gte': args.start,
                    'lte': args.end
                }
            })

        # OBSERVABLESFIX
        if args.observables:
            event_uuids = []

            observables = Observable.search()

            for _filter in search_filters:
                if _filter['type'] == 'range':
                    observables = observables.filter(_filter['type'], **{_filter['field']: _filter['value']})

            observables = observables.filter('terms', value=args.observables)
            observables = observables.filter('exists', field='events')

            observables = observables.params(size=10000).scan()

            event_uuids = [o.events[0] for o in observables]
            
            search_filters.append({
                'type': 'terms',
                'field': 'uuid',
                'value': list(set(event_uuids))
            })

        #end_filters = datetime.datetime.utcnow()

        #filter_total_time = (end_filters - start_filters).total_seconds()

        observables = {}

        raw_event_count = 0
        
        # If not filtering by a signature
        if not args.signature:

            #agg_start = datetime.datetime.utcnow()
            
            search = Event.search()

            search = search[:0]

            # Apply all filters
            for _filter in search_filters:
                search = search.filter(_filter['type'], **{_filter['field']: _filter['value']})
                
            raw_event_count = search.count()

            search.aggs.bucket('signature', 'terms', field='signature', order={'max_date': 'desc'}, size=1000000)
            search.aggs['signature'].metric('max_date', 'max', field='created_at')
            search.aggs['signature'].bucket('uuid', 'terms', field='uuid', size=1, order={'max_date': 'desc'})
            search.aggs['signature']['uuid'].metric('max_date', 'max', field='created_at')

            events = search.execute()

            event_uuids = []
            for signature in events.aggs.signature.buckets:
                event_uuids.append(signature.uuid.buckets[0]['key'])

            #agg_end = datetime.datetime.utcnow()
            #agg_total_time = (agg_end - agg_start).total_seconds()

            #search_start = datetime.datetime.utcnow()

            search = Event.search()
            search = search[start:end]

            if args.sort_direction:
                if args.sort_direction == "asc":
                    args.sort_by = f"-{args.sort_by}"
                else:
                    args.sort_by = f"{args.sort_by}"

            search = search.sort(args.sort_by)
            search = search.filter('terms', uuid=event_uuids)

            total_events = search.count()
            pages = math.ceil(float(total_events / args.page_size))
            
            events = search.execute()

            #search_end = datetime.datetime.utcnow()

            #search_total_time = (search_end - search_start).total_seconds()
       
        # If filtering by a signature
        else:

            #sig_filtered_search_start = datetime.datetime.utcnow()

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

            #sig_filtered_search_end = datetime.datetime.utcnow()

            #sig_filtered_search_total_time = (sig_filtered_search_end - sig_filtered_search_start).total_seconds()

            #print(f'sig_filtered_search_total_time: {sig_filtered_search_total_time}s')

        
        #response_start = datetime.datetime.utcnow()
        
        for event in events:

            # DISABLED 2022-02-08 - BC/JH - Testing
            #event.set_filters(filters=search_filters)
            #observables[event.uuid] = [o.to_dict() for o in event.observables]
            #print(observables)

            #observables[event.uuid] = []
            #for k in event.event_observables:
            #    for v in event.event_observables[k]:
            #        observables[event.uuid].append({'data_type': k, 'value': v })
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

        #response_end = datetime.datetime.utcnow()

        #response_total_time = (response_end - response_start).total_seconds()

        #end_request = datetime.datetime.utcnow()

        #request_total_time = (end_request - start_request).total_seconds()

        #print(f'filter_total_time: {filter_total_time}s')
        #print(f'agg_total_time: {agg_total_time}s')
        #print(f'search_total_time: {search_total_time}s')
        
        #print(f'response_total_time: {response_total_time}s')
        #print(f'request_total_time: {request_total_time}s')

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

        request_id = str(uuid.uuid4())
      
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
                    log_event(organization=organization, event_type='Bulk Event Insert', source_user="System", request_id=request_id, event_reference=event.reference, time_taken=0, status="Failed", message="Event Already Exists.")

        start_bulk_process_dt = datetime.datetime.utcnow().timestamp()
        if 'events' in api.payload and len(api.payload['events']) > 0:
            [event_queue.put(e) for e in api.payload['events']]

        for i in range(0,current_app.config['EVENT_PROCESSING_THREADS']):
            p = threading.Thread(target=process_event, daemon=True, args=(event_queue,request_id,current_user.organization))
            workers.append(p)
        [t.start() for t in workers]

        end_bulk_process_dt = datetime.datetime.utcnow().timestamp()
        total_process_time = end_bulk_process_dt - start_bulk_process_dt

        log_event(event_type="Bulk Event Insert", request_id=request_id, time_taken=total_process_time, status="Success", message="Bulk request finished.")

        return {"request_id": request_id, "response_time": total_process_time}


@api.route("/bulk_dismiss")
class EventBulkUpdate(Resource):

    @api.doc(security="Bearer")
    @api.expect(mod_event_bulk_dismiss)
    @api.marshal_with(mod_event_details, as_list=True)
    @token_required
    @user_has('update_event')
    def put(self, current_user):
        ''' Dismiss multiple events at the same time '''

        if 'dismiss_reason_uuid' in api.payload:
            reason = CloseReason.get_by_uuid(uuid=api.payload['dismiss_reason_uuid'])
            if not reason:
                api.abort(400, 'A dismiss reason is required.')                
        else:
            api.abort(400, 'A dismiss reason is required.')

        if 'events' in api.payload:

            comment = api.payload['dismiss_comment'] if api.payload['dismiss_comment'] != "" else None

            for event in api.payload['events']:
                e = Event.get_by_uuid(uuid=event)
                e.set_dismissed(reason=reason, comment=comment)
                related_events = Event.get_by_signature_and_status(signature=e.signature, status='New', all_events=True)
                if len(related_events) > 0:
                    for evt in related_events:
                        if hasattr(evt, 'uuid') and evt.uuid not in api.payload['events']:
                            evt.set_dismissed(reason=reason, comment=comment)

        time.sleep(1)

        return []


@api.route("/<uuid>")
class EventDetails(Resource):

    @api.doc(security="Bearer")
    @api.marshal_with(mod_event_details)
    @token_required
    @user_has('view_events')
    def get(self, uuid, current_user):

        event = Event.get_by_uuid(uuid)
        if event:
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
        if event and not event.case:
        
            # Remove this event from any cases it may be associated with
            #if event.case:
            #    case = Case.get_by_uuid(uuid=event.case)

            # Delete any observables from the observables index related to this event
            observables = Observable.get_by_event_uuid(uuid=uuid)
            for observable in observables:
                observable.delete()

            # Delete the event
            event.delete()

            return {'message': 'Successfully deleted the event.', 'uuid': uuid}, 200
        else:
            return {'message': 'Event not found'}, 404

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
event_stats_parser.add_argument('top', location='args', default=10, type=int, required=False)
event_stats_parser.add_argument('start', location='args', default=(datetime.datetime.utcnow()-datetime.timedelta(days=7)).strftime('%Y-%m-%dT%H:%M:%S'), type=str, required=False)
event_stats_parser.add_argument('end', location='args', default=(datetime.datetime.utcnow()+datetime.timedelta(days=1)).strftime('%Y-%m-%dT%H:%M:%S'), type=str, required=False)
event_stats_parser.add_argument('interval', location='args', default='day', required=False, type=str)
event_stats_parser.add_argument('metrics', location='args', action='split', default=['title','observable','source','tag','status','severity','data_type'])
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
                'field': 'source.keyword',
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

        if args.start and args.end:
            search_filters.append({
                'type': 'range',
                'field': 'created_at',
                'value': {
                    'gte': args.start,
                    'lte': args.end
                }
            })

        event_uuids = []

        # OBSERVABLESFIX
        if args.observables:
            event_uuids = []

            if any('|' in o for o in args.observables):
                for observable in args.observables:
                    if '|' in observable:
                        value,field = observable.split('|')
                        response = Observable.get_by_value_and_field(value, field)
                        event_uuids += [o.events[0] for o in response]
            else:
                observables = Observable.get_by_value(args.observables)
                event_uuids = [o.events[0] for o in observables if o.events if o.events[0] != None]
            
            search_filters.append({
                'type': 'terms',
                'field': 'uuid',
                'value': list(set(event_uuids))
            })

        search = Event.search()

        # Apply all filters
        for _filter in search_filters:
            search = search.filter(_filter['type'], **{_filter['field']: _filter['value']})

        search.aggs.bucket('range', 'filter', range={'created_at': {
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
            max_signature = args.top if args.top != 10 else 100
            search.aggs['range'].bucket('signature', 'terms', field='signature', size=max_signature)

        if 'source' in args.metrics:
            max_source = args.top if args.top != 10 else 100
            search.aggs['range'].bucket('source', 'terms', field='source.keyword', size=max_source)

        if 'organization' in args.metrics:
            max_organizations = args.top if args.top != 10 else 100
            search.aggs['range'].bucket('organization', 'terms', field='organization', size=max_organizations)

        if 'observable' in args.metrics:
            search.aggs['range'].bucket('uuids', 'terms', field='uuid', size=10000)

        if 'time_per_status' in args.metrics:
            search.aggs['range'].buckets('time_per_status', 'terms', field='status.name.keyword', size=max_status)

        search = search[0:0]

        events = search.execute()

        if 'observable' in args.metrics:
            observable_search = Observable.search()
            observable_search = observable_search.filter('exists', field='events')

            observable_search = observable_search.filter('terms', **{'events': [v['key'] for v in events.aggs.range.uuids.buckets]})

            observable_search.aggs.bucket('data_type', 'terms', field='data_type.keyword', size=50)
            observable_search.aggs.bucket('value', 'terms', field='value', size=100)

            observable_search = observable_search.execute()

        if 'events_over_time' in args.metrics:
            events_over_time = Event.search()
       
            events_over_time = events_over_time[0:0]

            events_over_time.aggs.bucket('range', 'filter', range={'created_at': {
                        'gte': args.start,
                        'lte': args.end
                    }})

            events_over_time.aggs['range'].bucket('events_per_day', 'date_histogram', field='created_at', format='yyyy-MM-dd', calendar_interval=args.interval, min_doc_count=0)

            events_over_time = events_over_time.execute()

        if 'time_per_status_over_time' in args.metrics:
            time_per_status_over_time = Event.search()

            time_per_status_over_time = time_per_status_over_time[0:0]
            
            time_per_status_over_time.aggs.bucket('range', 'filter', range={'created_at': {
                        'gte': args.start,
                        'lte': args.end
                    }})
            
            time_per_status_over_time.aggs['range'].bucket('per_day', 'date_histogram', field='created_at', format='yyyy-MM-dd', calendar_interval=args.interval, min_doc_count=0)
            time_per_status_over_time.aggs['range']['per_day'].bucket('status', 'terms', field='status.name.keyword', size=10)
            time_per_status_over_time.aggs['range']['per_day']['status'].bucket('avg_time_to_dismiss', 'avg', field='time_to_dismiss')
            time_per_status_over_time.aggs['range']['per_day']['status'].bucket('avg_time_to_act', 'avg', field='time_to_act')
            time_per_status_over_time.aggs['range']['per_day']['status'].bucket('avg_time_to_close', 'avg', field='time_to_close')

            time_per_status_over_time = time_per_status_over_time.execute()

        data = {}

        if 'title' in args.metrics:
            data['title'] = {v['key']: v['doc_count'] for v in events.aggs.range.title.buckets}

        if 'tag' in args.metrics:
            data['tag'] = {v['key']: v['doc_count'] for v in events.aggs.range.tags.buckets}

        if 'dismiss_reason' in args.metrics:
            data['dismiss reason'] = {v['key']: v['doc_count'] for v in events.aggs.range.dismiss_reason.buckets}

        if 'status' in args.metrics:
            data['status'] = {v['key']: v['doc_count'] for v in events.aggs.range.status.buckets}

        if 'severity' in args.metrics:
            data['severity'] = {v['key']: v['doc_count'] for v in events.aggs.range.severity.buckets}

        if 'signature' in args.metrics:
            data['signature'] = {v['key']: v['doc_count'] for v in events.aggs.range.signature.buckets}

        if 'source' in args.metrics:
            data['source'] = {v['key']: v['doc_count'] for v in events.aggs.range.source.buckets}

        if 'organization' in args.metrics:
            data['organization'] = {v['key']: v['doc_count'] for v in events.aggs.range.organization.buckets}

        if 'observable' in args.metrics:
            data['observable value'] = {v['key']: v['doc_count'] for v in observable_search.aggs.value.buckets}
            data['data type'] = {v['key']: v['doc_count'] for v in observable_search.aggs.data_type.buckets}

        if 'time_per_status' in args.metrics:
            data['time_per_status'] = {v['key']: v['doc_count'] for v in observable_search.aggs.time_per_status.buckets}
            
        if 'events_over_time' in args.metrics:
            data['events_over_time'] = {v['key_as_string']: v['doc_count'] for v in events_over_time.aggs.range.events_per_day.buckets}

        if 'time_per_status_over_time' in args.metrics:
            data['avg_time_to_act']  = {v['key_as_string']: {x['key']: x['avg_time_to_act']['value'] for x in v.status.buckets} for v in time_per_status_over_time.aggs.range.per_day.buckets}
            data['avg_time_to_dismiss']  = {v['key_as_string']: {x['key']: x['avg_time_to_dismiss']['value'] for x in v.status.buckets} for v in time_per_status_over_time.aggs.range.per_day.buckets}
            data['avg_time_to_close']  = {v['key_as_string']: {x['key']: x['avg_time_to_close']['value'] for x in v.status.buckets} for v in time_per_status_over_time.aggs.range.per_day.buckets}

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
event_bulk_select_parser.add_argument('start', location='args', default=(datetime.datetime.utcnow()-datetime.timedelta(days=7)).strftime('%Y-%m-%dT%H:%M:%S'), type=str, required=False)
event_bulk_select_parser.add_argument('end', location='args', default=(datetime.datetime.utcnow()+datetime.timedelta(days=1)).strftime('%Y-%m-%dT%H:%M:%S'), type=str, required=False)

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
                'field': 'created_at',
                'value': {
                    'gte': args.start,
                    'lte': args.end
                }
            })

        # OBSERVABLESFIX
        if args.observables:
            event_uuids = []

            if any('|' in o for o in args.observables):
                for observable in args.observables:
                    if '|' in observable:
                        value,field = observable.split('|')
                        response = Observable.get_by_value_and_field(value, field)
                        event_uuids += [o.events[0] for o in response]
            else:
                observables = Observable.get_by_value(args.observables)
                event_uuids = [o.events[0] for o in observables if o.events]
            
            search_filters.append({
                'type': 'terms',
                'field': 'uuid',
                'value': list(set(event_uuids))
            })

        observables = {}        
        
        search = Event.search()

        search = search[:0]

        org_uuids = {}

        # Apply all filters
        for _filter in search_filters:
            search = search.filter(_filter['type'], **{_filter['field']: _filter['value']})

        if not args.signature:
            search.aggs.bucket('signature', 'terms', field='signature', order={'max_date': 'desc'}, size=1000000)
            search.aggs['signature'].metric('max_date', 'max', field='created_at')
            search.aggs['signature'].bucket('uuid', 'terms', field='uuid', size=1, order={'max_date': 'desc'})
            search.aggs['signature']['uuid'].metric('max_date', 'max', field='created_at')
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
            org_uuids = [e.organization for e in events]

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

@api.route("/<signature>/new_related_events")
class EventNewRelatedEvents(Resource):

    @api.doc(security="Bearer")
    @api.marshal_with(mod_related_events)
    @api.response('200', 'Success')
    @api.response('404', 'Event not found')
    @token_required
    @user_has('view_events')
    def get(self, signature, current_user):
        ''' Returns the UUIDs of all related events that are Open '''
        events = Event.get_by_signature(signature=signature, all_events=True)
        related_events = [e.uuid for e in events if hasattr(e.status,'name') and e.status.name == 'New']
        return {"events": related_events}
