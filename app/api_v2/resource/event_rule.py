import time
import math
import json
from app.api_v2.model.system import Settings
import ndjson
import datetime
import threading
from queue import Queue
from flask import Response, current_app
from flask_restx import Resource, Namespace, fields, marshal
from werkzeug.datastructures import FileStorage
from werkzeug.utils import secure_filename
from ..rql.parser import QueryParser
from ..model import EventRule, Event, Task, CloseReason, Organization
from ..model.exceptions import EventRuleFailure
from ..utils import random_ending, token_required, user_has, check_org, log_event, default_org
from .shared import ISO8601, AsAttrDict, FormatTags, mod_pagination, mod_observable_list, mod_observable_brief, AsDict, mod_user_list
from .integration import mod_run_action
from .event import mod_event_status
from ... import ep


api = Namespace('EventRule', description='Event Rules control what happens to an event on ingest', path='/event_rule')

mod_event_rule_test = api.model('TestEventRuleQuery', {
    'query': fields.String(required=True),
    'organization': fields.String(required=True),
    'uuid': fields.String,
    'event_count': fields.Integer(required=True),
    'return_results': fields.Boolean,
    'start_date': fields.String,
    'end_date': fields.String,
})

mod_notification_channel = api.model('NotificationChannel', {
    'name': fields.String,
    'uuid': fields.String
})

mod_event_rule_create = api.model('CreateEventRule', {
    'name': fields.String,
    'organization': fields.String,
    'description': fields.String,
    'event_signature': fields.String,
    'merge_into_case': fields.Boolean,
    'create_new_case': fields.Boolean,
    'target_case_uuid': fields.String,
    'set_organization': fields.Boolean,
    'target_organization': fields.String,
    'add_tags': fields.Boolean,
    'tags_to_add': fields.List(fields.String),
    'remove_tags': fields.Boolean,
    'tags_to_remove': fields.List(fields.String),
    'update_severity': fields.Boolean,
    'target_severity': fields.Integer,
    'mute_event': fields.Boolean,
    'mute_period': fields.Integer,
    'query': fields.String,
    'dismiss': fields.Boolean,
    'dismiss_reason': fields.String,
    'dismiss_comment': fields.String,
    'expire': fields.Boolean,
    'expire_days': fields.Integer,
    'active': fields.Boolean,
    'global_rule': fields.Boolean,
    'run_retroactively': fields.Boolean(optional=True),
    'skip_previous_match': fields.Boolean(optional=True),
    'priority': fields.Integer,
    'notification_channels': fields.List(fields.String),
    'protected': fields.Boolean,
    'integration_actions': fields.List(fields.Nested(mod_run_action))
})

mod_event_rule_list = api.model('EventRuleList', {
    'uuid': fields.String,
    'organization': fields.String,
    'name': fields.String,
    'description': fields.String,
    'event_signature': fields.String,
    'dismiss_comment': fields.String,
    'dismiss_reason': fields.String,
    'rule_signature': fields.String,
    'merge_into_case': fields.Boolean,
    'create_new_case': fields.Boolean,
    'target_case_uuid': fields.String,
    'set_organization': fields.Boolean,
    'target_organization': fields.String,
    'add_tags': fields.Boolean,
    'tags_to_add': FormatTags(attribute='tags_to_add'),
    'remove_tags': fields.Boolean,
    'tags_to_remove': FormatTags(attribute='tags_to_remove'),
    'update_severity': fields.Boolean,
    'target_severity': fields.Integer,
    'mute_event': fields.Boolean,
    'mute_period': fields.Integer,
    'dismiss': fields.Boolean,
    'expire': fields.Boolean,
    'expire_days': fields.Integer,
    'active': fields.Boolean,
    'query': fields.String,
    'hits': fields.Integer,
    'hits_last_24': fields.Integer,
    'observables': fields.List(fields.Nested(mod_observable_brief)),
    'expire_at': ISO8601(attribute='expire_at'),
    'created_at': ISO8601(attribute='created_at'),
    'updated_at': ISO8601(attribute='updated_at'),
    'updated_by': fields.Nested(mod_user_list),
    'created_by': fields.Nested(mod_user_list),
    'last_matched_date': ISO8601(attribute='last_matched_date'),
    'global_rule': fields.Boolean,
    'disable_reason': fields.String,
    'priority': fields.Integer,
    'notification_channels': fields.List(fields.String),
    'run_retroactively': fields.Boolean,
    'tags': fields.List(fields.String),
    'high_volume_rule': fields.Boolean,
    'protected': fields.Boolean,
    'integration_actions': fields.List(AsAttrDict)
})

mod_event_rule_list_paged = api.model('PagedEventRuleList', {
    'event_rules': fields.List(fields.Nested(mod_event_rule_list)),
    'pagination': fields.Nested(mod_pagination)
})

mod_event_rql = api.model('EventDetailsRQLFormatted', {
    'uuid': fields.String,
    'title': fields.String(required=True),
    'reference': fields.String(required=True),
    'description': fields.String(required=True),
    'tlp': fields.Integer,
    'severity': fields.Integer,
    'risk_score': fields.Integer,
    'source': fields.String,
    'status': fields.Nested(mod_event_status),
    'tags': fields.List(fields.String),
    'observables': fields.List(fields.Nested(mod_observable_list)),
    'organization': fields.String,
    'detection_id': fields.String,
    'risk_score': fields.Integer,
    'case': fields.String,
    'created_at': ISO8601(attribute='created_at'),
    'modified_at': ISO8601(attribute='updated_at'),
    'raw_log': AsDict,
    'signature': fields.String
})

mod_event_rule_name_only = api.model('EventRuleNames', {
    'uuid': fields.String,
    'name': fields.String
})

event_rule_list_parser = api.parser()
event_rule_list_parser.add_argument('page', type=int, location='args', default=1, required=False)
event_rule_list_parser.add_argument('sort_by', type=str, location='args', default='created_at', required=False)
event_rule_list_parser.add_argument('sort_direction', type=str, location='args', default='asc', required=False)
event_rule_list_parser.add_argument('page_size', type=int, location='args', default=25, required=False)
event_rule_list_parser.add_argument('page_size', location='args', required=False, type=int, default=25)
event_rule_list_parser.add_argument('page', location='args', required=False, type=int, default=1)
event_rule_list_parser.add_argument('rules', location='args', required=False, type=str, action='split')

@api.route("")
class EventRuleList(Resource):

    @api.doc(security="Bearer")
    @api.marshal_with(mod_event_rule_list_paged)
    @api.expect(event_rule_list_parser)
    @token_required
    @user_has('view_event_rules')
    def get(self, current_user):
        ''' Gets a list of all the event rules '''

        args = event_rule_list_parser.parse_args()

        event_rules = EventRule.search()
        event_rules = event_rules.filter('term', deleted=False)

        if args.rules:
            event_rules = event_rules.filter('terms', uuid=list(set(args.rules)))
            
        event_rules = list(event_rules.scan())

        response = {
            'event_rules': event_rules,
            'pagination': {
                'total_results': len(event_rules),
                'pages': 1,
                'page': 1,
                'page_size': args.page_size
            }
        }

        return response

    @api.doc(security="Bearer")
    @api.expect(mod_event_rule_create)
    @api.marshal_with(mod_event_rule_list)
    @api.response('200', 'Successfully created event rule.')
    @token_required
    @default_org
    @user_has('create_event_rule')
    @check_org
    def post(self, user_in_default_org, current_user):
        ''' Creates a new event_rule '''

        if 'organization' in api.payload:
            settings = Settings.load(organization=api.payload['organization'])
        else:
            settings = Settings.load()
        
        if 'organization' in api.payload:
            event_rule = EventRule.get_by_name(name=api.payload['name'], organization=api.payload['organization'])
        else:
            event_rule = EventRule.get_by_name(name=api.payload['name'])

        # Only the default tenant can create global rules
        if 'global_rule' in api.payload and not hasattr(current_user,'default_org'):
            api.payload['global_rule'] = False

        if 'global_rule' not in api.payload:
            api.payload['global_rule'] = False

        if 'dismiss' in api.payload and api.payload['dismiss']:

            if 'dismiss_reason' not in api.payload or api.payload['dismiss_reason'] in [None,'']:
                api.abort(400, 'A dismiss reason is required')          

            if settings.require_event_dismiss_comment and 'dismiss_comment' not in api.payload:
                api.abort(400, 'Dismiss comment required')

            cr = CloseReason.get_by_uuid(uuid=api.payload['dismiss_reason'])
            if not cr:
                api.abort(404, 'Dismiss reason not found')

        if 'expire_days' in api.payload and not isinstance(api.payload['expire_days'], int):
                api.abort(400, 'expire_days should be an integer.')

        # Compute when the rule should expire
        if 'expire' in api.payload and api.payload['expire']:
            if 'expire_days' in api.payload:
                expire_days = api.payload['expire_days']

                expire_at = datetime.datetime.utcnow() + datetime.timedelta(days=expire_days)
                api.payload['expire_at'] = expire_at
            else:
                api.abort(400, 'Missing expire_days field.')

        if 'priority' in api.payload and api.payload['priority'] is not None and (api.payload['priority'] > 65535 or api.payload['priority'] < 1):
            api.abort(400, 'Priority must be between 0 and 65535.')

        # Allows a user to set the organization of events that match this rule
        # This action is restricted to the default organization
        if api.payload.get('set_organization'):
            if user_in_default_org:
                if api.payload.get('target_organization'):
                    target_organization = Organization.get_by_uuid(api.payload.get('target_organization'))
                    if not target_organization:
                        api.abort(404, 'Target organization not found')
            else:
                api.abort(400, 'Must be a member of the parent organization')

        if not event_rule:

            event_rule = EventRule(**api.payload)
            event_rule.active = True

            # Try to parse the rule and if it fails don't activate it
            try:
                event_rule.parse_rule()
                event_rule.parsed_rule = None
            except Exception as e:
                event_rule.active = False
                api.abort(400, f'Invalid RQL Query. {e}')
                #event_rule.disable_reason = f"Invalid RQL query. {e}"

            # Set the default state for new Event Rules to not deleted
            event_rule.deleted = False
            event_rule.save(refresh=True)
            time.sleep(1)

            if event_rule.global_rule and not ep.dedicated_workers:
                ep.restart_workers()
            else:
                if ep.dedicated_workers:
                    ep.restart_workers(organization=event_rule.organization)
                else:
                    ep.restart_workers(organization='all')

            if 'run_retroactively' in api.payload and api.payload['run_retroactively']:
                
                task = Task()
                request_id = task.create(task_type='event_rule_lookbehind', message=f'Event Rule lookbehind for {event_rule.name} complete.', broadcast=True)

                def delayed_retro_push(task, skip_previous, event_rule, api_payload, events):
                    '''
                    Queries for events and pushes them to the event queue for retro processing
                    '''

                    time.sleep(10)

                    try:
                        is_global = api_payload['global_rule'] if 'global_rule' in api_payload and api_payload['global_rule'] == True else False
                        org_specified = api_payload['organization'] if 'organization' in api_payload and api_payload['organization'] != None else None

                        if not is_global and org_specified:
                            events = events.filter('term', organization=api_payload['organization'])
                        elif not is_global:
                            events = events.filter('term', organization=current_user.organization)
                            
                        events = events.filter('term', status__name__keyword='New')

                        task.message += f" {events.count()} events processed."
                        task.save()

                        events = list(events.scan())
                        
                        if events:
                            time.sleep(2)
                            for event in events:

                                # Skip over this event if skip_previous_match is toggled and the
                                # event matches the critera
                                if skip_previous:
                                    if event_rule.uuid in event.event_rules:
                                        continue
                                    
                                event_dict = event.to_dict()

                                if 'event_observables' in event_dict:
                                    event_dict['observables'] = event_dict['event_observables']
                                    
                                event_dict['_meta'] = {
                                    'action': 'retro_apply_event_rule',
                                    '_id': event.meta.id,
                                    'rule_id': str(event_rule.uuid)
                                }
                                ep.enqueue(event_dict)

                        ep.enqueue({'organization': current_user.organization, '_meta':{'action': 'task_end', 'task_id': str(task.uuid)}})
                    except Exception as e:
                        print(e)
                
                skip_previous = False
                if 'skip_previous_match' in api.payload and api.payload['skip_previous_match']:
                    skip_previous = True

                events = Event.search()

                t = threading.Thread(target=delayed_retro_push, daemon=True, args=(task, skip_previous, event_rule, api.payload, events))
                t.start()

            return event_rule
        else:
            api.abort(400, 'Event Rule with this title already exists.')


@api.route("/<uuid>")
class EventRuleDetails(Resource):

    @api.doc(security="Bearer")
    @api.marshal_with(mod_event_rule_list)
    @token_required
    @user_has('view_event_rules')
    def get(self, uuid, current_user):
        ''' Gets a event rule '''
        event_rule = EventRule.get_by_uuid(uuid=uuid)
        if event_rule:
            return event_rule
        else:
            api.abort(404, 'Event rule not found.')

    @api.doc(security="Bearer")
    @api.expect(mod_event_rule_create)
    @api.marshal_with(mod_event_rule_list)
    @token_required
    @user_has('update_event_rule')
    def put(self, uuid, current_user):
        ''' Updates the event rule '''
        event_rule = EventRule.get_by_uuid(uuid=uuid)

        if event_rule:

            if event_rule.protected and event_rule.created_by.uuid != current_user.uuid and not current_user.is_default_org():
                api.abort(400, 'Cannot update protected event rule.')

            if 'expire_days' in api.payload and not isinstance(api.payload['expire_days'], int):
                api.abort(400, 'expire_days should be an integer.')

            # Only the default tenant can create global rules
            if 'global_rule' in api.payload and not hasattr(current_user,'default_org'):
                api.payload['global_rule'] = False

            # Computer when the rule should expire
            if 'expire' in api.payload and api.payload['expire']:
                if 'expire_days' in api.payload:
                    expire_days = api.payload['expire_days']

                    expire_at = datetime.datetime.utcnow() + datetime.timedelta(days=expire_days)
                    api.payload['expire_at'] = expire_at
                else:
                    api.abort(400, 'Missing expire_days field.')

            if 'query' in api.payload and api.payload['query'] != event_rule.query:
                if hasattr(event_rule, 'version') and event_rule.version:
                    api.payload['version'] = event_rule.version + 1
                else:
                    api.payload['version'] = 2

            if len(api.payload) > 0:
                event_rule.update(**{**api.payload, 'disable_reason': None}, refresh=True)
                time.sleep(1)
                
                if event_rule.global_rule:
                    ep.restart_workers()
                else:
                    if ep.dedicated_workers:
                        ep.restart_workers(organization=event_rule.organization)
                    else:
                        ep.restart_workers(organization='all')


            if 'run_retroactively' in api.payload and api.payload['run_retroactively']:

                task = Task()
                request_id = task.create(task_type='event_rule_lookbehind', message=f'Event Rule lookbehind for {event_rule.name} complete.', broadcast=True)

                events = Event.search()
              
                def delayed_retro_push(task, skip_previous, api_payload, events):
                    '''
                    Queries for events and pushes them to the event queue for retro processing
                    '''

                    time.sleep(10)

                    try:
                        is_global = api_payload['global_rule'] if 'global_rule' in api_payload and api_payload['global_rule'] == True else False
                        org_specified = api_payload['organization'] if 'organization' in api_payload and api_payload['organization'] != None else None

                        if not is_global and org_specified:
                            events = events.filter('term', organization=api_payload['organization'])
                        elif not is_global:
                            events = events.filter('term', organization=current_user.organization)
                            
                        events = events.filter('term', status__name__keyword='New')

                        task.message += f" {events.count()} events processed."
                        task.save()

                        events = list(events.scan())
                        
                        if events:
                            time.sleep(2)
                            for event in events:

                                # Skip over this event if skip_previous_match is toggled and the
                                # event matches the critera
                                if skip_previous:
                                    if event_rule.uuid in event.event_rules:
                                        continue
                                    
                                event_dict = event.to_dict()
                                if 'event_observables' in event_dict:
                                    event_dict['observables'] = event_dict['event_observables']
                                event_dict['_meta'] = {
                                    'action': 'retro_apply_event_rule',
                                    '_id': event.meta.id,
                                    'rule_id': event_rule.uuid
                                }
                                ep.enqueue(event_dict)

                        ep.enqueue({'organization': current_user.organization, '_meta':{'action': 'task_end', 'task_id': str(task.uuid)}})
                    except Exception as e:
                        print(e)
                
                skip_previous = False
                if 'skip_previous_match' in api.payload and api.payload['skip_previous_match']:
                    skip_previous = True

                if 'priority' in api.payload and api.payload['priority'] is not None and (api.payload['priority'] > 65535 or api.payload['priority'] < 1):
                    api.abort(400, 'Priority must be between 0 and 65535.')

                with current_app.app_context():
                    t = threading.Thread(target=delayed_retro_push, daemon=True, args=(task, skip_previous, api.payload, events))
                    t.start()
                
            return event_rule
        else:
            api.abort(404, 'Event rule not found.')

    @api.doc(security="Bearer")
    @token_required
    @user_has('delete_event_rule')
    def delete(self, uuid, current_user):
        ''' Removes an event rule '''
        event_rule = EventRule.get_by_uuid(uuid=uuid)
        if event_rule:
            event_rule.name = event_rule.name+random_ending('DELETED')
            event_rule.active = False
            event_rule.deleted = True
            event_rule.save(refresh=True)
            time.sleep(1)
            return {'message': 'Sucessfully deleted the event rule.'}


event_rule_stats_parser = api.parser()
event_rule_stats_parser.add_argument('rules', type=str, location='args', action='split', required=False)
event_rule_stats_parser.add_argument('metrics', type=str, location='args', action='split', required=False, default=['hits'])
event_rule_stats_parser.add_argument('start', location='args', type=str, required=False)
event_rule_stats_parser.add_argument('end', location='args', type=str, required=False)
@api.route("/stats")
class EventRuleStats(Resource):

    @api.doc(security="Bearer")
    @api.expect(event_rule_stats_parser)
    @token_required
    @user_has('view_event_rules')    
    def get(self, current_user):
        args = event_rule_stats_parser.parse_args()

        metrics = {}

        # Set default start/end date filters if they are not set above
        # We do this here because default= on add_argument() is only calculated when the API is initialized
        if not args.start:
            args.start = (datetime.datetime.utcnow()-datetime.timedelta(days=7)).strftime('%Y-%m-%dT%H:%M:%S')
        if not args.end:
            args.end = (datetime.datetime.utcnow()+datetime.timedelta(days=1)).strftime('%Y-%m-%dT%H:%M:%S')

        # Compute the number of hits on an event rule
        if 'hits' in args.metrics:
            search = Event.search()

            search.aggs.bucket('range', 'filter', range={'created_at': {
                        'gte': args.start,
                        'lte': args.end
                    }})
            
            if args.rules and len(args.rules) > 0:
                search = search.filter('terms', event_rules=args.rules)

            search.aggs['range'].bucket('event_rules', 'terms', order={'max_date': 'desc'}, field='event_rules', size=10000)
            search.aggs['range']['event_rules'].metric('max_date', 'max', field='created_at')
            search = search[:0]
            
            result = search.execute()

        # Prepare the hits metric
        if 'hits' in args.metrics:
            metrics['hits'] = {v['key']: v['doc_count'] for v in result.aggs.range.event_rules.buckets}
            metrics['last_hit'] = {v['key']: v['max_date']['value_as_string'] for v in result.aggs.range.event_rules.buckets}

        return metrics


export_rule_parser = api.parser()
export_rule_parser.add_argument('organizations', type=str, action='split', location='args', required=False)

@api.route('/export')
class ExportEventRules(Resource):

    @api.doc(security="Bearer")
    @api.expect(export_rule_parser)
    @api.header('Content-Type', 'application/x-ndjson')
    @token_required
    @check_org
    @user_has('view_event_rules')
    def get(self, current_user):
        '''
        Takes a list of organizations and exports all the Event Rules for the supplied organizations
        as NDJSON, if no organizations are provided, just dump the rules for the users current
        organization.
        '''

        args = export_rule_parser.parse_args()

        event_rules = EventRule.search()

        if args.organizations:
            print(args.organizations)
        else:   
            event_rules = event_rules.filter('term', organization=current_user.organization)
            
        event_rules = event_rules.scan()        

        output = ndjson.dumps([marshal(e, mod_event_rule_list) for e in event_rules])
        resp = Response(output,headers={'Content-Type': 'application/x-ndjson', 'Content-disposition':'attachment; filename=event_rules.ndjson'})
        
        return resp

upload_parser = api.parser()
upload_parser.add_argument('files', location='files',
                           type=FileStorage, required=True, action="append")

@api.route('/import')
class ImportEventRules(Resource):

    @api.doc(security="Bearer")
    @api.expect(upload_parser)
    @token_required
    @default_org
    @user_has('create_event_rule')
    def post(self, user_in_default_org, current_user):

        args = upload_parser.parse_args()

        def allowed_file(filename):
            return '.' in filename and filename.rsplit('.', 1)[1].lower() in ['.ndjson']

        uploaded_files = args.files
        for uploaded_file in uploaded_files:
            print(uploaded_file)
        return ""


@api.route("/test_rule_rql")
class TestEventRQL(Resource):

    @api.expect(mod_event_rule_test)
    @token_required
    @default_org
    @user_has('create_event_rule')
    def post(self, user_in_default_org, current_user):
        ''' Tests an RQL query against a target event to see if the RQL is valid '''

        date_filtered = False

        event = None

        if ('query' in api.payload and api.payload['query'] == '') or 'query' not in api.payload:
            return {'message':'Missing RQL query.', "success": False}, 400

        if 'event_count' in api.payload and api.payload['event_count'] > 2147483647:
            api.abort(400, 'Number of test events can not exceed 2147483647')

        if 'uuid' in api.payload and api.payload['uuid'] not in [None, '']:
            event = Event.get_by_uuid(uuid=api.payload['uuid'])
            event_data = json.loads(json.dumps(marshal(event, mod_event_rql)))            
        else:

            # A date filter is required when not supplying a single event UUID
            if 'start_date' in api.payload and 'end_date' in api.payload:
                date_filtered = True
            else:
                return {'message': 'A date range is required', "succes": False}, 400

            search = Event.search()
            
            if 'organization' in api.payload and api.payload['organization']:
                search = search.filter('term', organization=api.payload['organization'])
            else:
                if hasattr(current_user, 'default_org') and not current_user.default_org:
                    search = search.filter('term', organization=current_user.organization)
            search = search.sort('-original_date')
            search = search[0:api.payload['event_count']]

            # Apply a date filter
            if date_filtered:
                search = search.filter('range', **{'original_date': {
                    'gte': api.payload['start_date'],
                    'lte': api.payload['end_date']
                }})

            if 'event_count' in api.payload and api.payload['event_count'] > 10000:
                events = list(search.scan())
            else:
                events = search.execute()
           
            event_data = [json.loads(json.dumps(marshal(e, mod_event_rql))) for e in events]
       
        try:
            organization = current_user.organization

            if event:
                if user_in_default_org and event.organization != current_user.organization:
                    organization = event.organization
            else:
                if user_in_default_org and 'organization' in api.payload:
                    organization = api.payload['organization']
            
            qp = QueryParser(organization=organization)
            try:
                parsed_query = qp.parser.parse(api.payload['query'])
            except SyntaxError as e:
                api.abort(400, f"Invalid RQL Query.  Please consult the RQL documentation for more information.")
                
            try:
                result = [r for r in qp.run_search(event_data, parsed_query)]
            except Exception as e:
                api.abort(400, f"Invalid RQL Query. {e}")
            hits = len(result)

            response = {"message": f"Query matched {hits} Events", "success": True, "hits": result}
            if len(event_data) > 0:
                if hits/len(event_data) > 0.3:
                    response['message'] = f"Query matched {hits} Events.  This is more than 30% of the events queried.  Please consider refining your query."
                    response['danger'] = True

            if hits > 0:
                if 'return_results' in api.payload and api.payload['return_results']:
                    response['hits'] = [result]
                return response, 200
            else:
                return {"message": "Query did not match target Event", "success": False}, 200
        except ValueError as e:
            return {"message":f"Invalid RQL query. {e}", "success": False}, 400
        