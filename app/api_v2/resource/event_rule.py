import math
import json
import datetime
import threading
from queue import Queue
from flask_restx import Resource, Namespace, fields, marshal
from ..rql.parser import QueryParser
from ..model import EventRule, Event
from ..model.exceptions import EventRuleFailure
from ..utils import token_required, user_has, check_org, log_event
from .shared import ISO8601, FormatTags, mod_pagination, mod_observable_list, mod_observable_brief, AsDict
from .event import mod_event_status

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

mod_event_rule_create = api.model('CreateEventRule', {
    'name': fields.String,
    'organization': fields.String,
    'description': fields.String,
    'event_signature': fields.String,
    'merge_into_case': fields.Boolean,
    'target_case_uuid': fields.String,
    'add_tags': fields.Boolean,
    'tags_to_add': fields.List(fields.String),
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
    'global_rule': fields.Boolean
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
    'target_case_uuid': fields.String,
    'add_tags': fields.Boolean,
    'tags_to_add': FormatTags(attribute='tags_to_add'),
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
    'last_matched_date': ISO8601(attribute='last_matched_date'),
    'global_rule': fields.Boolean
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
    'source': fields.String,
    'status': fields.Nested(mod_event_status),
    'tags': fields.List(fields.String),
    'observables': fields.List(fields.Nested(mod_observable_list)),
    'case': fields.String,
    'created_at': ISO8601(attribute='created_at'),
    'modified_at': ISO8601(attribute='updated_at'),
    'raw_log': AsDict,
    'signature': fields.String
})


event_rule_list_parser = api.parser()
event_rule_list_parser.add_argument('page', type=int, location='args', default=1, required=False)
event_rule_list_parser.add_argument('sort_by', type=str, location='args', default='created_at', required=False)
event_rule_list_parser.add_argument('page_size', type=int, location='args', default=25, required=False)
event_rule_list_parser.add_argument('page_size', location='args', required=False, type=int, default=25)
event_rule_list_parser.add_argument('page', location='args', required=False, type=int, default=1)

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
        event_rules = event_rules.sort('-last_matched_date','-created_at')

        # Paginate the cases
        page = args.page - 1
        total_cases = event_rules.count()
        pages = math.ceil(float(total_cases / args.page_size))

        start = page*args.page_size
        end = args.page*args.page_size
        event_rules = event_rules[start:end]

        event_rules = event_rules.execute()

        response = {
            'event_rules': list(event_rules),
            'pagination': {
                'total_results': total_cases,
                'pages': pages,
                'page': page+1,
                'page_size': args.page_size
            }
        }

        return response

    @api.doc(security="Bearer")
    @api.expect(mod_event_rule_create)
    @api.marshal_with(mod_event_rule_list)
    @api.response('200', 'Successfully created event rule.')
    @token_required
    @user_has('create_event_rule')
    @check_org
    def post(self, current_user):
        ''' Creates a new event_rule '''
        
        if 'organization' in api.payload:
            event_rule = EventRule.get_by_name(name=api.payload['name'], organization=api.payload['organization'])
        else:
            event_rule = EventRule.get_by_name(name=api.payload['name'])

        # Only the default tenant can create global rules
        if 'global_rule' in api.payload and not hasattr(current_user,'default_org'):
            api.payload['global_rule'] = False

        if not event_rule:

            if 'expire_days' in api.payload and not isinstance(api.payload['expire_days'], int):
                api.abort(400, 'expire_days should be an integer.')

            # Computer when the rule should expire
            if 'expire' in api.payload and api.payload['expire']:
                if 'expire_days' in api.payload:
                    expire_days = api.payload['expire_days']

                    expire_at = datetime.datetime.utcnow() + datetime.timedelta(days=expire_days)
                    api.payload['expire_at'] = expire_at
                else:
                    api.abort(400, 'Missing expire_days field.')

            event_rule = EventRule(**api.payload)
            event_rule.active = True
            event_rule.save()

            events = Event.search()

            if 'organization' in api.payload and api.payload['organization']:
                events = events.filter('term', organization=api.payload['organization'])
            else:
                events = events.filter('term', organization=current_user.organization)
                
            events = events.filter('term', status__name__keyword='New')
            events = [e for e in events.scan()]


            matches = []
            def lookbehind(queue, event_rule, organization, matches):
                while not queue.empty():
                    event = queue.get()
                    matched = False
                    try:
                        raw_event = json.loads(json.dumps(marshal(event, mod_event_rql)))
                        matched = event_rule.process_rql(raw_event)
                    except EventRuleFailure as e:
                        log_event(organization=organization, event_type='Event Rule Processing', source_user="System", event_reference=event.reference, time_taken=0, status="Failed", message=f"Failed to process event rule. {e}")

                    # If the rule matched, process the event
                    if matched:
                        event_rule.process_event(event)
                        event.save()
                        matches.append(event.uuid)

            if events:
                workers = []
                event_queue = Queue()
                [event_queue.put(e) for e in events]

            if event_queue: 
                for i in range(0,5):
                    if hasattr(current_user,'default_org') and current_user.default_org:
                        p = threading.Thread(target=lookbehind, daemon=True, args=(event_queue, event_rule, api.payload['organization'], matches))
                    else:
                        p = threading.Thread(target=lookbehind, daemon=True, args=(event_queue, event_rule, current_user.organization, matches))
                    workers.append(p)

                [t.start() for t in workers]
                [t.join() for t in workers]

                if matches:
                    event_rule.last_matched_date = datetime.datetime.utcnow()
                    if event_rule.hit_count != None:
                        event_rule.hit_count += len(matches)
                    else:
                        event_rule.hit_count = len(matches)
                    event_rule.save()

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

            if len(api.payload) > 0:
                event_rule.update(**api.payload)

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
            event_rule.delete(refresh=True)
            return {'message': 'Sucessfully deleted the event rule.'}


@api.route("/test_rule_rql")
class TestEventRQL(Resource):

    @api.expect(mod_event_rule_test)
    @token_required
    @user_has('create_event_rule')
    def post(self, current_user):
        ''' Tests an RQL query against a target event to see if the RQL is valid '''

        date_filtered = False

        if api.payload['query'] == '' or 'query' not in api.payload:
            return {'message':'Missing RQL query.', "success": False}, 400

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
                if not current_user.default_org:
                    search = search.filter('term', organization=current_user.organization)
            search = search.sort('-created_at')
            search = search[0:api.payload['event_count']]

            # Apply a date filter
            if date_filtered:
                search = search.filter('range', **{'created_at': {
                    'gte': api.payload['start_date'],
                    'lte': api.payload['end_date']
                }})

            events = search.execute()
            
            event_data = [json.loads(json.dumps(marshal(e, mod_event_rql))) for e in events]
       
        try:
            qp = QueryParser(organization=current_user.organization)
            parsed_query = qp.parser.parse(api.payload['query'])
            result = [r for r in qp.run_search(event_data, parsed_query)]
            hits = len(result)

            if hits > 0:
                if 'return_results' in api.payload and api.payload['return_results']:
                    return {"message": f"Query matched {hits} Events", "success": True, "hits": [result]}, 200
                return {"message": f"Query matched {hits} Events", "success": True}, 200
            else:
                return {"message": "Query did not match target Event", "success": False}, 200
        except ValueError as e:
            return {"message":f"Invalid RQL query. {e}", "success": False}, 400
        