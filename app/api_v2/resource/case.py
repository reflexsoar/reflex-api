import base64
import datetime
import hashlib
import math
import time

from flask_restx import Namespace, Resource, fields
from flask_restx import inputs as xinputs

from ... import ep
from ..model import (Case, CaseComment, CaseHistory, CaseStatus, CaseTask,
                     Event, EventRule, EventStatus, Observable,
                     ObservableHistory, Q, Settings, User, UpdateByQuery)
from ..utils import (check_org, escape_special_characters_rql, token_required,
                     user_has)
from .observable import (mod_bulk_add_observables, mod_observable_list,
                         mod_observable_list_paged, mod_observable_update)
from .shared import (ISO8601, FormatTags, ObservableCount, ValueCount,
                     mod_pagination, mod_user_list, pager_parser)
from .utils import save_tags, time_since

api = Namespace('Case', description='Reflex cases', path='/case')


mod_case_watchers = api.model('CaseWatchers', {
    'watchers': fields.List(fields.Nested(mod_user_list))
})


mod_case_observables = api.model('CaseObservables', {
    'observables': fields.List(fields.Nested(mod_observable_list))
})

mod_add_events_to_case = api.model('AddEventsToCase', {
    'include_related_events': fields.Boolean,
    'events': fields.List(fields.String)
})

mod_response_message = api.model('ResponseMessage', {
    'message': fields.String
})

mod_add_events_response = api.model('AddEventsToCaseResponse', {
    'results': fields.List(fields.Nested(mod_response_message)),
    'success': fields.Boolean,
    # 'case': fields.Nested(mod_case_full)
})

mod_case_create = api.model('CaseCreate', {
    'title': fields.String(required=True),
    'owner_uuid': fields.String,
    'description': fields.String(required=True),
    'tags': fields.List(fields.String),
    'tlp': fields.Integer(required=True),
    'severity': fields.Integer(required=True),
    'observables': fields.List(fields.String),
    'events': fields.List(fields.String),
    'case_template_uuid': fields.String,
    'include_related_events': fields.Boolean,
    'generate_event_rule': fields.Boolean
})

mod_case_status = api.model('CaseStatusString', {
    'uuid': fields.String,
    'name': fields.String,
    'closed': fields.Boolean
})

mod_case_status_create = api.model('CaseStatusCreate', {
    'name': fields.String,
    'description': fields.String
})

mod_case_status_list = api.model('CaseStatusList', {
    'uuid': fields.String,
    'name': fields.String,
    'description': fields.String,
    'closed': fields.Boolean
})

mod_case_list = api.model('CaseList', {
    # 'id': fields.String,
    'uuid': fields.String,
    'organization': fields.String,
    'title': fields.String,
    'owner': fields.Nested(mod_user_list),
    # 'description': fields.String,
    # 'tags': fields.List(fields.String),
    'tlp': fields.Integer,
    'severity': fields.Integer,
    'status': fields.Nested(mod_case_status),
    'event_count': fields.Integer,
    # 'open_tasks': fields.Integer,
    # 'total_tasks': ValueCount(attribute='tasks'),
    'created_at': ISO8601(attribute='created_at'),
    'updated_at': ISO8601(attribute='updated_at'),
    'case_template_uuid': fields.String,
    'escalated': fields.Boolean
    # 'created_by': fields.Nested(mod_user_list),
    # 'updated_by': fields.Nested(mod_user_list),
    # 'observable_count': ValueCount(attribute='observables'),
    # 'close_reason': fields.Nested(mod_close_reason_list),
    # 'closed': fields.Boolean(),
    # 'case_template': fields.Nested(mod_case_template_brief)
})

mod_case_details = api.model('CaseDetails', {
    
    'uuid': fields.String,
    'organization': fields.String,
    'title': fields.String,
    'owner': fields.Nested(mod_user_list),
    'description': fields.String,
    'tags': FormatTags(attribute='tags'),
    'tlp': fields.Integer,
    'severity': fields.Integer,
    'status': fields.Nested(mod_case_status),
    'event_count': fields.Integer,
    'related_cases': ValueCount(attribute='related_cases'),
    'open_tasks': fields.Integer,
    'total_tasks': fields.Integer,
    'case_template_uuid': fields.String,
    'created_at': ISO8601(attribute='created_at'),
    'updated_at': ISO8601(attribute='updated_at'),
    'created_by': fields.Nested(mod_user_list),
    'updated_by': fields.Nested(mod_user_list),
    'observable_count': ValueCount(attribute='observables'),
    'escalated': fields.Boolean
})

mod_case_paged_list = api.model('PagedCaseList', {
    'cases': fields.List(fields.Nested(mod_case_list)),
    'pagination': fields.Nested(mod_pagination)
})

mod_related_case = api.model('RelatedCase', {
    'id': fields.Integer,
    'uuid': fields.String,
    'title': fields.String,
    'event_count': ValueCount(attribute='events'),
    'observable_count': ObservableCount(attribute='observables'),
    'owner': fields.Nested(mod_user_list),
    'status': fields.Nested(mod_case_status)
})

mod_link_cases = api.model('LinkCases', {
    'cases': fields.List(fields.String)
})


case_parser = pager_parser.copy()
case_parser.add_argument('title', location='args', required=False, type=str)
case_parser.add_argument('title__like', location='args',
                         required=False, type=str)
case_parser.add_argument(
    'description__like', location='args', required=False, type=str)
case_parser.add_argument('observables', location='args',
                         required=False, type=str, action='split')
case_parser.add_argument(
    'organization', location='args', required=False, type=str)
case_parser.add_argument(
    'comments__like', location='args', required=False, type=str)
case_parser.add_argument('status', location='args', required=False, type=str)
case_parser.add_argument('close_reason', location='args',
                         required=False, action="split", type=str)
case_parser.add_argument('severity', location='args',
                         required=False, action="split", type=str)
case_parser.add_argument('owner', location='args',
                         required=False, action="split", type=str)
case_parser.add_argument('tag', location='args',
                         required=False, action="split", type=str)
case_parser.add_argument('search', location='args',
                         required=False, action="split", type=str)
case_parser.add_argument('my_tasks', location='args',
                         required=False, type=xinputs.boolean)
case_parser.add_argument('my_cases', location='args',
                         required=False, type=xinputs.boolean)
case_parser.add_argument('escalated', location='args',
                         required=False, type=xinputs.boolean)
case_parser.add_argument(
    'page', type=int, location='args', default=1, required=False)
case_parser.add_argument('sort_by', type=str, location='args',
                         default='created_at', required=False)
case_parser.add_argument(
    'sort_direction', type=str, location='args', default='desc', required=False
)
case_parser.add_argument('page_size', type=int,
                         location='args', default=25, required=False)
case_parser.add_argument('start', location='args', type=str, required=False)
case_parser.add_argument('end', location='args', type=str, required=False)


@api.route("")
class CaseList(Resource):

    @api.doc(security="Bearer")
    @api.marshal_with(mod_case_paged_list)
    @api.expect(case_parser)
    @token_required
    @user_has('view_cases')
    @check_org
    def get(self, current_user):
        ''' Returns a list of case '''

        args = case_parser.parse_args()

        # Set default start/end date filters if they are not set above
        # We do this here because default= on add_argument() is only calculated when the API is initialized
        # if not args.start:
        #    args.start = (datetime.datetime.utcnow()-datetime.timedelta(days=7)).strftime('%Y-%m-%dT%H:%M:%S')
        # if not args.end:
        #    args.end = (datetime.datetime.utcnow()+datetime.timedelta(days=1)).strftime('%Y-%m-%dT%H:%M:%S')

        cases = Case.search()

        cases = cases.sort('-created_at')

        # Apply filters

        # If the user is attempting to filter by observables, find all the events that have
        # the related observables so we can map them to the cases they belong to
        # and use that as a filter on our overall case search
        case_uuids = []
        if 'observables' in args and args.observables:
            events = Event.search()
            events = events.filter('exists', field='case')
            events = events.filter('nested', path='event_observables', query=Q(
                'terms', event_observables__value__keyword=args.observables))
            events = events.source(['case'])
            events = [e for e in events.scan()]
            if events:
                case_uuids = [e.case for e in events]

        # If the user is attempting to filter by comments, find all the comments
        # with the text they are searching for and use that as a filter on our
        # overall case search
        if 'comments__like' in args and args.comments__like:
            comments = CaseComment.search()
            comments = comments.filter('exists', field='case_uuid')
            comments = comments.filter(
                'wildcard', message__keyword="*"+args.comments__like+"*")
            comments = comments.source(['case_uuid'])
            comments = [c for c in comments.scan()]
            if comments:
                [case_uuids.append(c.case_uuid) for c in comments]

        if case_uuids:
            cases = cases.filter('terms', uuid=case_uuids)

        if 'title__like' in args and args['title__like']:
            cases = cases.filter('wildcard', title="*"+args['title__like']+"*")

        if 'title' in args and args['title']:
            cases = cases.filter('match', title=args['title'])

        if 'description__like' in args and args['description__like']:
            cases = cases.filter(
                'wildcard', description__keyword="*"+args['description__like']+"*")

        if 'status' in args and args['status']:
            cases = cases.filter('match', status__name=args['status'])

        if 'severity' in args and args['severity']:
            cases = cases.filter('terms', severity=args['severity'])

        if 'tag' in args and args['tag']:
            cases = cases.filter('terms', tags=args['tag'])

        if 'organization' in args and args.organization:
            cases = cases.filter('term', organization=args.organization)

        if 'close_reason' in args and args.close_reason:
            cases = cases.filter(
                'terms', close_reason__title__keyword=args.close_reason)

        if args.owner and args.owner not in ['', None, []] and not args.my_cases:
            cases = cases.filter(
                'terms', **{'owner.username__keyword': args.owner})

        if args.escalated == True:
            cases = cases.filter('term', escalated=args.escalated)

        if args.my_cases:
            cases = cases.filter(
                'term', **{'owner.username__keyword': current_user.username})

        if args.start and args.end:
            cases = cases.filter('range', created_at={
                'gte': args.start,
                'lte': args.end
            }
            )

        # Paginate the cases
        page = args.page - 1
        total_cases = cases.count()
        pages = math.ceil(float(total_cases / args.page_size))

        start = page*args.page_size
        end = args.page*args.page_size

        sort_by = args.sort_by
        # Only allow these fields to be sorted on
        if sort_by not in ['title', 'tlp', 'severity', 'status']:
            sort_by = "created_at"

        if sort_by == 'status':
            sort_by = "status.name.keyword"

        if args.sort_direction == 'desc':
            sort_by = f"-{sort_by}"

        cases = cases.sort(sort_by)

        cases = cases[start:end]

        response = {
            'cases': [c for c in cases],
            'pagination': {
                'total_results': total_cases,
                'pages': pages,
                'page': page+1,
                'page_size': args.page_size
            }
        }

        return response

    @api.doc(security="Bearer")
    @api.expect(mod_case_create)
    @api.response('409', 'Case already exists.')
    @api.response('200', "Successfully created the case.")
    @token_required
    @user_has('create_case')
    # @check_org
    def post(self, current_user):
        ''' Creates a new case '''

        owner_uuid = None

        organization = None
        if 'organization' in api.payload:
            organization = api.payload['organization']

        settings = Settings.load(organization=organization)

        if 'owner_uuid' in api.payload:
            owner_uuid = api.payload.pop('owner_uuid')
        else:
            # Automatically assign the case to the creator if they didn't pick an owner
            if settings.assign_case_on_create:
                owner_uuid = current_user.uuid

        # Set a minimum tlp
        if api.payload['tlp'] < 1:
            api.payload['tlp'] = 1

        # Set a maximum tlp
        if api.payload['tlp'] > 4:
            api.payload['tlp'] = 4

        # Set a minimum severity
        if api.payload['severity'] < 1:
            api.payload['severity'] = 1

        # Set a maximum severity
        if api.payload['severity'] > 4:
            api.payload['severity'] = 4

        if 'events' in api.payload:
            events = api.payload.pop('events')

        case = Case(**api.payload)

        # Set the default status to New
        case.status = CaseStatus.get_by_name(name="New", organization=organization)
        case.set_owner(owner_uuid)

        event_update_query = UpdateByQuery(index='reflex-events')

        uuids = []

        if isinstance(events, list) and len(events) > 0:
            

            # Fetch all the events that are being added to the case
            events_to_add = Event.get_by_uuid(uuid=events, all_results=True)

            observables = []
            titles = []
            signatures = []
            # If they exist
            if events_to_add:

                # Add the event uuids to the case
                uuids += events

                start_time = datetime.datetime.utcnow()

                signatures += [event.signature for event in events_to_add if event.signature not in signatures]
                titles += [event.title for event in events_to_add if event.title not in titles]
                observables += [observable for event in events_to_add for observable in event.observables]
                if 'include_related_events' in api.payload and api.payload['include_related_events']:
                    related_events = Event.get_by_signature_and_status(signature=signatures,
                                                                       status='New',
                                                                       all_events=True)
                    if related_events:
                        start_related_events = datetime.datetime.utcnow()
                        titles += [event.title for event in related_events if event.title not in titles]
                        uuids += [event.uuid for event in related_events if event.uuid not in uuids]
                        observables += [observable for event in related_events for observable in event.observables]
                        time_since(start_related_events, "Related Events")                    
                
                time_since(start_time, "Event Loop")

                # Dedupe observables and titles
                observables = list(set(observables))
                titles = list(set(titles))

                # Automatically generates an event rule for the event associated with this case
                if 'generate_event_rule' in api.payload and api.payload['generate_event_rule']:
                    rule_text = f'''# System generated base query
# Pin this rule to this event by it's title
title in ["{'","'.join([escape_special_characters_rql(t) for t in titles])}"]

# Default matching on all present observables
# Consider fine tuning this with expands function
and observables.value|any In ["{'","'.join([escape_special_characters_rql(o.value) for o in observables if isinstance(o.value, str)])}"]'''

                    event_rule = EventRule(
                        name=f"Automatic Rule for Case {case.title}",
                        description=f"Automatic Rule for Case {case.title}",
                        expire=False,
                        expire_days=0,
                        merge_into_case=True,
                        target_case_uuid=case.uuid,
                        query=rule_text,
                        dismiss=False)
                    event_rule.active = True
                    event_rule.save()

            status = EventStatus.get_by_name('Open', organization=case.organization)
            
            event_update_query = event_update_query.query('terms', uuid=uuids)
            event_update_query = event_update_query.script(
                source="ctx._source.case = params.case; ctx._source.status = params.status",
                params={'case': case.uuid,
                        'status': {
                            'name': status.name,
                            'description': status.description,
                            'uuid': status.uuid},
                        'updated_at': datetime.datetime.utcnow().isoformat()
                })
            event_update_query.params(slices='auto', wait_for_completion=False, max_docs=len(uuids))

            case.events = list(set(uuids))

        # If the user selected a case template, take the template items
        # and copy them over to the case
        if 'case_template_uuid' in api.payload:
            case.apply_template(api.payload['case_template_uuid'])

        x = case.save(refresh=True)
        if len(uuids) > 0 and x == 'updated':
            event_update_query.execute()

        # Save the tags so they can be referenced in the future
        save_tags(api.payload['tags'])

        case.add_history(message='Case created')

        time.sleep(0.5)

        # TODO - NOTIFICATIONS: Notify the assigned user that they have been assigned a case
        print(f"Notifying {case.owner} that they have been assigned a case")

        # TODO - NOTIFICATIONS: Notify the users in the tenant that a new case has been created (if enabled)
        # Find all the users to notify that a new case has been created
        notification_users = User.get_by_organization(organization=case.organization)
        for user in notification_users:
            # Notify the user if they have enabled new case notifications but not if they are the owner of the case
            if hasattr(user.notification_settings, 'new_case_email') and user.notification_settings.new_case_email and user.uuid != case.owner.uuid:
                print(f"Notifying {user} that a new case has been created, if enabled {user.notification_settings.new_case_email}")

        return {'message': 'Successfully created the case.', 'uuid': str(case.uuid)}


@api.route("/<uuid>")
class CaseDetails(Resource):

    @api.doc(security="Bearer")
    @api.marshal_with(mod_case_details)
    @api.response('200', 'Success')
    @api.response('404', 'Case not found')
    @token_required
    @user_has('view_cases')
    def get(self, uuid, current_user):
        ''' Returns information about a case '''
        case = Case.get_by_uuid(uuid=uuid)

        if case:
            tasks = CaseTask.get_by_case(uuid=uuid)
            if tasks:
                case.total_tasks = len(tasks)
                case.open_tasks = len([t for t in tasks if t.status == 0])
            else:
                case.total_tasks = 0

            return case
        else:
            api.abort(404, 'Case not found.')

    @api.doc(security="Bearer")
    @api.expect(mod_case_create)
    @api.marshal_with(mod_case_details)
    @token_required
    @user_has('update_case')
    def put(self, uuid, current_user):
        ''' Updates information for a case '''
        case = Case.get_by_uuid(uuid=uuid)
        case_watchers = User.get_by_uuid(case.watchers)
        if case:

            for f in ['severity', 'tlp', 'status_uuid', 'owner', 'description', 'owner_uuid', 'escalated']:
                value = ""
                message = None

                import json

                if f in api.payload:
                    if f == 'status_uuid':
                        status = CaseStatus.get_by_uuid(
                            uuid=api.payload['status_uuid'])

                        # Remove the closure reason if the new status re-opens the case
                        if not status.closed:
                            api.payload['close_reason_uuid'] = None

                        value = status.name
                        f = 'status'

                        case.status = status
                        case.save()

                        if status.closed:
                            case.close(api.payload['close_reason_uuid'])
                            # TODO - NOTIFICATIONS: Notify the watchers that the case has been closed
                            if case_watchers:
                                for watcher in case_watchers:
                                    print(
                                        f"Notifying {watcher} that the case has been closed, if their notification settings allow it")
                        else:
                            if hasattr(case, 'closed') and case.closed:
                                case.reopen()
                                # TODO - NOTIFICATIONS: Notify the watchers that the case has been re-opened
                                if case_watchers:
                                    for watcher in case_watchers:
                                        print(
                                            f"Notifying {watcher} that the case has been re-opened, if their notification settings allow it")

                    elif f == 'severity':

                        if api.payload[f] > 4:
                            api.payload[f] = 4

                        if api.payload[f] < 1:
                            api.payload[f] = 1

                        value = {1: 'Low', 2: 'Medium', 3: 'High',
                                 4: 'Critical'}[api.payload[f]]

                        # TODO - NOTIFICATIONS: Notify the watchers that the severity has changed
                        if case_watchers:
                            for watcher in case_watchers:
                                print(
                                    f"Notifying {watcher} that the severity has changed, if their notification settings allow it")

                    elif f == 'description':
                        message = '**Description** updated'

                    elif f == 'owner':
                        owner = api.payload.pop(f)
                        if owner:
                            owner = User.get_by_uuid(uuid=owner['uuid'])

                            if owner:
                                message = 'Case assigned to **{}**'.format(
                                    owner.username)
                                api.payload['owner'] = {
                                    'username': owner.username, 'uuid': owner.uuid}
                            else:
                                message = 'Case unassigned'
                                api.payload['owner'] = {}
                        else:
                            message = 'Case unassigned'
                            api.payload['owner'] = None

                    elif f == 'escalated':
                        if api.payload[f]:
                            message = 'Case escalated'
                        else:
                            message = 'Case de-escalated'

                    if message:
                        case.add_history(message=message)
                    else:
                        case.add_history(
                            message="**{}** changed to **{}**".format(f.title(), value))

            if 'tags' in api.payload:
                save_tags(api.payload['tags'])

            if 'case_template_uuid' in api.payload:
                remove_successful = case.remove_template()
                if remove_successful:
                    case.apply_template(api.payload['case_template_uuid'])

            case.update(**api.payload, refresh=True)

            tasks = CaseTask.get_by_case(uuid=uuid)
            if tasks:
                case.total_tasks = len(tasks)
                case.open_tasks = len([t for t in tasks if t.status == 0])
            else:
                case.total_tasks = 0

            return case
        else:
            api.abort(404, 'Case not found.')

    @api.doc(security="Bearer")
    @token_required
    @user_has('delete_case')
    def delete(self, uuid, current_user):
        ''' Deletes a case '''
        case = Case.get_by_uuid(uuid=uuid)
        if case:

            # Set any associated events back to New status
            if case.events:
                for event_uuid in case.events:
                    event = Event.get_by_uuid(event_uuid)
                    if event:
                        event.case = None
                        event.set_new()

            # DEPRECATED: This method is no longer used to store observales
            # suc they don't need deleted - BC 2022-05-03
            #observables = Observable.get_by_case_uuid(uuid=uuid)
            # if observables and len(observables) > 0:
            #    [o.delete() for o in observables]

            tasks = CaseTask.get_by_case(uuid=uuid, all_results=True)
            if tasks and len(tasks) > 0:
                [t.delete() for t in tasks]

            comments = CaseComment.get_by_case(uuid=uuid)
            if comments and len(comments) > 0:
                [c.delete() for c in comments]

            history = CaseHistory.get_by_case(uuid=uuid)
            if history and len(history) > 0:
                [h.delete() for h in history]

            case.delete()
            return {'message': 'Sucessfully deleted case.'}


@api.route("/<uuid>/add_events")
class AddEventsToCase(Resource):

    @api.doc(security="Bearer")
    @api.expect(mod_add_events_to_case)
    @api.marshal_with(mod_add_events_response)
    @api.response(207, 'Success')
    @api.response(404, 'Case not found.')
    @token_required
    @user_has('update_case')
    def put(self, uuid, current_user):
        '''Merges an event or events in to a case

        Parameters:
            uuid (str): The UUID of the case

        Return:
            dict: JSON response containing event details
        '''

        case = Case.get_by_uuid(uuid=uuid)
        if case:
            settings = Settings.load(organization=case.organization)
            events = Event.get_by_uuid(uuid=api.payload['events'], all_results=True)

            signatures = []

            if events:

                if any([event.organization != case.organization for event in events]):
                    api.abort(400, 'One or more events are not associated with this cases organization.')

                uuids = [event.uuid for event in events]
                signatures = [event.signature for event in events if event.signature not in signatures]
                
                if 'include_related_events' in api.payload and api.payload['include_related_events'] == True:
                    related_events = Event.get_by_signature_and_status(signature=signatures,
                                                                        status='New',
                                                                        all_events=True)
                    if related_events:
                        uuids.extend([event.uuid for event in related_events if event.uuid not in uuids])

                status = EventStatus.get_by_name('Open', organization=case.organization)
                event_update_query = UpdateByQuery(index='reflex-events')
                event_update_query = event_update_query.query('terms', uuid=uuids)
                event_update_query = event_update_query.script(
                    source="ctx._source.case = params.case; ctx._source.status = params.status",
                    params={'case': case.uuid,
                            'status': {
                                'name': status.name,
                                'description': status.description,
                                'uuid': status.uuid},
                            'updated_at': datetime.datetime.utcnow().isoformat()
                    })
                event_update_query.params(slices='auto', wait_for_completion=False, max_docs=len(uuids))
                event_update_query.execute()

                if case.events:
                    case.events.extend(uuids)
                else:
                    case.events = uuids

                case.add_history(
                    message=f'{len(uuids)} events added')

                if case.closed and settings.reopen_case_on_event_merge:
                    # TODO - NOTIFICATIONS: Notify case owner that case has been reopened
                    case.reopen(skip_save=True)

                case.save()
                return "YARP"
            else:
                api.abort(404, 'Events not found.')

        api.abort(404, 'Case not found.')


@api.route("/<uuid>/observables")
class CaseObservables(Resource):

    @api.doc(security="Bearer")
    @api.marshal_with(mod_observable_list_paged, as_list=True)
    @api.response('200', 'Successs')
    @api.response('404', 'Case not found')
    @token_required
    @user_has('view_cases')
    def get(self, uuid, current_user):
        ''' Returns the observables for a case'''
        observables = Observable.get_by_case_uuid(uuid)

        if not observables:
            observables = []

        return {'observables': observables, 'pagination': {}}


@api.route("/<uuid>/observables/<value>")
class CaseObservable(Resource):

    @api.doc(security="Bearer")
    @api.response('200', 'Success')
    @api.response('404', 'Observable not found')
    @api.marshal_with(mod_observable_list)
    @token_required
    @user_has('view_cases')
    def get(self, uuid, value, current_user):
        ''' Returns the information about a single observable '''
        case = Case.get_by_uuid(uuid=uuid)

        if case:

            search = Event.search()
            search = search[0:1]
            search = search.filter('term', case=uuid)
            search = search.query('nested', path='event_observables', query=Q(
                {"terms": {"event_observables.value": value}}))

            return {}
        else:
            api.abort(404, 'Observable not found.')

    @api.doc(security="Bearer")
    @api.response('200', 'Success')
    @api.response('400', 'Observable not found')
    @api.expect(mod_observable_update)
    @api.marshal_with(mod_observable_list)
    @token_required
    @user_has('update_case')
    def put(self, uuid, value, current_user):
        ''' Updates a cases observable '''

        observable = None

        value = base64.b64decode(value).decode()

        search = Event.search()
        search = search[0:1]
        search = search.filter('term', case=uuid)
        search = search.query('nested', path='event_observables', query=Q(
            {"term": {"event_observables.value.keyword": value}}))
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
                observable = [
                    o for o in event.event_observables if o['value'] == value][0]

        if observable:

            # Can not flag an observable as safe if it is also flagged as an ioc
            if 'safe' in api.payload:
                observable.safe = api.payload['safe']

            if 'ioc' in api.payload:
                observable.ioc = api.payload['ioc']

            if 'spotted' in api.payload:
                observable.spotted = api.payload['spotted']

            if getattr(observable, 'ioc') and getattr(observable, 'safe'):
                api.abort(
                    400, 'An observable can not be an ioc if it is flagged safe.')

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


@api.route("/<uuid>/add_observables/_bulk")
class CaseAddObservables(Resource):

    @api.doc(security="Bearer")
    @api.response('200', 'Success')
    @api.expect(mod_bulk_add_observables)
    @api.marshal_with(mod_case_observables)
    @token_required
    @user_has('update_case')
    @check_org
    def post(self, uuid, current_user):
        ''' Adds multiple observables to a case '''
        case = Case.get_by_uuid(uuid=uuid)

        if case:

            organization = case.organization
            if 'organization' in api.payload:
                organization = api.payload['organization']

            if 'observables' in api.payload:
                _observables = api.payload['observables']
                observables = []

                # Make sure tags are in the observables
                for observable in _observables:
                    if 'tag' not in observable:
                        observable['tag'] = []

                    # If any of the values are not False, which is the default, add a history item
                    # for this observable
                    if True in (observable['ioc'], observable['spotted'], observable['safe']):
                        observable_history = ObservableHistory(
                            **observable, organization=organization)
                        observable_history.save()

                    observables.append(observable)

                status = EventStatus.get_by_name(
                    name='Open', organization=organization)

                h = hashlib.md5()
                h.update(str(datetime.datetime.utcnow().timestamp()).encode())
                _id = base64.b64encode(h.digest()).decode()

                event = Event(title='[REFLEX] User Added Observables',
                              description=f'{current_user.username} has added additional observables to a case.',
                              signature=case.uuid,
                              event_observables=observables,
                              case=case.uuid,
                              tags=['manual-observables'],
                              severity=1,
                              status=status.to_dict(),
                              organization=organization,
                              raw_log='',
                              source='reflex-system',
                              reference=_id
                              )
                event.save()

                if case.events:
                    case.events.append(event.uuid)
                else:
                    case.events = [event.uuid]
                case.save()
                #case.add_observables(observables, case.uuid, organization=organization)
                case.add_history(f"Added {len(observables)} observables")

                return {'observables': [o for o in observables]}
            else:
                return {'observables': []}
        else:
            api.abort(404, 'Case not found.')


@api.route('/<uuid>/relate_cases')
class RelateCases(Resource):

    @api.doc(security="Bearer")
    @api.marshal_with(mod_related_case, envelope='related_cases')
    @api.response(207, 'Success')
    @api.response(404, 'Case not found.')
    @token_required
    @user_has('view_cases')
    def get(self, current_user, uuid):
        ''' Returns a list of related cases '''
        case = Case.get_by_uuid(uuid=uuid)
        if case:
            if case.related_cases:
                return Case.get_by_uuid(uuid=case.related_cases)
        return []

    @api.doc(security="Bearer")
    @api.expect(mod_link_cases)
    @api.marshal_with(mod_related_case, envelope='related_cases')
    @api.response(207, 'Success')
    @api.response(404, 'Case not found.')
    @token_required
    @user_has('update_case')
    def put(self, current_user, uuid):

        case = Case.get_by_uuid(uuid=uuid)
        related_cases = Case.get_related_cases(uuid=uuid)
        cases = []
        if case:
            if 'cases' in api.payload:
                _cases = api.payload.pop('cases')
                for c in _cases:
                    _case = Case.get_by_uuid(uuid=c)
                    if _case:

                        if case.related_cases and _case not in case.related_cases:
                            case.related_cases.append(_case.uuid)
                            if _case.related_cases:
                                _case.related_cases.append(case.uuid)
                            else:
                                _case.related_cases = [case.uuid]
                        else:
                            case.related_cases = [_case.uuid]
                            _case.related_cases = [case.uuid]
                        _case.save()
                        cases.append(_case)
                case.save()

            return [c for c in cases+related_cases]
        else:
            return []

    @api.doc(security="Bearer")
    @api.marshal_with(mod_related_case, envelope='related_cases')
    @api.response(207, 'Success')
    @api.response(404, 'Case not found.')
    @token_required
    @user_has('update_case')
    def delete(self, current_user, uuid):
        ''' Unlinks a case or a group of cases '''

        case = Case.get_by_uuid(uuid=uuid)
        related_cases = Case.get_related_cases(uuid=uuid)
        if case:
            if 'cases' in api.payload:
                _cases = api.payload.pop('cases')
                if case.related_cases:
                    case.related_cases = [
                        c for c in case.related_cases if c not in _cases]
                    case.save()

                for c in _cases:
                    _case = Case.get_by_uuid(uuid=c)
                    if _case.related_cases:
                        _case.related_cases = [
                            c for c in case.related_cases if c not in [uuid]]
                        _case.save()

        cases = [c for c in related_cases if c.uuid not in _cases]
        if len(cases) > 0:
            return [c for c in cases]
        else:
            return []


@api.route('/<uuid>/watch')
class WatchCase(Resource):

    @api.doc(security="Bearer")
    @api.response(207, 'Success')
    @api.response(404, 'Case not found.')
    @api.marshal_with(mod_case_watchers)
    @token_required
    @user_has('view_cases')
    def post(self, current_user, uuid):
        ''' Sets a case as watched for the current user '''
        case = Case.get_by_uuid(uuid=uuid)
        if case:
            if case.watchers:
                if current_user.uuid not in case.watchers:
                    case.add_watcher(current_user.uuid)
                    current_user.watch_case(case.uuid)
            else:
                case.watchers = [current_user.uuid]
            case.save()
            watchers = User.get_by_uuid(uuid=case.watchers)
            return {'watchers': watchers}
        else:
            api.abort(404, 'Case not found.')

@api.route('/<uuid>/unwatch')
class UnwatchCase(Resource):

    @api.doc(security="Bearer")
    @api.response(207, 'Success')
    @api.response(404, 'Case not found.')
    @api.marshal_with(mod_case_watchers)
    @token_required
    @user_has('view_cases')
    def post(self, current_user, uuid):
        ''' Removes a case from the watched list for the current user '''
        case = Case.get_by_uuid(uuid=uuid)
        if case:
            if case.watchers:
                if current_user.uuid in case.watchers:
                    case.remove_watcher(current_user.uuid)
                    current_user.unwatch_case(case.uuid)
            case.save()
            watchers = User.get_by_uuid(uuid=case.watchers)
            return {'watchers': watchers}
        else:
            api.abort(404, 'Case not found.')


case_stats_parser = api.parser()
case_stats_parser.add_argument('title', location='args', default=[
], type=str, action='split', required=False)
case_stats_parser.add_argument('status', location='args', default=[
], type=str, action='split', required=False)
case_stats_parser.add_argument('tags', location='args', default=[
], type=str, action='split', required=False)
case_stats_parser.add_argument('owner', location='args', default=[
], type=str, action='split', required=False)
case_stats_parser.add_argument('close_reason', location='args', default=[
], type=str, action='split', required=False)
case_stats_parser.add_argument(
    'top', location='args', default=10, type=int, required=False)
case_stats_parser.add_argument(
    'my_cases', location='args', required=False, type=xinputs.boolean)
case_stats_parser.add_argument(
    'escalated', location='args', required=False, type=xinputs.boolean)
case_stats_parser.add_argument(
    'interval', location='args', default='day', required=False, type=str)
case_stats_parser.add_argument(
    'start', location='args', type=str, required=False)
case_stats_parser.add_argument(
    'end', location='args', type=str, required=False)
case_stats_parser.add_argument('metrics', location='args', action='split', default=[
                               'title', 'tag', 'status', 'severity', 'close_reason', 'owner', 'organization', 'escalated'])
case_stats_parser.add_argument(
    'organization', location='args', action='split', required=False)


@api.route('/stats')
class CaseStats(Resource):

    @api.doc(security="Bearer")
    @api.expect(case_stats_parser)
    @token_required
    @user_has('view_cases')
    def get(self, current_user):
        '''
        Returns metrics about cases that can be used for easier filtering
        of cases on the Case List page
        '''

        args = case_stats_parser.parse_args()

        # Set default start/end date filters if they are not set above
        # We do this here because default= on add_argument() is only calculated when the API is initialized
        # if not args.start:
        #    args.start = (datetime.datetime.utcnow()-datetime.timedelta(days=7)).strftime('%Y-%m-%dT%H:%M:%S')
        # if not args.end:
        #    args.end = datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S')

        search_filters = []

        if args.status and args.status != ['']:
            search_filters.append({
                'type': 'terms',
                'field': 'status.name__keyword',
                'value': args.status
            })

        if args.close_reason and args.close_reason != ['']:
            search_filters.append({
                'type': 'terms',
                'field': 'close_reason.title__keyword',
                'value': args.close_reason
            })

        if args.owner and args.owner not in ['', None, []] and not args.my_cases:
            search_filters.append({
                'type': 'terms',
                'field': 'owner.username__keyword',
                'value': args.owner
            })

        if args.my_cases:
            search_filters.append({
                'type': 'term',
                'field': 'owner.username__keyword',
                'value': current_user.username
            })

        if args.escalated == True:
            search_filters.append({
                'type': 'term',
                'field': 'escalated',
                'value': args.escalated
            })

        for arg in ['severity', 'title', 'tags', 'organization']:
            if arg in args and args[arg] not in ['', None, []]:
                search_filters.append({
                    'type': 'terms',
                    'field': arg,
                    'value': args[arg]
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

        search = Case.search()

        # Apply all filters
        for _filter in search_filters:
            search = search.filter(
                _filter['type'], **{_filter['field']: _filter['value']})

        search.aggs.bucket('range', 'filter', range={'created_at': {
            'gte': args.start,
            'lte': args.end
        }})

        if 'title' in args.metrics:
            max_title = args.top if args.top != 10 else 100
            search.aggs['range'].bucket(
                'title', 'terms', field='title', size=max_title)

        if 'tag' in args.metrics:
            max_tags = args.top if args.top != 10 else 50
            search.aggs['range'].bucket(
                'tags', 'terms', field='tags', size=max_tags)

        if 'close_reason' in args.metrics:
            max_reasons = args.top if args.top != 10 else 10
            search.aggs['range'].bucket(
                'close_reason', 'terms', field='close_reason.title.keyword', size=max_reasons)

        if 'status' in args.metrics:
            max_status = args.top if args.top != 10 else 5
            search.aggs['range'].bucket(
                'status', 'terms', field='status.name.keyword', size=max_status)

        if 'owner' in args.metrics:
            max_status = args.top if args.top != 10 else 5
            search.aggs['range'].bucket(
                'owner', 'terms', field='owner.username.keyword', size=max_status)

        if 'severity' in args.metrics:
            max_severity = args.top if args.top != 10 else 10
            search.aggs['range'].bucket(
                'severity', 'terms', field='severity', size=max_severity)

        if 'organization' in args.metrics:
            max_organizations = args.top if args.top != 10 else 10
            search.aggs['range'].bucket(
                'organization', 'terms', field='organization', size=max_organizations)

        if 'escalated' in args.metrics:
            search.aggs['range'].bucket(
                'escalated', 'terms', field='escalated', size=2)

        search = search[0:0]

        cases = search.execute()

        if 'cases_over_time' in args.metrics:
            cases_over_time = Case.search()

            cases_over_time = cases_over_time[0:0]

            cases_over_time.aggs.bucket('range', 'filter', range={'created_at': {
                'gte': args.start,
                'lte': args.end
            }})

            cases_over_time.aggs['range'].bucket(
                'cases_per_day', 'date_histogram', field='created_at', format='yyyy-MM-dd', calendar_interval=args.interval, min_doc_count=0)

            cases_over_time = cases_over_time.execute()

        metrics = {}

        if 'title' in args.metrics:
            metrics['title'] = {v['key']: v['doc_count']
                                for v in cases.aggs.range.title.buckets}

        if 'tag' in args.metrics:
            metrics['tags'] = {v['key']: v['doc_count']
                               for v in cases.aggs.range.tags.buckets}

        if 'close_reason' in args.metrics:
            metrics['close reason'] = {v['key']: v['doc_count']
                                       for v in cases.aggs.range.close_reason.buckets}

        if 'status' in args.metrics:
            metrics['status'] = {v['key']: v['doc_count']
                                 for v in cases.aggs.range.status.buckets}

        if 'owner' in args.metrics:
            metrics['owner'] = {v['key']: v['doc_count']
                                for v in cases.aggs.range.owner.buckets}

        if 'severity' in args.metrics:
            metrics['severity'] = {v['key']: v['doc_count']
                                   for v in cases.aggs.range.severity.buckets}

        if 'organization' in args.metrics:
            metrics['organization'] = {v['key']: v['doc_count']
                                       for v in cases.aggs.range.organization.buckets}

        if 'cases_over_time' in args.metrics:
            metrics['cases_over_time'] = {v['key_as_string']: v['doc_count']
                                          for v in cases_over_time.aggs.range.cases_per_day.buckets}

        if 'escalated' in args.metrics:
            metrics['escalated'] = {v['key']: v['doc_count']
                                    for v in cases.aggs.range.escalated.buckets}

        return metrics
