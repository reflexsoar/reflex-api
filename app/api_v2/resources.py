import base64
import math
import datetime
import itertools
import os
from queue import Queue
import threading
import uuid
import json
import hashlib
from zipfile import ZipFile
from flask import request, current_app, abort, make_response, send_from_directory, send_file, Blueprint, render_template
from flask_restx import Api, Resource, Namespace, fields, Model, inputs as xinputs, marshal
from werkzeug.datastructures import FileStorage
from werkzeug.utils import secure_filename
from .schemas import *
from .model import (
    Event,
    EventRule,
    Observable,
    Observable,
    User,
    Role,
    Settings,
    Credential,
    Input,
    Agent,
    ThreatList,
    ExpiredToken,
    DataType,
    CaseComment,
    CaseHistory,
    CaseTemplate,
    Case,
    CaseStatus,
    CloseReason,
    CaseTask,
    Tag,
    AgentGroup,
    PluginConfig,
    Plugin,
    EventLog,
    A
)

from .utils import ip_approved, token_required, user_has, generate_token, log_event

# Instantiate a new API object
api_v2 = Blueprint("api2", __name__, url_prefix="/api/v2.0")
api2 = Api(api_v2)

# All the API namespaces
ns_user_v2 = api2.namespace(
    'User', description='User operations', path='/user')
ns_role_v2 = api2.namespace(
    'Role', description='Role operations', path='/role')
ns_auth_v2 = api2.namespace(
    'Auth', description='Authentication operations', path='/auth')
ns_event_v2 = api2.namespace(
    'Event', description='Event operations', path='/event')
ns_settings_v2 = api2.namespace(
    'Settings', description='Settings operations', path='/settings')
ns_credential_v2 = api2.namespace(
    'Credential', description='Credential operations', path='/credential')
ns_input_v2 = api2.namespace(
    'Input', description='Input operations', path='/input')
ns_agent_v2 = api2.namespace(
    'Agent', description='Agent operations', path='/agent')
ns_list_v2 = api2.namespace(
    'List', description='Lists API endpoints for managing indicator lists, lists may be string values or regular expressions', path='/list', validate=True)
ns_event_rule_v2 = api2.namespace(
    'EventRule', description='Event Rules control what happens to an event on ingest', path='/event_rule')
ns_agent_group_v2 = api2.namespace(
    'AgentGroup', description='Agent Group operations', path='/agent_group')
ns_data_type_v2 = api2.namespace(
    'DataType', description='DataType operations', path='/data_type')
ns_case_v2 = api2.namespace(
    'Case', description='Case operations', path='/case')
ns_case_status_v2 = api2.namespace(
    'CaseStatus', description='Case Status operations', path='/case_status')
ns_case_comment_v2 = api2.namespace(
    'CaseComment', description='Case Comments', path='/case_comment')
ns_case_task_v2 = api2.namespace(
    'CaseTask', description='Case Tasks', path='/case_task')
ns_case_history_v2 = api2.namespace(
    'CaseHistory', description='Case history operations', path='/case_history')
ns_case_template_v2 = api2.namespace(
    'CaseTemplate', description='Case Template operations', path='/case_template')
ns_close_reason_v2 = api2.namespace(
    'CloseReason', description='Closure reason are used when closing a case and can be customized', path='/close_reason')
ns_tag_v2 = api2.namespace('Tag', description='Tag operations', path='/tag')
ns_dashboard_v2 = api2.namespace('Dashboard', description='API endpoints that drive dashboard display', path='/dashboard')
ns_plugins_v2 = api2.namespace('Plugin', description='Plugin operations', path='/plugin')
ns_audit_log_v2 = api2.namespace('AuditLog', description='Reflex audit logs', path='/audit_log')

# Register all the schemas from flask-restx
for model in schema_models:
    api2.models[model.name] = model


# Generic parsers
pager_parser = api2.parser()
pager_parser.add_argument('page_size', location='args',
                          required=False, type=int, default=25)
pager_parser.add_argument('page', location='args',
                          required=False, type=int, default=1)

upload_parser = api2.parser()
upload_parser.add_argument('files', location='files',
                           type=FileStorage, required=True, action="append")



def save_tags(tags):
    '''
    Adds tags to a reference index that the UI uses for 
    suggesting reasonable tags to the user
    '''

    for tag in tags:
        _tag = Tag.get_by_name(name=tag)
        if not _tag:
            tag = Tag(name=tag)
            tag.save()


@ns_auth_v2.route("/login")
class Login(Resource):

    @api2.expect(mod_auth)
    @api2.response(200, 'Success', mod_auth_success_token)
    @api2.response(401, 'Incorrect username or password')
    def post(self):
        '''
        Log a user in to the platform and provide them with an access_token a refresh_token
        '''

        # Find the user based on their username, if their account is locked don't return a user
        # object to prevent processing any more failed logons
        user = User.get_by_username(api2.payload['username'])
        if not user:
            ns_auth_v2.abort(401, 'Incorrect username or password')

        if user.check_password(api2.payload['password']):

            # Generate an access token
            _access_token = user.create_access_token()

            # Generate a refresh tokenn
            _refresh_token = user.create_refresh_token(
                request.user_agent.string.encode('utf-8'))

            # Update the users failed_logons and last_logon entries
            user.update(failed_logons=0, last_logon=datetime.datetime.utcnow())

            
            log_event(event_type="Authentication", source_user=user.username, source_ip=request.remote_addr, message="Successful Authentication.", status="Success")

            return {'access_token': _access_token, 'refresh_token': _refresh_token, 'user': user.uuid}, 200

        if user.failed_logons == None:
            user.update(failed_logons=0)

        if user.failed_logons >= Settings.load().logon_password_attempts:
            user.update(locked=True)
            log_event(event_type="Authentication", source_user=user.username, source_ip=request.remote_addr, message="Account Locked.", status="Failed")
        else:
            user.update(failed_logons=user.failed_logons+1)
            log_event(event_type="Authentication", source_user=user.username, source_ip=request.remote_addr, message="Bad username or password.", status="Failed")

        ns_auth_v2.abort(401, 'Incorrect username or password')


@ns_auth_v2.route('/logout')
class Logout(Resource):

    @api2.doc(security="Bearer")
    @api2.response(200, 'Successfully logged out.')
    @api2.response(401, 'Not logged in.')
    @token_required
    def get(self, current_user):
        '''
        Logs a user out of the platform and invalidates their access_token
        so that they can't use it again.  The token is stored in a blocked token
        index for lookup when calling the API
        '''
        try:
            auth_header = request.headers.get('Authorization')
            access_token = auth_header.split(' ')[1]
            b_token = ExpiredToken(token=access_token)
            b_token.save()
            return {'message': 'Successfully logged out.'}, 200
        except:
            return {'message': 'Not logged in.'}, 401

        ns_auth_v2.abort(401, 'Not logged in.')


@ns_user_v2.route("/me")
class UserInfo(Resource):

    @api2.doc(security="Bearer")
    @api2.marshal_with(mod_user_self)
    @token_required
    def get(self, current_user):
        ''' Returns information about the currently logged in user '''
        role = Role.get_by_member(current_user.uuid)
        current_user.role = role
        return current_user


@ns_user_v2.route('/generate_api_key')
class UserGenerateApiKey(Resource):

    @api2.doc(security="Bearer")
    @api2.marshal_with(mod_api_key)
    @token_required
    @user_has('use_api')
    def get(self, current_user):
        ''' Returns a new API key for the user making the request '''
        return current_user.generate_api_key()


@ns_user_v2.route("/<uuid>/unlock")
class UnlockUser(Resource):

    @api2.doc(security="Bearer")
    @api2.marshal_with(mod_user_full)
    @token_required
    @user_has('unlock_user')
    def put(self, uuid, current_user):
        ''' Unlocks a user and resets their failed logons back to 0 '''
        user = User.get_by_uuid(uuid)
        if user:
            user.unlock()
            log_event(event_type="User Management", message=f"User {user.username} was unlocked.", source_user=current_user.username, status="Success")
            return user
        else:
            ns_user_v2.abort(404, 'User not found.')


user_parser = api2.parser()
user_parser.add_argument('username', location='args', required=False)
user_parser.add_argument('deleted', type=xinputs.boolean, location='args',
                         required=False, default=False)


@ns_user_v2.route("")
class UserList(Resource):

    @api2.doc(security="Bearer")
    @api2.marshal_with(mod_user_full, as_list=True)
    @api2.expect(user_parser)
    @token_required
    @user_has('view_users')
    def get(self, current_user):
        ''' Returns a list of users '''

        args = user_parser.parse_args()

        if args['username']:
            user = User.get_by_username(args['username'])
            if user:
                return [user]
            else:
                return []
        else:
            if args['deleted']:
                s = User.search()
            else:
                s = User.search().query('match', deleted=False)

            s = s[0:s.count()]
            response = s.execute()
            [user.load_role() for user in response]
            return [user for user in response]

    @api2.doc(security="Bearer")
    @api2.expect(mod_user_create)
    @api2.marshal_with(mod_user_create_success)
    @api2.response('409', 'User already exists.')
    @api2.response('200', "Successfully created the user.")
    @token_required
    @user_has('add_user')
    def post(self, current_user):
        ''' Creates a new user '''

        # Check to see if the user already exists
        user = User.get_by_email(api2.payload['email'])
        if user:
            ns_user_v2.abort(409, "User with this e-mail already exists.")
        else:
            user_role = api2.payload.pop('role_uuid')

            user_password = api2.payload.pop('password')
            user = User(**api2.payload)
            user.set_password(user_password)
            user.deleted = False
            user.save()

            role = Role.get_by_uuid(uuid=user_role)
            role.add_user_to_role(user.uuid)

            user.role = role

            return {'message': 'Successfully created the user.', 'user': user}


@ns_user_v2.route("/<uuid>")
class UserDetails(Resource):

    @api2.doc(security="Bearer")
    @api2.marshal_with(mod_user_full)
    @token_required
    @user_has('view_users')
    def get(self, uuid, current_user):
        ''' Returns information about a user '''
        user = User.get_by_uuid(uuid)
        if user:
            return user
        else:
            ns_user_v2.abort(404, 'User not found.')

    @api2.doc(security="Bearer")
    @api2.expect(mod_user_create)
    @api2.marshal_with(mod_user_full)
    @token_required
    @user_has('update_user')
    def put(self, uuid, current_user):
        ''' Updates information for a user '''

        user = User.get_by_uuid(uuid)
        if user:

            if 'username' in api2.payload:
                target_user = User.get_by_username(api2.payload['username'])
                if target_user:
                    if target_user.uuid == uuid:
                        del api2.payload['username']
                    else:
                        ns_user_v2.abort(409, 'Username already taken.')

            if 'email' in api2.payload:
                target_user = User.get_by_email(api2.payload['email'])
                if target_user:
                    if target_user.uuid == uuid:
                        del api2.payload['email']
                    else:
                        ns_user_v2.abort(409, 'Email already taken.')

            if 'password' in api2.payload and not current_user.has_right('reset_user_password'):
                api2.payload.pop('password')
            if 'password' in api2.payload and current_user.has_right('reset_user_password'):
                pw = api2.payload.pop('password')
                user.set_password(pw)
                user.save()

            # Update the users role if a role update is triggered
            if 'role_uuid' in api2.payload and api2.payload['role_uuid'] is not None:

                # Remove them from their old role
                old_role = Role.get_by_member(uuid=user.uuid)
                new_role = Role.get_by_uuid(uuid=api2.payload['role_uuid'])
                if old_role != new_role:
                    new_role.add_user_to_role(user_id=user.uuid)                    
                    old_role.remove_user_from_role(user_id=user.uuid)
                    return user

            if len(api2.payload) > 0:
                user.update(**api2.payload)

            return user
        else:
            ns_user_v2.abort(404, 'User not found.')

    @api2.doc(security="Bearer")
    @token_required
    @user_has('delete_user')
    def delete(self, uuid, current_user):
        ''' 
        Deletes a user 

        Users are soft deleted, meaning they never get removed from the database.  Instead,
        their deleted attribute is set and they do not show up in the UI.  This is 
        used to preserve database relationships like ownership, comment history.
        Deleted users can not be restored at this time.        
        '''
        user = User.get_by_uuid(uuid)
        if user:
            if current_user.uuid == user.uuid:
                ns_user_v2.abort(403, 'User can not delete themself.')
            else:
                user.deleted = True
                user.locked = True
                user.save()
                return {'message': 'User successfully deleted.'}
        else:
            ns_user_v2.abort(404, 'User not found.')


@ns_role_v2.route("")
class RoleList(Resource):

    @api2.doc(security="Bearer")
    @api2.marshal_with(mod_role_list, as_list=True)
    @token_required
    @user_has('view_roles')
    def get(self, current_user):
        ''' Returns a list of Roles '''
        roles = Role.search().execute()
        if roles:
            return [r for r in roles]
        else:
            return []

    @api2.doc(security="Bearer")
    @api2.expect(mod_role_create)
    @api2.response('409', 'Role already exists.')
    @api2.response('200', "Successfully created the role.")
    @token_required
    @user_has('add_role')
    def post(self, current_user):
        ''' Creates a new Role '''
        role = Role.get_by_name(name=api2.payload['name'])
        if not role:
            role = Role(**api2.payload)
            role.save()
            return {'message': 'Successfully created the role.', 'uuid': str(role.uuid)}
        else:
            ns_role_v2.abort(409, "Role already exists.")


@ns_role_v2.route("/<uuid>")
class RoleDetails(Resource):

    @api2.doc(security="Bearer")
    @api2.expect(mod_role_create)
    @api2.marshal_with(mod_role_list)
    @token_required
    @user_has('update_role')
    def put(self, uuid, current_user):
        ''' Updates an Role '''
        role = Role.get_by_uuid(uuid=uuid)
        if role:
            exists = Role.get_by_name(name=api2.payload['name'])
            if 'name' in api2.payload and exists and exists.uuid != role.uuid:
                ns_role_v2.abort(409, 'Role with that name already exists.')
            else:
                role.update(**api2.payload)
                return role
        else:
            ns_role_v2.abort(404, 'Role not found.')

    @api2.doc(security="Bearer")
    @token_required
    @user_has('delete_role')
    def delete(self, uuid, current_user):
        ''' Removes a Role '''
        role = Role.get_by_uuid(uuid=uuid)
        if role:
            if role.members and len(role.members) > 0:
                ns_role_v2.abort(
                    400, 'Can not delete a role with assigned users.  Assign the users to a new role first.')
            else:
                role.delete()
                return {'message': 'Role successfully delete.'}
        else:
            ns_role_v2.abort(404, 'Role not found.')

    @api2.doc(security="Bearer")
    @api2.marshal_with(mod_role_list)
    @token_required
    @user_has('view_roles')
    def get(self, uuid, current_user):
        ''' Gets the details of a Role '''
        role = Role.get_by_uuid(uuid=uuid)
        if role:
            return role
        else:
            ns_role_v2.abort(404, 'Role not found.')


@ns_data_type_v2.route("")
class DataTypeList(Resource):

    @api2.doc(security="Bearer")
    @api2.marshal_with(mod_data_type_list)
    @token_required
    def get(self, current_user):
        ''' Gets a list of all the data types '''
        data_types = DataType.search()
        data_types = data_types[0:data_types.count()]
        data_types = data_types.execute()
        if data_types:
            return [d for d in data_types]
        else:
            return []

    @api2.doc(security="Bearer")
    @api2.expect(mod_data_type_create)
    @api2.response('200', 'Successfully created data type.')
    @token_required
    @user_has('create_data_type')
    def post(self, current_user):
        ''' Creates a new data_type set '''
        data_type = DataType(**api2.payload)
        data_type.save()
        return {'message': 'Successfully created data type.', 'uuid': str(data_type.uuid)}


@ns_data_type_v2.route("/<uuid>")
class DataTypeDetails(Resource):

    @api2.doc(security="Bearer")
    @api2.marshal_with(mod_data_type_list)
    @token_required
    def get(self, uuid, current_user):
        ''' Gets a data type '''
        data_type = DataType.get_by_uuid(uuid=uuid)
        if data_type:
            return data_type
        else:
            ns_data_type_v2.abort(404, 'Data type not found.')

    @api2.doc(security="Bearer")
    @api2.expect(mod_data_type_create)
    @api2.marshal_with(mod_data_type_list)
    @token_required
    @user_has('update_data_type')
    def put(self, uuid, current_user):
        ''' Updates the data type '''
        data_type = DataType.get_by_uuid(uuid=uuid)
        if data_type:
            data_type.update(**api2.payload)
            return data_type
        else:
            ns_data_type_v2.abort(404, 'Data type not found.')


event_list_parser = api2.parser()
event_list_parser.add_argument('status', location='args', default=[
], type=str, action='split', required=False)
event_list_parser.add_argument('tags', location='args', default=[
], type=str, action='split', required=False)
event_list_parser.add_argument('observables', location='args', default=[
], type=str, action='split', required=False)
event_list_parser.add_argument('signature', location='args', required=False)
event_list_parser.add_argument(
    'severity', action='split', location='args', required=False)
event_list_parser.add_argument(
    'grouped', type=xinputs.boolean, location='args', required=False)
event_list_parser.add_argument(
    'case_uuid', type=str, location='args', required=False)
event_list_parser.add_argument('search', type=str, action='split', default=[
], location='args', required=False)
event_list_parser.add_argument(
    'title', type=str, location='args', action='split', required=False)
event_list_parser.add_argument(
    'page', type=int, location='args', default=1, required=False)
event_list_parser.add_argument(
    'page_size', type=int, location='args', default=10, required=False)
event_list_parser.add_argument(
    'sort_by', type=str, location='args', default='created_at', required=False)
event_list_parser.add_argument(
    'sort_desc', type=xinputs.boolean, location='args', default=True, required=False)


@ns_event_v2.route("")
class EventList(Resource):

    @api2.doc(security="Bearer")
    @api2.marshal_with(mod_event_paged_list)
    @api2.expect(event_list_parser)
    @token_required
    @user_has('view_events')
    def get(self, current_user):
        ''' Returns a list of events '''

        args = event_list_parser.parse_args()

        if args['page'] == 1:
            start = 0
            end = args['page']*args['page_size']
            args['page'] = 0
        else:
            start = ((args['page']-1)*args['page_size'])
            end = args['page_size']*args['page']

        events = []
        total_events = 0
        event_uuids = [] # Used for selecting events based on their UUID

        search_filter = {}
        for arg in args:
            if arg in ['status','severity','title','observables','tags']:
                if args[arg] != '' and args[arg] is not None:
                    if isinstance(args[arg], list):
                        if arg == 'observables':
                            if len(args[arg]) > 0:
                                observables = Observable.get_by_value(args[arg])
                                event_uuids=list(itertools.chain.from_iterable([o.events for o in observables if o.events is not None]))
                        elif arg == 'status':
                            if len(args[arg]) > 0 and '' not in args[arg]:
                                search_filter['status.name__keyword'] = {"value": args[arg], "type":"terms"}
                        elif arg == 'severity':
                            if len(args[arg]) > 0 and '' not in args[arg]:
                                search_filter['severity'] = {"value": args[arg], "type":"terms"}
                        elif arg == 'tags':
                            if len(args[arg]) > 0 and '' not in args[arg]:
                                search_filter['tags'] = {"value": args[arg], "type":"terms"}
                        elif arg == 'title':
                            if len(args[arg]) > 0 and '' not in args[arg]:
                                search_filter['title'] = {"value": args[arg], "type":"terms"}
                        else:
                            if len(args[arg]) > 0 and '' not in args[arg]:
                                search_filter[arg] = args[arg]
                    else:
                        search_filter[arg] = args[arg]                   

        sort_by = { args['sort_by']: {'order': 'desc'} }

        s = Event.search()
        s = s.sort(sort_by)

        if len(event_uuids) > 0:
            s = s.filter('terms', **{'uuid': event_uuids})

        if 'signature' in args and args['signature']:
            s = s.filter('term', **{'signature': args['signature']})
            total_events = s.count()

        if 'case_uuid' in args and args['case_uuid']:
            s = s.filter('match', **{'case': args['case_uuid']})
            total_events = s.count()

        if len(search_filter) > 0:
            for a in search_filter:
                s = s.filter(search_filter[a]["type"], **{a: search_filter[a]["value"]})
            total_events = s.count()
            
            events = [e for e in s[start:end]]
        else:
            total_events = s.count()
            events = [e for e in s[start:end]]

        if args['page_size'] < total_events:
            pages = math.ceil(float(total_events / args['page_size']))
        else:
            pages = 0

        """ Calculate related event counts
            I couldn't figure out a better way to do this with elasticsearch DSL
            this may become expensive at some point in the future
            - BC
        """
        for event in events:
            related_events_count = len([e for e in events if e.signature == event.signature])
            if related_events_count > 1:
                event.related_events_count = related_events_count
            else:
                event.related_events_count = 0

        # Keep only one copy of an event where signatures are the same
        # Keep the most recent
        if 'signature' in args and not args['signature']:
            events_dedupe = []
            for event in events:
                x = list(filter(lambda e: e.signature == event.signature, events))[0]
                if x not in events_dedupe:
                    events_dedupe += [x]

            events = events_dedupe

        event_uuids = [e.uuid for e in events]
        observables = Observable.get_by_event_uuid(uuid=event_uuids)
        event_to_observables = {}
        for event in events:
            event_to_observables[event.uuid] = [o.to_dict() for o in observables if event.uuid in o.events]

        response = {
            'events': events,
            'observables': json.loads(json.dumps(event_to_observables, default=str)),
            'pagination': {
                'total_results': total_events,
                'pages': pages,
                'page': args['page'],
                'page_size': args['page_size']
            }
        }

        return response

    @api2.expect(mod_event_create)
    def post(self):
        ''' Creates a new event '''

        observables = []
        added_observables = []

        # If the event has an observables pop them off the request payload
        # so that the Event can be generated using the remaining dictionary values
        if 'observables' in api2.payload:
            observables = api2.payload.pop('observables')

        event = Event.get_by_reference(api2.payload['reference'])

        if not event:
            event = Event(**api2.payload)
            event.save()

            if observables:
                added_observables = event.add_observable(observables)

            event.hash_event(observables=added_observables)

            # Check if there are any event rules for the alarm with this title
            event_rules = EventRule.get_by_title(title=event.title)
            if event_rules:

                matched = None            
                for event_rule in event_rules:

                    # If the event matches the event rules criteria perform the rule actions
                    if event.check_event_rule_signature(event_rule.rule_signature, observables=added_observables):
                        # TODO: Add logging for when this fails
                        matched = event_rule.process(event)

                if not matched:
                    event.set_new()
            else:
                event.set_new()

            return {'message': 'Successfully created the event.'}
        else:
            return {'message': 'Event already exists'}, 409


@ns_event_v2.route('/_bulk')
class CreateBulkEvents(Resource):

    # TODO: This needs some serious love but it should work let's test it

    @api2.doc(security="Bearer")
    @api2.expect(mod_event_create_bulk)
    @token_required
    @user_has('add_event')
    def post(self, current_user):
        event_queue = Queue()

        workers = []

        request_id = str(uuid.uuid4())
        
        def process_event(queue, request_id):
            while not queue.empty():
                raw_event = queue.get()
                event = Event.get_by_reference(raw_event['reference'])

                if not event:

                    observables = []
                    added_observables = []

                    # Start clocking event creation
                    start_event_process_dt = datetime.datetime.utcnow().timestamp()

                    if 'observables' in raw_event:
                        observables = raw_event.pop('observables')

                    event = Event(**raw_event)
                    event.save()

                    if observables:
                        added_observables = event.add_observable(observables)

                    event.hash_event(observables=added_observables)

                    # Check if there are any event rules for the alarm with this title
                    event_rules = EventRule.get_by_title(title=event.title)
                    if event_rules:

                        matched = None                    
                        for event_rule in event_rules:

                            # If the event matches the event rules criteria perform the rule actions
                            if event.check_event_rule_signature(event_rule.rule_signature, observables=added_observables):
                                # TODO: Add logging for when this fails
                                matched = event_rule.process(event)

                        if not matched:
                            event.set_new()
                    else:
                        event.set_new()

                    end_event_process_dt = datetime.datetime.utcnow().timestamp()
                    event_process_time = end_event_process_dt - start_event_process_dt
                    log_event(event_type='Bulk Event Insert', request_id=request_id, event_reference=event.reference, time_taken=event_process_time, status="Success", message="Event Inserted.", event_id=event.uuid)
                else:
                    log_event(event_type='Bulk Event Insert', request_id=request_id, event_reference=event.reference, time_taken=0, status="Failed", message="Event Already Exists.")

        
        start_bulk_process_dt = datetime.datetime.utcnow().timestamp()
        if 'events' in api2.payload and len(api2.payload['events']) > 0:
            [event_queue.put(e) for e in api2.payload['events']]

        for i in range(0,current_app.config['EVENT_PROCESSING_THREADS']):
            p = threading.Thread(target=process_event, daemon=True, args=(event_queue,request_id))
            workers.append(p)
        [t.start() for t in workers]

        end_bulk_process_dt = datetime.datetime.utcnow().timestamp()
        total_process_time = end_bulk_process_dt - start_bulk_process_dt

        log_event(event_type="Bulk Event Insert", request_id=request_id, time_taken=total_process_time, status="Success", message="Bulk request finished.")

        return {"request_id": request_id, "response_time": total_process_time}


@ns_event_v2.route('/_bulk_old')
class CreateBulkEventsOld(Resource):

    @api2.doc(security="Bearer")
    @api2.expect(mod_event_create_bulk)
    @api2.response('200', 'Sucessfully created events.')
    @api2.response('207', 'Multi-Status')    
    @token_required
    @user_has('add_event')
    def post(self, current_user):
        '''
        Creates Events in bulk 
        '''
        response = {
            'results': [],
            'success': True
        }

        # Start clocking the bulk process
        start_bulk_process_dt = datetime.datetime.utcnow().timestamp()

        events = api2.payload['events']
        for item in events:

            event = Event.get_by_reference(item['reference'])

            if not event:

                observables = []
                added_observables = []

                # Start clocking event creation
                start_event_process_dt = datetime.datetime.utcnow().timestamp()

                if 'observables' in item:
                    observables = item.pop('observables')

                event = Event(**item)
                event.save()

                if observables:
                    added_observables = event.add_observable(observables)

                event.hash_event(observables=added_observables)

                # Check if there are any event rules for the alarm with this title
                event_rules = EventRule.get_by_title(title=event.title)
                if event_rules:

                    matched = None                    
                    for event_rule in event_rules:

                        # If the event matches the event rules criteria perform the rule actions
                        if event.check_event_rule_signature(event_rule.rule_signature, observables=added_observables):
                            # TODO: Add logging for when this fails
                            matched = event_rule.process(event)

                    if not matched:
                        event.set_new()
                else:
                    event.set_new()

                # Stop clocking the event and compute the time the event took to create
                end_event_process_dt = datetime.datetime.utcnow().timestamp()
                event_process_time = end_event_process_dt - start_event_process_dt

                response['results'].append(
                    {'reference': item['reference'], 'status': 200, 'message': 'Event successfully created.', 'process_time': event_process_time})
            else:
                response['results'].append(
                    {'reference': item['reference'], 'status': 409, 'message': 'Event already exists.', 'process_time': '0'})
                response['success'] = False

        # Stop clocking the bulk process and compute the time taken
        end_bulk_process_dt = datetime.datetime.utcnow().timestamp()
        total_process_time = end_bulk_process_dt - start_bulk_process_dt
        response['process_time'] = total_process_time

        return response, 207


@ns_event_v2.route("/bulk_dismiss")
class EventBulkUpdate(Resource):

    @api2.doc(security="Bearer")
    @api2.expect(mod_event_bulk_dismiss)
    @api2.marshal_with(mod_event_details, as_list=True)
    @token_required
    @user_has('update_event')
    def put(self, current_user):
        ''' Dismiss multiple events at the same time '''

        if 'dismiss_reason_uuid' in api2.payload:
            reason = CloseReason.get_by_uuid(uuid=api2.payload['dismiss_reason_uuid'])
        else:
            ns_event_v2.abort(400, 'A dismiss reason is required.')

        if 'events' in api2.payload:

            comment = api2.payload['dismiss_comment'] if api2.payload['dismiss_comment'] != "" else None

            events = Event.get_by_uuid(uuid=api2.payload['events'])
            [event.set_dismissed(reason=reason, comment=comment) for event in events]

        return []


@ns_event_v2.route("/<uuid>")
class EventDetails(Resource):

    @api2.doc(security="Bearer")
    @api2.marshal_with(mod_event_details)
    @token_required
    @user_has('view_events')
    def get(self, uuid, current_user):

        event = Event.get_by_uuid(uuid)
        if event:
            return event
        else:
            ns_event_v2.abort(404, 'Event not found.')

    @api2.doc(security="Bearer")
    @token_required
    @user_has('update_event')
    def put(self, uuid, current_user):
        '''Updates an event

        Parameters:
            uuid (str): The unique identifier of the Event
            current_user (User): The current user making the API request
        '''

        if 'dismiss_reason_uuid' in api2.payload:
            reason = CloseReason.get_by_uuid(uuid=api2.payload['dismiss_reason_uuid'])
            event = Event.get_by_uuid(uuid=uuid)

            comment = None
            if 'dismiss_comment' in api2.payload and api2.payload['dismiss_comment'] != '':
                comment = api2.payload['dismiss_comment']
            
            event.set_dismissed(reason, comment=comment)
            return {'message':'Successfully dismissed event'}, 200
        else:
            return {}

"""
@ns_event_v2.route("/<uuid>/update_case")
class EventUpdateCase(Resource):

    @api2.doc(security="Bearer")
    @api2.marshal_with(mod_event_update_case)
    @api2.response('200', 'Success')
    @token_required
    @user_has('update_event')
    def put(self, uuid, current_user):

        if 'action' in api2.payload:
            action = api2.payload.pop('action')

            if action in ['remove','transfer']:

                event = Event.get_by_uuid()

                if action == 'remove':
                    
                    event.remove_from_case()

                if action == 'transfer':
                    if 'target_case_uuid' in api2.payload:
                        event.set_case()
                    else:
                        ns_event_v2(400, 'Missing target case details.')
            
                print('a')
            else:
                ns_event_v2.abort(400, 'Missing or invalid action.')
        else:
            ns_event_v2.abort(400, 'Missing or invalid action.')
"""

@ns_event_v2.route("/<uuid>/new_related_events")
class EventNewRelatedEvents(Resource):

    @api2.doc(security="Bearer")
    @api2.marshal_with(mod_related_events)
    @api2.response('200', 'Success')
    @api2.response('404', 'Event not found')
    @token_required
    @user_has('view_events')
    def get(self, uuid, current_user):
        ''' Returns the UUIDs of all related events that are Open '''
        event = Event.get_by_uuid(uuid=uuid)
        events = Event.get_by_signature(signature=event.signature)
        related_events = [e.uuid for e in events if e.status.name == 'New']
        return {"events": related_events}

@ns_event_rule_v2.route("")
class EventRuleList(Resource):

    @api2.doc(security="Bearer")
    @api2.marshal_with(mod_event_rule_list)
    @token_required
    @user_has('view_event_rules')
    def get(self, current_user):
        ''' Gets a list of all the event rules '''
        event_rules = EventRule.search().execute()
        if event_rules:
            return [r for r in event_rules]
        else:
            return []

    @api2.doc(security="Bearer")
    @api2.expect(mod_event_rule_create)
    @api2.response('200', 'Successfully created event rule.')
    @token_required
    @user_has('create_event_rule')
    def post(self, current_user):
        ''' Creates a new event_rule set '''

        if 'expire_days' in api2.payload and not isinstance(api2.payload['expire_days'], int):
            ns_event_rule_v2(400, 'expire_days should be an integer.')

        # Computer when the rule should expire
        if 'expire' in api2.payload and api2.payload['expire']:
            if 'expire_days' in api2.payload:
                expire_days = api2.payload.pop('expire_days')

                expire_at = datetime.datetime.utcnow() + datetime.timedelta(days=expire_days)
                api2.payload['expire_at'] = expire_at
            else:
                ns_event_rule_v2.abort(400, 'Missing expire_days field.')

        
        observables = None
        added_observables = []

        if 'observables' in api2.payload:
            observables = api2.payload.pop('observables')

        event_rule = EventRule(**api2.payload)
        event_rule.save()

        if observables:
            added_observables = event_rule.add_observable(observables)

        event_rule.hash_observables(observables=added_observables)
        event_rule.active = True
        event_rule.save()

        return {'message': 'Successfully created event rule.', 'uuid': str(event_rule.uuid)}


@ns_event_rule_v2.route("/<uuid>")
class EventRuleDetails(Resource):

    @api2.doc(security="Bearer")
    @api2.marshal_with(mod_event_rule_list)
    @token_required
    @user_has('view_event_rules')
    def get(self, uuid, current_user):
        ''' Gets a event rule '''
        event_rule = EventRule.get_by_uuid(uuid=uuid)
        if event_rule:
            return event_rule
        else:
            ns_event_rule_v2.abort(404, 'Event rule not found.')

    @api2.doc(security="Bearer")
    @api2.expect(mod_event_rule_create)
    @api2.marshal_with(mod_event_rule_list)
    @token_required
    @user_has('update_event_rule')
    def put(self, uuid, current_user):
        ''' Updates the event rule '''
        event_rule = EventRule.get_by_uuid(uuid=uuid)

        if event_rule:

            if 'observables' in api2.payload:
                event_rule.observables = api2.payload.pop('observables')
                event_rule.hash_observables()

            if len(api2.payload) > 0:
                event_rule.update(**api2.payload)

            return event_rule
        else:
            ns_event_rule_v2.abort(404, 'Event rule not found.')

    @api2.doc(security="Bearer")
    @token_required
    @user_has('delete_event_rule')
    def delete(self, uuid, current_user):
        ''' Removes an event rule '''
        event_rule = EventRule.get_by_uuid(uuid=uuid)
        if event_rule:
            event_rule.delete()
            return {'message': 'Sucessfully deleted the event rule.'}


case_status_parser = api2.parser()
case_status_parser.add_argument(
    'name', type=str, location='args', required=False)

@ns_case_status_v2.route("")
class CaseStatusList(Resource):

    @api2.doc(security="Bearer")
    @api2.expect(case_status_parser)
    @api2.marshal_with(mod_case_status_list, as_list=True)
    @token_required
    def get(self, current_user):
        ''' Returns a list of case_statuss '''

        args = case_status_parser.parse_args()

        
        statuses = CaseStatus.search()

        if args.name is not None:
            statuses = statuses.filter('term', name=args.name)

        statuses = statuses.execute()
        if statuses:
            return [s for s in statuses]
        else:
            return []

    @api2.doc(security="Bearer")
    @api2.expect(mod_case_status_create)
    @api2.response('409', 'Case Status already exists.')
    @api2.response('200', 'Successfully create the CaseStatus.')
    @token_required
    @user_has('create_case_status')
    def post(self, current_user):
        ''' Creates a new Case Status '''
        case_status = CaseStatus.get_by_name(name=api2.payload['name'])

        if not case_status:
            case_status = CaseStatus(**api2.payload)
            case_status.save()
        else:
            ns_case_status_v2.abort(409, 'Case Status already exists.')
        return {'message': 'Successfully created the Case Status.'}


@ns_case_status_v2.route("/<uuid>")
class CaseStatusDetails(Resource):

    @api2.doc(security="Bearer")
    @api2.marshal_with(mod_case_status_list)
    @token_required
    def get(self, uuid, current_user):
        ''' Returns information about an CaseStatus '''
        case_status = CaseStatus.get_by_uuid(uuid=uuid)
        if case_status:
            return case_status
        else:
            ns_case_status_v2.abort(404, 'Case Status not found.')

    @api2.doc(security="Bearer")
    @api2.expect(mod_case_status_create)
    @api2.marshal_with(mod_case_status_list)
    @token_required
    @user_has('update_case_status')
    def put(self, uuid, current_user):
        ''' Updates information for an Case Status '''
        case_status = CaseStatus.get_by_uuid(uuid=uuid)
        if case_status:
            exists = CaseStatus.get_by_name(name=api2.payload['name'])
            if 'name' in api2.payload and exists and exists.uuid != case_status.uuid:
                ns_case_status_v2.abort(
                    409, 'Case Status name already exists.')
            else:
                case_status.update(**api2.payload)
                return case_status
        else:
            ns_case_status_v2.abort(404, 'Case Status not found.')

    @api2.doc(security="Bearer")
    @token_required
    @user_has('delete_case_status')
    def delete(self, uuid, current_user):
        ''' Deletes an CaseStatus '''
        case_status = CaseStatus.get_by_uuid(uuid=uuid)
        if case_status:
            case_status.delete()
            return {'message': 'Sucessfully deleted Case Status.'}

close_reason_parser = api2.parser()
close_reason_parser.add_argument(
    'title', type=str, location='args', required=False)

@ns_close_reason_v2.route("")
class CloseReasonList(Resource):

    @api2.doc(security="Bearer")
    @api2.expect(close_reason_parser)
    @api2.marshal_with(mod_close_reason_list, as_list=True)
    @token_required
    def get(self, current_user):
        ''' Returns a list of close_reasons '''

        args = close_reason_parser.parse_args()

        close_reasons = CloseReason.search()
        
        if args.title:
            close_reasons = close_reasons.filter('match', title=args.title)
        
        close_reasons = close_reasons.execute()
        if close_reasons:
            return list(close_reasons)
        else:
            return []

    @api2.doc(security="Bearer")
    @api2.expect(mod_close_reason_create)
    @api2.response('409', 'Close Reason already exists.')
    @api2.response('200', 'Successfully create the CloseReason.')
    @token_required
    @user_has('create_close_reason')
    def post(self, current_user):
        ''' Creates a new Close Reason '''
        close_reason = CloseReason.get_by_name(title=api2.payload['title'])

        if not close_reason:
            close_reason = CloseReason(**api2.payload)
            close_reason.save()
        else:
            ns_close_reason_v2.abort(
                409, 'Close Reason with that name already exists.')
        return {'message': 'Successfully created the Close Reason.'}


@ns_close_reason_v2.route("/<uuid>")
class CloseReasonDetails(Resource):

    @api2.doc(security="Bearer")
    @api2.marshal_with(mod_close_reason_list)
    @token_required
    def get(self, uuid, current_user):
        ''' Returns information about an CloseReason '''
        close_reason = CloseReason.get_by_uuid(uuid=uuid)
        if close_reason:
            return close_reason
        else:
            ns_close_reason_v2.abort(404, 'Close Reason not found.')

    @api2.doc(security="Bearer")
    @api2.expect(mod_close_reason_create)
    @api2.marshal_with(mod_close_reason_list)
    @token_required
    @user_has('update_close_reason')
    def put(self, uuid, current_user):
        ''' Updates information for an Close Reason '''
        close_reason = CloseReason.get_by_uuid(uuid=uuid)
        if close_reason:
            exists = CloseReason.get_by_name(title=api2.payload['title'])
            if 'title' in api2.payload and exists and exists.uuid != close_reason.uuid:
                ns_close_reason_v2.abort(
                    409, 'Close Reason title already exists.')
            else:
                close_reason.update(**api2.payload)
                return close_reason
        else:
            ns_close_reason_v2.abort(404, 'Close Reason not found.')

    @api2.doc(security="Bearer")
    @token_required
    @user_has('delete_close_reason')
    def delete(self, uuid, current_user):
        ''' Deletes an CloseReason '''
        close_reason = CloseReason.get_by_uuid(uuid=uuid)
        if close_reason:
            close_reason.delete()
            return {'message': 'Sucessfully deleted Close Reason.'}


case_parser = pager_parser.copy()
case_parser.add_argument('title', location='args', required=False, type=str)
case_parser.add_argument('status', location='args', required=False, type=str)
case_parser.add_argument('severity', location='args', required=False, action="split", type=str)
case_parser.add_argument('owner', location='args', required=False, action="split", type=str)
case_parser.add_argument('tag', location='args', required=False, action="split", type=str)
case_parser.add_argument('search', location='args', required=False, action="split", type=str)
case_parser.add_argument('my_tasks', location='args', required=False, type=xinputs.boolean)
case_parser.add_argument('my_cases', location='args', required=False, type=xinputs.boolean)
case_parser.add_argument('page', type=int, location='args', default=1, required=False)
case_parser.add_argument('sort_by', type=str, location='args', default='created_at', required=False)
case_parser.add_argument('page_size', type=int, location='args', default=25, required=False)

@ns_case_v2.route("")
class CaseList(Resource):

    @api2.doc(security="Bearer")
    @api2.marshal_with(mod_case_paged_list)
    @api2.expect(case_parser)
    @token_required
    @user_has('view_cases')
    def get(self, current_user):
        ''' Returns a list of case '''

        args = case_parser.parse_args()

        cases = Case.search()

        cases = cases.sort('-created_at')

        # Apply filters
        if 'title' in args and args['title']:
            cases = cases.filter('term', title=args['title'])

        if 'status' in args and args['status']:
            cases = cases.filter('match', status__name=args['status'])

        if 'severity' in args and args['severity']:
            cases = cases.filter('terms', severity=args['severity'])

        # Paginate the cases
        page = args.page - 1
        total_cases = cases.count()
        pages = math.ceil(float(total_cases / args.page_size))

        start = page*args.page_size
        end = args.page*args.page_size
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

    @api2.doc(security="Bearer")
    @api2.expect(mod_case_create)
    @api2.response('409', 'Case already exists.')
    @api2.response('200', "Successfully created the case.")
    @token_required
    @user_has('create_case')
    def post(self, current_user):
        ''' Creates a new case '''

        _tags = []
        event_observables = []
        case_observables = []
        owner_uuid = None
        case_template = None

        settings = Settings.load()

        if 'case_template_uuid' in api2.payload:
            case_template = CaseTemplate.get_by_uuid(
                uuid=api2.payload.pop('case_template_uuid'))

        if 'owner_uuid' in api2.payload:
            owner_uuid = api2.payload.pop('owner_uuid')
        else:
            # Automatically assign the case to the creator if they didn't pick an owner
            if settings.assign_case_on_create:
                owner_uuid = current_user.uuid

        # Set a minimum tlp
        if api2.payload['tlp'] < 1:
            api2.payload['tlp'] = 1

        # Set a maximum tlp
        if api2.payload['tlp'] > 4:
            api2.payload['tlp'] = 4

        # Set a minimum severity
        if api2.payload['severity'] < 1:
            api2.payload['severity'] = 1

        # Set a maximum severity
        if api2.payload['severity'] > 4:
            api2.payload['severity'] = 4

        case = Case(**api2.payload)

        # Set the default status to New
        case.status = CaseStatus.get_by_name(name="New")
        case.set_owner(owner_uuid)

        if 'events' in api2.payload:
            for event in api2.payload['events']:
                e = Event.get_by_uuid(event)
                e.set_open()
                e.set_case(uuid=case.uuid)

                case_observables += Observable.get_by_event_uuid(event)

        # Deduplicate case observables
        case_observables = list(set([Observable(
            tags=o.tags, value=o.value, data_type=o.data_type, ioc=o.ioc, spotted=o.spotted, tlp=o.tlp, case=case.uuid) for o in case_observables]))
        [o.save() for o in case_observables]

        # If the user selected a case template, take the template items
        # and copy them over to the case
        if case_template:

            # Append the default tags
            for tag in case_template.tags:

                # If the tag does not already exist
                if tag not in case.tags:
                    case.tags.append(tag)

            # Append the default tasks
            for task in case_template.tasks:
                case.add_task(title=task.title, description=task.description,
                              order=task.order, from_template=True)

            # Set the default severity
            case.severity = case_template.severity
            case.tlp = case_template.tlp
            case.save()

        case.save()

        # Save the tags so they can be referenced in the future
        save_tags(api2.payload['tags'])

        case.add_history(message='Case created')

        return {'message': 'Successfully created the case.', 'uuid': str(case.uuid)}


@ns_case_v2.route("/<uuid>")
class CaseDetails(Resource):

    @api2.doc(security="Bearer")
    @api2.marshal_with(mod_case_details)
    @api2.response('200', 'Success')
    @api2.response('404', 'Case not found')
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
            ns_case_v2.abort(404, 'Case not found.')

    @api2.doc(security="Bearer")
    @api2.expect(mod_case_create)
    @api2.marshal_with(mod_case_details)
    @token_required
    @user_has('update_case')
    def put(self, uuid, current_user):
        ''' Updates information for a case '''
        case = Case.get_by_uuid(uuid=uuid)
        if case:

            for f in ['severity', 'tlp', 'status_uuid', 'owner', 'description', 'owner_uuid']:
                value = ""
                message = None

                # TODO: handle notifications here, asynchronous of course to not block this processing
                if f in api2.payload:
                    if f == 'status_uuid':
                        status = CaseStatus.get_by_uuid(
                            uuid=api2.payload['status_uuid'])

                        # Remove the closure reason if the new status re-opens the case
                        if not status.closed:
                            api2.payload['close_reason_uuid'] = None

                        value = status.name
                        f = 'status'

                        case.status = status
                        case.save()

                        if status.closed:
                            case.close(api2.payload['close_reason_uuid'])
                        else:
                            case.reopen()

                    elif f == 'severity':

                        if api2.payload[f] > 4:
                            api2.payload[f] = 4

                        if api2.payload[f] < 1:
                            api2.payload[f] = 1

                        value = {1: 'Low', 2: 'Medium', 3: 'High',
                                 4: 'Critical'}[api2.payload[f]]

                    elif f == 'description':
                        message = '**Description** updated'

                    elif f == 'owner':
                        owner = api2.payload.pop(f)
                        if owner:
                            owner = User.get_by_uuid(uuid=owner['uuid'])

                            if owner:
                                message = 'Case assigned to **{}**'.format(
                                    owner.username)
                                api2.payload['owner'] = {
                                    'username': owner.username, 'uuid': owner.uuid}
                            else:
                                message = 'Case unassigned'
                                api2.payload['owner'] = {}
                        else:
                            message = 'Case unassigned'
                            api2.payload['owner'] = None

                    if message:
                        case.add_history(message=message)
                    else:
                        case.add_history(
                            message="**{}** changed to **{}**".format(f.title(), value))

            if 'tags' in api2.payload:
                save_tags(api2.payload['tags'])

            """ TODO: MIGRATE THIS
             if 'case_template_uuid' in api.payload:

                # If the case already has a template, and none of the tasks have been started, remove the
                # old template and its tasks/tags and add the new stuff
                tasks_started = False
                if case.case_template and api.payload['case_template_uuid'] != case.case_template:
                    
                    for task in case.tasks:

                        # If any task is already started, don't apply a new template
                        if task.status != 0 and task.from_template:
                            tasks_started = True
                            break
                        else:
                            if task.from_template:
                                task.delete()

                    # Remove the tags from the case that were assigned by the 
                    # template
                    for tag in case.case_template.tags:
                        if tag in case.tags:
                            case.tags = [tag for tag in case.tags if tag.name not in [t.name for t in case.case_template.tags]]

                    case.case_template_uuid = None
                    case.save()
                    
                # If there was an old template or no template at all
                # apply the new template
                if not tasks_started and api.payload['case_template_uuid'] != case.case_template_uuid:

                    case_template = CaseTemplate.query.filter_by(uuid=api.payload['case_template_uuid'], organization_uuid=current_user.organization.uuid).first()
                    if case_template:

                        # Append the default tags
                        for tag in case_template.tags:

                            # If the tag does not already exist
                            if tag not in case.tags:
                                case.tags.append(tag)

                        # Append the default tasks
                        for task in case_template.tasks:
                            case_task = CaseTask(title=task.title, description=task.description,
                                                order=task.order, owner=task.owner, group=task.group,
                                                from_template=True,
                                                organization_uuid=current_user.organization.uuid)
                            case.tasks.append(case_task)
                        case.save()
                        message = 'The case template **{}** was applied'.format(case_template.title)
                        case.add_history(message=message)
                """

            case.update(**api2.payload)

            return case
        else:
            ns_case_v2.abort(404, 'Case not found.')

    @api2.doc(security="Bearer")
    @token_required
    @user_has('delete_case')
    def delete(self, uuid, current_user):
        ''' Deletes a case '''
        case = Case.get_by_uuid(uuid=uuid)
        if case:

            # TODO: MIGRATE THIS
            # Set any associated events back to New status
            # for event in case.events:
            #    event.status = EventStatus.query.filter_by(organization_uuid=current_user.organization.uuid, name='New').first()
            #    event.save()

            # TODO: MIGRATE THIS
            # case.events = []
            # case.save()
            # case.observables = []
            # case.save()

            case.delete()
            return {'message': 'Sucessfully deleted case.'}


@ns_case_v2.route("/<uuid>/add_events")
class AddEventsToCase(Resource):

    @api2.doc(security="Bearer")
    @api2.expect(mod_add_events_to_case)
    @api2.marshal_with(mod_add_events_response)
    @api2.response(207, 'Success')
    @api2.response(404, 'Case not found.')
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
        events = Event.get_by_uuid(uuid=api2.payload['events'])
        if events:
            case.add_event(list(events))
            return "YARP"
        return "NARP"


@ns_case_v2.route("/<uuid>/observables")
class CaseObservables(Resource):

    @api2.doc(security="Bearer")
    @api2.marshal_with(mod_observable_list_paged, as_list=True)
    @api2.response('200', 'Successs')
    @api2.response('404', 'Case not found')
    @token_required
    @user_has('view_cases')
    def get(self, uuid, current_user):
        ''' Returns the observables for a case'''
        observables = Observable.get_by_case_uuid(uuid)

        if not observables:
            observables = []

        return {'observables': observables, 'pagination': {}}


@ns_case_v2.route("/<uuid>/observables/<value>")
class CaseObservable(Resource):

    @api2.doc(security="Bearer")
    @api2.response('200', 'Success')
    @api2.response('404', 'Observable not found')
    @api2.marshal_with(mod_observable_list)
    @token_required
    @user_has('view_cases')
    def get(self, uuid, value, current_user):
        ''' Returns the information about a single observable '''
        case = Case.get_by_uuid(uuid=uuid)

        if case:
            observable = case.get_observable_by_value(value=value)
            return observable
        else:
            ns_case_v2.abort(404, 'Observable not found.')

    @api2.doc(security="Bearer")
    @api2.response('200', 'Success')
    @api2.response('400', 'Observable not found')
    @api2.expect(mod_observable_update)
    @api2.marshal_with(mod_observable_list)
    @token_required
    @user_has('update_case')
    def put(self, uuid, value, current_user):
        ''' Updates a cases observable '''

        observable = Observable.get_by_case_and_value(uuid, value)

        if observable:

            # Can not flag an observable as safe if it is also flagged as an ioc
            if observable.ioc and (observable.ioc == observable.safe):
                ns_case_v2.abort(400, 'An observable can not be safe if it is an ioc.')

            observable.update(**api2.payload, refresh=True)

            return observable
        else:
            return ns_case_v2.abort(404, 'Observable not found.')


@ns_case_v2.route("/<uuid>/add_observables/_bulk")
class CaseAddObservables(Resource):

    @api2.doc(security="Bearer")
    @api2.response('200', 'Success')
    @api2.expect(mod_bulk_add_observables)
    @api2.marshal_with(mod_case_observables)
    @token_required
    @user_has('update_case')
    def post(self, uuid, current_user):
        ''' Adds multiple observables to a case '''
        case = Case.get_by_uuid(uuid=uuid)

        if case:
            observables = api2.payload['observables']
            case.add_observables(observables, case.uuid)
            case.add_history(f"Added {len(observables)} observables")
            
            return {'observables': [o for o in observables]}
        else:
            ns_case_v2.abort(404, 'Case not found.')

@ns_case_v2.route('/<uuid>/relate_cases')
class RelateCases(Resource):

    @api2.doc(security="Bearer")
    @api2.marshal_with(mod_related_case, envelope='related_cases')
    @api2.response(207, 'Success')
    @api2.response(404, 'Case not found.')
    @token_required
    @user_has('view_cases')
    def get(self, current_user, uuid):
        ''' Returns a list of related cases '''
        case = Case.get_by_uuid(uuid=uuid)
        if case:
            if case.related_cases:
                return [c for c in Case.get_related_cases(uuid=uuid)]
        return []

    @api2.doc(security="Bearer")
    @api2.expect(mod_link_cases)
    @api2.marshal_with(mod_related_case, envelope='related_cases')
    @api2.response(207, 'Success')
    @api2.response(404, 'Case not found.')
    @token_required
    @user_has('update_case')
    def put(self, current_user, uuid):

        case = Case.get_by_uuid(uuid=uuid)
        related_cases = Case.get_related_cases(uuid=uuid)
        cases = []
        if case:
            if 'cases' in api2.payload:
                _cases = api2.payload.pop('cases')
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

    @api2.doc(security="Bearer")
    @api2.marshal_with(mod_related_case, envelope='related_cases')
    @api2.response(207, 'Success')
    @api2.response(404, 'Case not found.')
    @token_required
    @user_has('update_case')
    def delete(self, current_user, uuid):
        ''' Unlinks a case or a group of cases '''

        case = Case.get_by_uuid(uuid=uuid)
        related_cases = Case.get_related_cases(uuid=uuid)
        if case:
            if 'cases' in api2.payload:
                _cases = api2.payload.pop('cases')
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


case_history_parser = api2.parser()
case_history_parser.add_argument(
    'case_uuid', type=str, location='args', required=True)


@ns_case_history_v2.route("")
class CaseHistoryList(Resource):

    @api2.doc(security="Bearer")
    @api2.expect(case_history_parser)
    @api2.marshal_with(mod_case_history, as_list=True)
    @token_required
    @user_has('view_cases')
    def get(self, current_user):
        ''' Returns a list of case history events '''

        args = case_history_parser.parse_args()

        history = CaseHistory.get_by_case(uuid=args['case_uuid'], sort_by="-created_at")

        if history:
            return [h for h in history]
        else:
            return []


case_comment_parser = api2.parser()
case_comment_parser.add_argument(
    'case_uuid', type=str, location='args', required=True)


@ns_case_comment_v2.route("")
class CaseCommentList(Resource):

    @api2.doc(security="Bearer")
    @api2.expect(case_comment_parser)
    @api2.marshal_with(mod_comment, as_list=True)
    @token_required
    @user_has('view_case_comments')
    def get(self, current_user):
        ''' Returns a list of comments '''

        args = case_comment_parser.parse_args()

        if 'case_uuid' in args:
            comments = CaseComment.get_by_case(uuid=args['case_uuid'])
            if comments:
                return [c for c in comments]
            else:
                return []
        else:
            ns_case_comment_v2.abort(400, 'A case UUID is required.')

    @api2.doc(security="Bearer")
    @api2.expect(mod_comment_create, validate=True)
    @api2.response(200, 'AMAZING', mod_comment)
    @api2.marshal_with(mod_comment)
    @token_required
    @user_has('create_case_comment')
    def post(self, current_user):
        _tags = []
        ''' Creates a new comment '''
        if 'closure_reason_uuid' in api2.payload:
            api2.payload['closure_reason'] = CloseReason.get_by_uuid(
                api2.payload.pop('closure_reason_uuid'))

        case = Case.get_by_uuid(uuid=api2.payload['case_uuid'])
        if case:
            case_comment = CaseComment(**api2.payload)
            case_comment.save()
            case.add_history(message="Comment added to case")
        else:
            ns_case_comment_v2.abort(404, 'Case not found.')        
        return case_comment


@ns_case_comment_v2.route("/<uuid>")
class CaseCommentDetails(Resource):

    @api2.doc(security="Bearer")
    @api2.marshal_with(mod_comment)
    @api2.response('200', 'Success')
    @api2.response('404', 'Comment not found')
    @token_required
    @user_has('view_case_comments')
    def get(self, uuid, current_user):
        ''' Returns information about a comment '''
        case_comment = CaseComment.get_by_uuid(uuid=uuid)
        if case_comment:
            return case_comment
        else:
            ns_case_comment_v2.abort(404, 'Comment not found.')

    @api2.doc(security="Bearer")
    @api2.expect(mod_comment_create)
    @api2.marshal_with(mod_comment)
    @token_required
    @user_has('update_case_comment')
    def put(self, uuid, current_user):
        ''' Updates information for a comment '''
        case_comment = CaseComment.get_by_uuid(uuid=uuid)
        if case_comment:
            case_comment.edited = True
            case_comment.update(**api2.payload)
            return case_comment
        else:
            ns_case_comment_v2.abort(404, 'Comment not found.')

    @api2.doc(security="Bearer")
    @token_required
    @user_has('delete_case_comment')
    def delete(self, uuid, current_user):
        ''' Deletes a comment '''
        case_comment = CaseComment.get_by_uuid(uuid=uuid)
        if case_comment:
            case = Case.get_by_uuid(case_comment.case_uuid)
            case_comment.delete()
            case.add_history("Comment deleted")            
            return {'message': 'Sucessfully deleted comment.'}


case_template_parser = api2.parser()
case_template_parser.add_argument('title', location='args', required=False)


@ns_case_template_v2.route("")
class CaseTemplateList(Resource):

    @api2.doc(security="Bearer")
    @api2.marshal_with(mod_case_template_full, as_list=True)
    @api2.expect(case_template_parser)
    @token_required
    @user_has('view_case_templates')
    def get(self, current_user):
        ''' Returns a list of case_template '''

        args = case_template_parser.parse_args()
        case_templates = None

        if args['title']:
            case_templates = CaseTemplate.title_search(search=args['title'])
        else:
            case_templates = CaseTemplate.search().execute()
        if case_templates:
            return [c for c in case_templates]
        else:
            return []

    @api2.doc(security="Bearer")
    @api2.expect(mod_case_template_create)
    @api2.response('409', 'Case Template already exists.')
    @api2.response('200', "Successfully created the case_template.")
    @api2.marshal_with(mod_case_template_full)
    @token_required
    @user_has('create_case_template')
    def post(self, current_user):

        # Check to see if the case template already exists and
        # return an error indicating as such
        case_template = CaseTemplate.get_by_title(title=api2.payload['title'])
        if case_template:
            ns_case_template_v2.abort(409, 'Case Template already exists.')
        else:
            ''' Creates a new case_template template '''

            case_template = CaseTemplate(**api2.payload)
            case_template.save()

            # Set the default status to New
            # case_template_status = CaseStatus.query.filter_by(
            #   name="New").first()
            #case_template.status = case_template_status
            # case_template.save()

            return case_template


@ns_case_template_v2.route("/<uuid>")
class CaseTemplateDetails(Resource):

    @api2.doc(security="Bearer")
    @api2.marshal_with(mod_case_template_full)
    @api2.response('200', 'Success')
    @api2.response('404', 'Case Template not found')
    @token_required
    @user_has('view_case_templates')
    def get(self, uuid, current_user):
        ''' Returns information about a case_template '''
        case_template = CaseTemplate.get_by_uuid(uuid=uuid)
        if case_template:
            return case_template
        else:
            ns_case_template_v2.abort(404, 'Case Template not found.')

    @api2.doc(security="Bearer")
    @api2.expect(mod_case_template_create)
    @api2.marshal_with(mod_case_template_full)
    @token_required
    @user_has('update_case_template')
    def put(self, uuid, current_user):
        ''' Updates information for a case_template '''
        case_template = CaseTemplate.get_by_uuid(uuid=uuid)
        if case_template:
            if 'title' in api2.payload:
                exists = CaseTemplate.get_by_title(title=api2.payload['title'])
                if exists and exists.uuid != case_template.uuid:
                    ns_case_template_v2.abort(
                        409, 'A Case Template with that title already exists.')

            case_template.update(**api2.payload)
            return case_template
        else:
            ns_case_template_v2.abort(404, 'Case Template not found.')

    @api2.doc(security="Bearer")
    @token_required
    @user_has('delete_case_template')
    def delete(self, uuid, current_user):
        ''' Deletes a case_template '''
        case_template = CaseTemplate.get_by_uuid(uuid=uuid)
        if case_template:
            case_template.delete()
            return {'message': 'Sucessfully deleted case_template.'}


case_task_parser = api2.parser()
case_task_parser.add_argument(
    'case_uuid', type=str, location='args', required=False)


@ns_case_task_v2.route("")
class CaseTaskList(Resource):

    @api2.doc(security="Bearer")
    @api2.expect(case_task_parser)
    @api2.marshal_with(mod_case_task_full, as_list=True)
    @token_required
    @user_has('view_case_tasks')
    def get(self, current_user):
        ''' Returns a list of case_task '''
        args = case_task_parser.parse_args()

        if 'case_uuid' in args:
            tasks = CaseTask.get_by_case(uuid=args['case_uuid'])
            if tasks:
                return [t for t in sorted(tasks, key = lambda t: t.order)]
            else:
                return []
        else:
            ns_case_task_v2.abort(400, 'A case UUID is required.')

    @api2.doc(security="Bearer")
    @api2.expect(mod_case_task_create)
    @api2.marshal_with(mod_case_task_full)
    @api2.response('409', 'Case Task already exists.')
    @api2.response('200', "Successfully created the case task.")
    @token_required
    @user_has('create_case_task')
    def post(self, current_user):
        ''' Creates a new case_task '''

        task = CaseTask.get_by_title(
            title=api2.payload['title'], case_uuid=api2.payload['case_uuid'])

        if not task:
            case_uuid = api2.payload.pop('case_uuid')
            if 'owner_uuid' in api2.payload:
                owner = api2.payload.pop('owner_uuid')
            case = Case.get_by_uuid(uuid=case_uuid)
            task = case.add_task(**api2.payload)
            task.set_owner(owner)
            task.save()

            return task

        else:
            ns_case_task_v2.abort(409, 'Case Task already exists')

@ns_case_task_v2.route("/<uuid>/add_note")
class CaseTaskNote(Resource):

    @api2.doc(security="Bearer")
    @api2.expect(mod_case_task_note_create)
    @api2.marshal_with(mod_case_task_note_details)
    @api2.response('200', 'Success')
    @token_required
    @user_has('update_case_task')
    def post(self, uuid, current_user):
        ''' Creates a new note on a specified task'''

        task = CaseTask.get_by_uuid(uuid)
        
        if task:
            note = task.add_note(note=api2.payload['note'])
            return note
        return {}


@ns_case_task_v2.route("/<uuid>")
class CaseTaskDetails(Resource):

    @api2.doc(security="Bearer")
    @api2.marshal_with(mod_case_task_full)
    @api2.response('200', 'Success')
    @api2.response('404', 'Case Task not found')
    @token_required
    @user_has('view_case_tasks')
    def get(self, uuid, current_user):
        ''' Returns information about a case task '''
        task = CaseTask.get_by_title(
            title=api2.payload['title'], case_uuid=api2.payload['case_uuid'])
        if task:
            return task
        else:
            ns_case_task_v2.abort(404, 'Case Task not found.')

    @api2.doc(security="Bearer")
    @api2.expect(mod_case_task_create)
    @api2.marshal_with(mod_case_task_full)
    @token_required
    @user_has('update_case_task')
    def put(self, uuid, current_user):
        ''' Updates information for a case_task '''

        settings = Settings.load()
        task = CaseTask.get_by_uuid(uuid=uuid)

        if task:
            if 'name' in api2.payload and CaseTask.get_by_title(title=api2.payload['title'], case_uuid=api2.payload['case_uuid']):
                ns_case_task_v2.abort(409, 'Case Task name already exists.')
            else:
                if 'status' in api2.payload:

                    # Start a task
                    if api2.payload['status'] == 1:

                        # If set, automatically assign the task to the user starting the task
                        if task.owner == [] and settings.assign_task_on_start:
                            task.start_task(current_user.uuid)
                        else:
                            task.start_task()

                    # Close a task
                    if api2.payload['status'] == 2:
                        task.close_task()

                    # Reopen the task if the previous status was closed
                    if task.status == 2 and api2.payload['status'] == 1:
                        task.reopen_task()
            return task
        else:
            ns_case_task_v2.abort(404, 'Case Task not found.')

    @api2.doc(security="Bearer")
    @token_required
    @user_has('delete_case_task')
    def delete(self, uuid, current_user):
        ''' Deletes a case_task '''

        task = CaseTask.get_by_uuid(uuid=uuid)
        if task:
            task.delete()

            return {'message': 'Sucessfully deleted case task.'}


@ns_tag_v2.route("")
class TagList(Resource):

    @api2.doc(security="Bearer")
    @api2.marshal_with(mod_tag_list, as_list=True)
    @token_required
    def get(self, current_user):
        ''' Gets a list of tags '''
        tags = Tag.search().execute()
        if tags:
            return [t for t in tags]
        else:
            return []

    @api2.doc(security="Bearer")
    @api2.expect(mod_tag)
    @api2.response('409', 'Tag already exists.')
    @api2.response('200', "Successfully created the tag.")
    @token_required
    def post(self, current_user):
        ''' Creates a new tag '''
        tag = Tag.get_by_name(name=api2.payload['name'])
        if not tag:
            tag = Tag(**api2.payload)
            tag.create()
            return {'message': 'Successfully created the tag.'}
        else:
            ns_tag_v2.abort(409, 'Tag already exists.')


@ns_input_v2.route("")
class InputList(Resource):

    @api2.doc(security="Bearer")
    @api2.marshal_with(mod_input_list, as_list=True)
    @token_required
    @user_has('view_inputs')
    def get(self, current_user):
        ''' Returns a list of inputs '''
        inputs = Input.search().execute()
        if inputs:
            return [i for i in inputs]
        else:
            return []

    @api2.doc(security="Bearer")
    @api2.expect(mod_input_create)
    @api2.response('409', 'Input already exists.')
    @api2.response('200', 'Successfully create the input.')
    @token_required
    @user_has('add_input')
    def post(self, current_user):
        ''' Creates a new input '''
        _tags = []
        inp = Input.get_by_name(name=api2.payload['name'])

        if not inp:

            if 'credential' in api2.payload:
                cred_uuid = api2.payload.pop('credential')
                api2.payload['credential'] = cred_uuid

            if 'config' in api2.payload:
                try:
                    api2.payload['config'] = json.loads(base64.b64decode(
                        api2.payload['config']).decode('ascii').strip())
                except Exception:
                    ns_input_v2.abort(
                        400, 'Invalid JSON configuration, check your syntax')

            if 'field_mapping' in api2.payload:
                try:
                    api2.payload['field_mapping'] = json.loads(base64.b64decode(
                        api2.payload['field_mapping']).decode('ascii').strip())
                except Exception:
                    ns_input_v2.abort(
                        400, 'Invalid JSON in field_mapping, check your syntax')

            inp = Input(**api2.payload)
            inp.save()

            if len(_tags) > 0:
                inp.tags += _tags
                inp.save()
        else:
            ns_input_v2.abort(409, 'Input already exists.')
        return {'message': 'Successfully created the input.'}


@ns_input_v2.route("/<uuid>")
class InputDetails(Resource):

    @api2.doc(security="Bearer")
    @api2.marshal_with(mod_input_list)
    @token_required
    @user_has('view_inputs')
    def get(self, uuid, current_user):
        ''' Returns information about an input '''
        inp = Input.get_by_uuid(uuid=uuid)
        if inp:
            return inp
        else:
            ns_input_v2.abort(404, 'Input not found.')

    @api2.doc(security="Bearer")
    @api2.expect(mod_input_create)
    @api2.marshal_with(mod_input_list)
    @token_required
    @user_has('update_input')
    def put(self, uuid, current_user):
        ''' Updates information for an input '''
        inp = Input.get_by_uuid(uuid=uuid)
        if inp:
            if 'name' in api2.payload and Input.get_by_name(name=api2.payload['name']):
                ns_input_v2.abort(409, 'Input name already exists.')
            else:
                inp.update(**api2.payload)
                return inp
        else:
            ns_input_v2.abort(404, 'Input not found.')

    @api2.doc(security="Bearer")
    @token_required
    @user_has('delete_input')
    def delete(self, uuid, current_user):
        ''' Deletes an input '''
        inp = Input.get_by_uuid(uuid=uuid)
        if inp:
            inp.delete()
            return {'message': 'Sucessfully deleted input.'}


@ns_agent_v2.route("/pair_token")
class AgentPairToken(Resource):

    @api2.doc(security="Bearer")
    @token_required
    @user_has('pair_agent')
    def get(self, current_user):
        ''' 
        Generates a short lived pairing token used by the agent to get a long running JWT
        '''

        settings = Settings.load()
        return generate_token(None, settings.agent_pairing_token_valid_minutes, 'pairing')


@ns_agent_v2.route("")
class AgentList(Resource):

    @api2.doc(security="Bearer")
    @api2.marshal_with(mod_agent_list, as_list=True)
    @token_required
    @user_has('view_agents')
    def get(self, current_user):
        ''' Returns a list of Agents '''
        agents = Agent.search().execute()
        if agents:
            return [agent for agent in agents]
        else:
            return []

    @api2.doc(security="Bearer")
    @api2.expect(mod_agent_create)
    @api2.response('409', 'Agent already exists.')
    @api2.response('200', "Successfully created the agent.")
    @token_required
    @user_has('add_agent')
    def post(self, current_user):
        ''' Creates a new Agent '''

        agent = Agent.get_by_name(name=api2.payload['name'])
        if not agent:

            agent = Agent(**api2.payload)
            agent.save()
            role = Role.get_by_name(name='Agent')
            role.add_user_to_role(agent.uuid)

            token = generate_token(str(agent.uuid), 86400, token_type='agent')

            return {'message': 'Successfully created the agent.', 'uuid': str(agent.uuid), 'token': token}
        else:
            ns_agent_v2.abort(409, "Agent already exists.")


@ns_agent_v2.route("/heartbeat/<uuid>")
class AgentHeartbeat(Resource):

    @api2.doc(security="Bearer")
    @token_required
    def get(self, uuid, current_user):
        agent = Agent.get_by_uuid(uuid=uuid)
        if agent:
            agent.last_heartbeat = datetime.datetime.utcnow()
            agent.save()
            return {'message': 'Your heart still beats!'}
        else:
            '''
            If the agent can't be found, revoke the agent token
            '''

            auth_header = request.headers.get('Authorization')
            access_token = auth_header.split(' ')[1]
            expired = ExpiredToken(token=access_token)
            expired.save()

            ns_agent_v2.abort(400, 'Your heart stopped.')


@ns_agent_v2.route("/<uuid>")
class AgentDetails(Resource):

    @api2.doc(security="Bearer")
    @api2.expect(mod_agent_create)
    @api2.marshal_with(mod_agent_list)
    @token_required
    @user_has('update_agent')
    def put(self, uuid, current_user):
        ''' Updates an Agent '''
        agent = Agent.get_by_uuid(uuid=uuid)
        if agent:
            agent.update(**api2.payload)
            return agent
        else:
            ns_agent_v2.abort(404, 'Agent not found.')

    @api2.doc(security="Bearer")
    @token_required
    @user_has('delete_agent')
    def delete(self, uuid, current_user):
        ''' Removes a Agent '''
        agent = Agent.get_by_uuid(uuid=uuid)
        if agent:
            role = Role.get_by_name(name='Agent')
            role.remove_user_from_role(uuid)
            agent.delete()
            return {'message': 'Agent successfully delete.'}
        else:
            ns_agent_v2.abort(404, 'Agent not found.')

    @api2.doc(security="Bearer")
    @api2.marshal_with(mod_agent_list)
    @token_required
    @user_has('view_agents')
    def get(self, uuid, current_user):
        ''' Gets the details of a Agent '''
        agent = Agent.get_by_uuid(uuid=uuid)
        if agent:
            return agent
        else:
            ns_agent_v2.abort(404, 'Agent not found.')


@ns_agent_group_v2.route("/<uuid>")
class AgentGroupDetails(Resource):

    @api2.doc(security="Bearer")
    @api2.marshal_with(mod_agent_group_list)
    @token_required
    @user_has('view_agent_groups')
    def get(self, uuid, current_user):

        group = AgentGroup.get_by_uuid(uuid)
        if group:
            return group
        else:
            ns_agent_group_v2.abort(404, 'Agent Group not found.')

    @api2.doc(security="Bearer")
    @api2.expect(mod_agent_group_create)
    @api2.marshal_with(mod_agent_group_list)
    @token_required
    @user_has('update_agent_group')
    def put(self, uuid, current_user):

        group = AgentGroup.get_by_uuid(uuid)

        if group:
            group.update(**api2.payload, refresh=True)
        
        return group

    @api2.doc(security="Bearer")
    @token_required
    @user_has('delete_agent_group')
    def delete(self, uuid, current_user):

        group = AgentGroup.get_by_uuid(uuid)
        group.delete()
        return {'message': f'Successfully deleted Agent Group {group.name}'}, 200


@ns_agent_group_v2.route("")
class AgentGroupList(Resource):

    @api2.doc(security="Bearer")
    @api2.marshal_with(mod_paged_agent_group_list)
    @token_required
    @user_has('view_agent_groups')
    def get(self, current_user):
        groups = AgentGroup.search()
        total_groups = groups.count()
        groups = groups.execute()
        if groups:
            groups = [g for g in groups]
        else:
            groups = []
        return {'groups': groups, 'pagination': {'total_results': total_groups}}

    @api2.doc(security="Bearer")
    @api2.expect(mod_agent_group_create)
    @api2.marshal_with(mod_agent_group_list)
    @api2.response('200', 'Successfully created agent group.')
    @api2.response('409', 'Agent group already exists.')
    @token_required
    @user_has('add_agent_group')
    def post(self, current_user):
        '''
        Creates a new agent group that can be used to assign 
        certain stack features to specific agents
        '''
        group = AgentGroup(**api2.payload)
        group.save()
        return group


@ns_credential_v2.route('/encrypt')
class EncryptPassword(Resource):

    @api2.doc(security="Bearer")
    @api2.expect(mod_credential_create, validate=True)
    @api2.marshal_with(mod_credential_full)
    @api2.response('400', 'Successfully created credential.')
    @api2.response('409', 'Credential already exists.')
    @token_required
    @user_has('add_credential')
    def post(self, current_user):
        ''' Encrypts the password '''
        credential = Credential.get_by_name(api2.payload['name'])
        if not credential:
            pw = api2.payload.pop('secret')
            credential = Credential(**api2.payload)
            credential.save()
            credential.encrypt(pw.encode(
            ), current_app.config['MASTER_PASSWORD'])

            return credential
        else:
            ns_credential_v2.abort(409, 'Credential already exists.')



cred_parser = pager_parser.copy()
cred_parser.add_argument('name', location='args', required=False, type=str)
cred_parser.add_argument('page', type=int, location='args', default=1, required=False)
cred_parser.add_argument('sort_by', type=str, location='args', default='-created_at', required=False)
cred_parser.add_argument('page_size', type=int, location='args', default=10, required=False)

@ns_credential_v2.route("")
class CredentialList(Resource):

    @api2.doc(security="Bearer")
    @api2.marshal_with(mod_credential_list)
    @api2.expect(cred_parser)
    @token_required
    @user_has('view_credentials')
    def get(self, current_user):

        

        args = cred_parser.parse_args()

        credentials = Credential.search()

        if 'name' in args and args.name not in [None, '']:
            credentials = credentials.filter('match', name=args.name)

        credentials = credentials.sort(args.sort_by)

        total_creds = credentials.count()

        page = args.page - 1
        pages = math.ceil(float(total_creds / args['page_size']))

        start = page*args.page_size
        end = start+args.page_size

        credentials = credentials[start:end]
        credentials = credentials.execute()

        """ TODO: Make this the new return for credentials
        return {
            'logs': credentials,
            'pagination': {
                'page': args.page,
                'page_size': args.page_size,
                'total_results': total_cred,
                'pages': pages
            }
        }
        """

        if credentials:
            return list(credentials)
        else:
            return []


@ns_credential_v2.route('/decrypt/<uuid>')
class DecryptPassword(Resource):

    @api2.doc(security="Bearer")
    @api2.marshal_with(mod_credential_return)
    @api2.response('404', 'Credential not found.')
    @token_required
    @user_has('decrypt_credential')
    def get(self, uuid, current_user):
        ''' Decrypts the credential for use '''
        credential = Credential.get_by_uuid(uuid=uuid)
        if credential:
            value = credential.decrypt(current_app.config['MASTER_PASSWORD'])
            if value:
                return {'secret': value}
            else:
                ns_credential_v2.abort(401, 'Invalid master password.')
        else:
            ns_credential_v2.abort(404, 'Credential not found.')


@ns_credential_v2.route('/<uuid>')
class CredentialDetails(Resource):

    @api2.doc(security="Bearer")
    @api2.marshal_with(mod_credential_full)
    @api2.response('404', 'Credential not found.')
    @token_required
    @user_has('view_credentials')
    def get(self, uuid, current_user):
        ''' Gets the full details of a credential '''
        credential = Credential.get_by_uuid(uuid)
        if credential:
            return credential
        else:
            ns_credential_v2.abort(404, 'Credential not found.')

    @api2.doc(security="Bearer")
    @api2.expect(mod_credential_update, validate=True)
    @api2.marshal_with(mod_credential_full)
    @api2.response('404', 'Credential not found.')
    @api2.response('409', 'Credential name already exists.')
    @token_required
    @user_has('update_credential')
    def put(self, uuid, current_user):
        ''' Updates a credential '''
        credential = Credential.get_by_uuid(uuid=uuid)
        if credential:
            if 'name' in api2.payload:
                cred = Credential.get_by_name(api2.payload['name'])
                if cred:
                    if cred.uuid != uuid:
                        ns_credential_v2.abort(
                            409, 'Credential name already exists.')

            if 'secret' in api2.payload:
                credential.encrypt(api2.payload.pop('secret').encode(
                ), current_app.config['MASTER_PASSWORD'])

            if len(api2.payload) > 0:
                credential.update(**api2.payload)
            return credential
        else:
            ns_credential_v2.abort(404, 'Credential not found.')

    @api2.doc(security="Bearer")
    @api2.response('404', 'Credential not found.')
    @api2.response('200', "Credential sucessfully deleted.")
    @token_required
    @user_has('delete_credential')
    def delete(self, uuid, current_user):
        ''' Deletes a credential '''
        credential = Credential.get_by_uuid(uuid=uuid)
        if credential:
            credential.delete()
            return {'message': 'Credential successfully deleted.'}
        else:
            ns_credential_v2.abort(404, 'Credential not found.')


@ns_list_v2.route("")
class ThreatListList(Resource):

    @api2.doc(security="Bearer")
    @api2.marshal_with(mod_list_list, as_list=True)
    @token_required
    @user_has('view_lists')
    def get(self, current_user):
        ''' Returns a list of ThreatLists '''
        lists = ThreatList.search().execute()
        if lists:
            return [l for l in lists]
        else:
            return []

    @api2.doc(security="Bearer")
    @api2.expect(mod_list_create, validate=True)
    @api2.marshal_with(mod_list_list)
    @api2.response('409', 'ThreatList already exists.')
    @api2.response('200', "Successfully created the list.")
    @token_required
    @user_has('add_list')
    def post(self, current_user):
        '''Creates a new ThreatList
        
        A threat list is what the system uses to determine if an observable
        is malicious or suspicious in nature.  ThreatLists can be consumed
        via target URLs or manually entered in to the system, or added to
        via the API. 

        Supported list types: `values|pattern`

        When `url` is populated the `values` field will be ignored.

        '''

        value_list = ThreatList.get_by_name(name=api2.payload['name'])

        if value_list:
            ns_list_v2.abort(409, "ThreatList already exists.")

        if api2.payload['list_type'] not in ['values', 'patterns']:
            ns_list_v2.abort(400, "Invalid list type.")

        # Remove any values entered by the user as they also want to pull
        # from a URL and the URL will overwrite their additions
        if 'url' in api2.payload:
            del api2.payload['values']

            # The polling interval must exist in the URL field exists
            if 'polling_interval' not in api2.payload or api2.payload['polling_interval'] is None:
                ns_list_v2.abort(400, 'Missing polling_interval')

            # Don't let the user define an insanely fast polling interval
            if api2.payload['polling_interval'] < 60:
                ns_list_v2.abort(400, 'Invalid polling interval, must be greater than or equal to 60')


        if 'values' in api2.payload:
            _values = api2.payload.pop('values')
            if not isinstance(_values, list):
                _values = _values.split('\n')
            values = []
            for value in _values:
                if value == '':
                    continue
                values.append(value)

            api2.payload['values'] = values

        if 'data_type_uuid' in api2.payload and DataType.get_by_uuid(api2.payload['data_type_uuid']) is None:
            ns_list_v2.abort(400, "Invalid data type")

        value_list = ThreatList(**api2.payload)
        value_list.save()
        return value_list            


@ns_list_v2.route("/<uuid>")
class ThreatListDetails(Resource):

    @api2.doc(security="Bearer")
    @api2.expect(mod_list_create)
    @api2.marshal_with(mod_list_list)
    @token_required
    @user_has('update_list')
    def put(self, uuid, current_user):
        ''' Updates a ThreatList '''
        value_list = ThreatList.get_by_uuid(uuid=uuid)
        if value_list:

            if 'name' in api2.payload:
                l = ThreatList.get_by_name(name=api2.payload['name'])
                if l and l.uuid != uuid:
                    ns_list_v2.abort(
                        409, 'ThreatList with that name already exists.')

            if 'values' in api2.payload:

                # Get the current values in the list
                if value_list.values:
                    current_values = [v for v in value_list.values]
                else:
                    current_values = []

                # Determine what the new values should be, current, new or removed
                _values = api2.payload.pop('values')

                # Detect if the user sent it as a list or a \n delimited string
                if _values and not isinstance(_values, list):
                    _values = _values.split('\n')
                else:
                    _values = []

                removed_values = [
                    v for v in current_values if v not in _values and v != '']
                new_values = [
                    v for v in _values if v not in current_values and v != '']

                # For all values not in the new list
                # delete them from the database and disassociate them
                # from the list
                for v in removed_values:
                    value_list.values.remove(v)

                for v in new_values:
                    if value_list.values:
                        value_list.values.append(v)
                    else:
                        value_list.values = [v]

                # Dedupe
                value_list.values = list(set(value_list.values))

                value_list.save()

            # Update the list with all other fields
            if len(api2.payload) > 0:
                value_list.update(**api2.payload)

            return value_list
        else:
            ns_list_v2.abort(404, 'ThreatList not found.')

    @api2.doc(security="Bearer")
    @token_required
    @user_has('delete_list')
    def delete(self, uuid, current_user):
        ''' Removes a ThreatList '''
        value_list = ThreatList.get_by_uuid(uuid=uuid)
        if value_list:
            value_list.delete()
            return {'message': 'ThreatList successfully delete.'}
        else:
            ns_list_v2.abort(404, 'ThreatList not found.')

    @api2.doc(security="Bearer")
    @api2.marshal_with(mod_list_list)
    @token_required
    @user_has('view_lists')
    def get(self, uuid, current_user):
        ''' Gets the details of a ThreatList '''

        value_list = ThreatList.get_by_uuid(uuid=uuid)
        if value_list:
            return value_list
        else:
            ns_list_v2.abort(404, 'ThreatList not found.')


@ns_plugins_v2.route("")
class PluginList(Resource):

    @api2.doc(security="Bearer")
    @api2.marshal_with(mod_plugin_list)
    @token_required
    @user_has('view_plugins')
    def get(self, current_user):
        ''' Retrieves a list of plugins'''

        plugins = Plugin.search()
        plugins = plugins[0:plugins.count()]
        plugins = plugins.execute()

        return list(plugins)


@ns_plugins_v2.route("/<uuid>")
class PluginDetails(Resource):

    @api2.doc(security="Bearer")
    @api2.marshal_with(mod_plugin_list)
    @token_required
    @user_has('view_plugins')
    def get(self, uuid, current_user):
        ''' Retrieves the details of a specific plugin'''

        plugin = Plugin.get_by_uuid(uuid)
        if plugin:
            return plugin
        else:
            ns_plugins_v2.abort(404, 'Plugin not found.')


@ns_plugins_v2.route("/download/<path:path>")
class DownloadPlugin(Resource):

    # TODO: MAKE THIS ONLY ACCESSIBLE FROM AGENT TOKENS
    @api2.doc(security="Bearer")
    @token_required
    def get(self, path, current_user):
        plugin_dir = os.path.join(os.path.dirname(os.path.realpath(__file__)), current_app.config['PLUGIN_DIRECTORY'])
        return send_from_directory(plugin_dir, path, as_attachment=True)


@ns_plugins_v2.route("/upload")
class PluginUpload(Resource):

    @api2.doc(security="Bearer")
    @api2.expect(upload_parser)
    @api2.marshal_with(mod_plugin_list, as_list=True)
    @token_required
    @user_has('create_plugin')
    def post(self, current_user):
        ''' Adds a new plugin to the system'''

        plugins = []

        args = upload_parser.parse_args()

        def allowed_file(filename):
            return '.' in filename and filename.rsplit('.', 1)[1].lower() in current_app.config['PLUGIN_EXTENSIONS']

        if 'files' not in request.files:
            ns_plugins_v2.abort(400, 'No file selected.')

        uploaded_files = args['files']
        for uploaded_file in uploaded_files:

            if uploaded_file.filename == '':
                ns_plugins_v2.abort(400, 'No file selected.')

            if uploaded_file and allowed_file(uploaded_file.filename):

                # Make sure the file is one that can be uploaded
                # TODO: Add mime-type checking
                filename = secure_filename(uploaded_file.filename)
                
                # Check to see if the organizations plugin directory exists
                plugin_dir = os.path.join(os.path.dirname(os.path.realpath(__file__)), current_app.config['PLUGIN_DIRECTORY'])
                if not os.path.exists(plugin_dir):
                    os.makedirs(plugin_dir)

                # Save the file
                file_path = os.path.join(plugin_dir, filename)
                uploaded_file.save(file_path)
                uploaded_file.close()

                # Hash the file and update the checksum for the plugin
                hasher = hashlib.sha1()
                with open(file_path, 'rb') as f:
                    hasher.update(f.read())

                # Open the file and grab the manifest and the logo
                with ZipFile(file_path, 'r') as z:
                    # TODO: Add plugin structure checks
                    # if 'logo.png' not in z.namelist():
                    #    ns_plugin.abort(400, "Archive does not contain logo.png")
                    # if 'plugin.json' not in z.namelist():
                    #    ns_plugin.abort(400, "Archive does not contain plugin.json")

                    files = [{'name': name, 'data': z.read(
                        name)} for name in z.namelist()]
                    for f in files:
                        if 'logo.png' in f['name']:
                            logo_b64 = base64.b64encode(f['data']).decode()
                        if 'plugin.json' in f['name']:
                            manifest_data = json.loads(f['data'].decode())
                            description = manifest_data['description']
                            name = manifest_data['name']
                            if 'config_template' in manifest_data:
                                config_template = manifest_data['config_template']
                            else:
                                config_template = {}
                

                #plugin = Plugin.query.filter_by(filename=filename).first()
                plugin = Plugin.get_by_filename(filename=filename)
                if plugin:
                    plugin = plugin[0]
                    plugin.manifest = manifest_data
                    plugin.logo = logo_b64
                    plugin.description = description
                    plugin.config_template = config_template
                    plugin.name = name
                    plugin.file_hash = hasher.hexdigest()
                    plugin.save()
                else:
                    plugin = Plugin(name=name,
                                    filename=filename,
                                    description=description,
                                    manifest=manifest_data,
                                    logo=logo_b64,
                                    config_template=config_template,
                                    file_hash=hasher.hexdigest())
                    plugin.save()
                    
                plugins.append(plugin)
            print(plugins)
        return plugins

audit_list_parser = api2.parser()
audit_list_parser.add_argument(
    'event_type', action='split', location='args', required=False)
audit_list_parser.add_argument(
    'status', action='split', location='args', required=False)
audit_list_parser.add_argument(
    'source_user', action='split', location='args', required=False)
audit_list_parser.add_argument(
    'page', type=int, location='args', default=1, required=False)
audit_list_parser.add_argument(
    'sort_by', type=str, location='args', default='created_at', required=False)

@ns_audit_log_v2.route("")
class AuditLogsList(Resource):

    @api2.doc(security="Bearer")
    @api2.marshal_with(mod_audit_log_paged_list)
    @api2.expect(audit_list_parser)
    @ip_approved
    @token_required    
    @user_has('view_settings')
    def get(self, current_user):
        ''' Returns a paginated collection of audit logs'''

        args = audit_list_parser.parse_args()

        page_size = 25
        page = args.page - 1
        logs = EventLog.search()

        if args.status:
            logs = logs.filter('terms', status=args.status)

        if args.event_type:
            logs = logs.filter('terms', event_type=args.event_type)

        if args.source_user:
            logs = logs.filter('terms', source_user=args.source_user)

        total_logs = logs.count()
        total_pages = total_logs/page_size

        start = page*page_size
        end = start+page_size
        
        logs = logs.sort('-created_at')
        logs = logs[start:end]
        logs = [l for l in logs]

        return {
            'logs': logs,
            'pagination': {
                'page': page+1,
                'page_size': page_size,
                'total_results': total_logs,
                'pages': total_pages
            }
        }


@ns_settings_v2.route("")
class GlobalSettings(Resource):

    @api2.doc(security="Bearer")
    @api2.marshal_with(mod_settings)
    @token_required
    @user_has('view_settings')
    def get(self, current_user):
        ''' Retrieves the global settings for the system '''
        settings = Settings.load()
        return settings

    @api2.doc(security="Bearer")
    @api2.expect(mod_settings)
    @token_required
    @user_has('update_settings')
    def put(self, current_user):

        if 'agent_pairing_token_valid_minutes' in api2.payload:
            if int(api2.payload['agent_pairing_token_valid_minutes']) > 365:
                ns_settings_v2.abort(
                    400, 'agent_pairing_token_valid_minutes can not be greated than 365 days.')

        if 'approved_ips' in api2.payload:
            api2.payload['approved_ips'] = api2.payload['approved_ips'].split('\n')
             
        settings = Settings.load()
        settings.update(**api2.payload)

        return {'message': 'Succesfully updated settings'}


@ns_settings_v2.route("/generate_persistent_pairing_token")
class PersistentPairingToken(Resource):

    @api2.doc(security="Bearer")
    @api2.marshal_with(mod_persistent_pairing_token)
    @token_required
    @user_has('create_persistent_pairing_token')
    def get(self, current_user):
        ''' Returns a new API key for the user making the request '''
        settings = Settings.load()
        return settings.generate_persistent_pairing_token()


@ns_dashboard_v2.route("")
class DashboardMetrics(Resource):

    @api2.doc(security="Bearer")
    @token_required
    def get(self, current_user):

        cases = Case.search()
        open_cases = cases.filter('match', status__name='New')
        closed_cases = cases.filter('match', status__closed='true')

        events = Event.search()
        new_events = events.filter('term', **{'status.name__keyword': 'New'})
        events_sorted = events.sort('-created_at')
        last_event = None
        if events_sorted.count() > 0:
            last_event = [e for e in events_sorted[0:1]][0]

        return {
            'total_cases': cases.count(),
            'open_cases': open_cases.count(),
            'closed_cases': closed_cases.count(),
            'total_events': events.count(),
            'new_events': new_events.count(),
            'time_since_last_event': last_event.created_at.isoformat()+"Z" if last_event else "Never"
        }