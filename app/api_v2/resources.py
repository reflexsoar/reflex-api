import base64
import datetime
import asyncio
from flask import request, current_app, abort, make_response, send_from_directory, send_file, Blueprint, render_template
from flask_restx import Api, Resource, Namespace, fields, Model, inputs as xinputs, marshal
from .schemas import *
from .models import (
    Event,
    EventRule,
    EventStatus,
    Observable,
    EventObservable,
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
    Tag
)
from .utils import token_required, user_has, generate_token

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
    'List', description='Lists API endpoints for managing indicator lists, lists may be string values or regular expressions', path='/list')
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

# Register all the schemas from flask-restx
for model in schema_models:
    api2.models[model.name] = model


# Generic parsers
pager_parser = api2.parser()
pager_parser.add_argument('page_size', location='args',
                          required=False, type=int, default=25)
pager_parser.add_argument('page', location='args',
                          required=False, type=int, default=1)

'''
def create_observables(observables):
    _observables = []
    _tags = []
    for o in observables:
        if 'tags' in o:
            tags = o.pop('tags')
            _tags = parse_tags(tags)

        if len(_tags) > 0:
            o['tags'] = _tags        

        observable = Observable.get(current_app.elasticsearch, key_field='value', key_value=o['value'])
        if observable:
            _observables += [observable.uuid]
        else:
            observable = Observable(**o)
            current_app.elasticsearch.add([observable])
            _observables += [observable.uuid]

        # TODO: Add threat list matching back in!

         observable_type = DataType.query.filter_by(name=o['dataType'], organization_uuid=organization_uuid).first()
        if observable_type:
            intel_lists = List.query.filter_by(organization_uuid=organization_uuid, tag_on_match=True, data_type_uuid=observable_type.uuid).all()

            o['dataType'] = observable_type
            observable = Observable(organization_uuid=organization_uuid, **o)
            observable.create()
            _observables += [observable]

            if len(_tags) > 0:
                observable.tags += _tags
                observable.save()

            # Intel list matching, if the value is on a list
            # put the list name in an array so we can tag the observable
            list_matches = []
            for l in intel_lists:
                hits = 0
                if l.list_type == 'values':
                    hits = len([v for v in l.values if v.value.lower() == o['value'].lower()])
                if l.list_type == 'patterns':
                    hits = len([v for v in l.values if re.match(v.value, o['value']) != None])
                if hits > 0:
                    list_matches.append(l.name.replace(' ','-').lower())

            # Process the tags based on the matched intel lists
            if len(list_matches) > 0:
                list_tags = []
                for m in list_matches:
                    tag = Tag.query.filter_by(organization_uuid=organization_uuid, name='list:%s' % m).first()
                    if tag:
                        list_tags.append(tag)
                    else:
                        tag = Tag(organization_uuid=organization_uuid, **{'name':'list:%s' % m, 'color': '#ffffff'})
                        list_tags.append(tag)
                observable.tags += list_tags
                observable.save()

    return _observables       
'''


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

            return {'access_token': _access_token, 'refresh_token': _refresh_token, 'user': user.uuid}, 200

        if user.failed_logons == None:
            user.update(failed_logons=0)

        # TODO: Move this back to a global setting when settings is migrated
        if user.failed_logons >= Settings.load().logon_password_attempts:
            user.update(locked=True)
        else:
            user.update(failed_logons=user.failed_logons+1)

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
            return user
        else:
            ns_user_v2.abort(404, 'User not found.')


user_parser = api2.parser()
user_parser.add_argument('username', location='args', required=False)
user_parser.add_argument('deleted', location='args',
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
            if 'role_uuid' in api2.payload:

                # Remove them from their old role
                role = Role.get_by_member(uuid=user.uuid)
                if role:
                    role.remove_user_from_role(user_id=user.uuid)

                # Add them to their new role
                role_uuid = api2.payload.pop('role_uuid')
                role = Role.get_by_uuid(uuid=role_uuid)
                role.add_user_to_role(user_id=user.uuid)
                user.role = role

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
        data_types = DataType.search().execute()
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
            ns_data_type.abort(404, 'Data type not found.')

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
            ns_data_type.abort(404, 'Data type not found.')


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

    @api2.marshal_with(mod_event_paged_list)
    @api2.expect(event_list_parser)
    def get(self):
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

        search_filter = {}
        for arg in args:
            if arg in ['status','severity','title','observables']:
                if args[arg] != '' and args[arg] is not None:
                    if isinstance(args[arg], list):
                        if arg == 'observables':
                            if len(args[arg]) > 0:
                                search_filter['event_observables.value'] = {"value": args[arg], "type":"terms"}
                        elif arg == 'status':
                            if len(args[arg]) > 0 and '' not in args[arg]:
                                search_filter['status.name__keyword'] = {"value": args[arg], "type":"terms"}
                        else:
                            if len(args[arg]) > 0 and '' not in args[arg]:
                                search_filter[arg] = args[arg]
                    else:
                        search_filter[arg] = args[arg]

        sort_by = { args['sort_by']: {'order': 'desc'} }

        if 'signature' in args and args['signature']:
            events = [e for e in Event.get_by_signature(
                signature=args['signature'])]
            total_events = len(events)
        elif 'case_uuid' in args and args['case_uuid']:
            events = [e for e in Event.get_by_case(case=args['case_uuid'])]
            total_events = len(events)
        else:
            s = Event.search()
            s = s.sort(sort_by)
            
            if len(search_filter) > 0:
                for a in search_filter:
                    print(a, search_filter[a]["type"], search_filter[a]["value"])
                    s = s.filter(search_filter[a]["type"], **{a: search_filter[a]["value"]})
                total_events = s.count()
                events = [e for e in s[start:end]]
            else:
                total_events = s.count()
                events = [e for e in s[start:end]]

        if args['page_size'] < total_events:
            pages = total_events % args['page_size']
        else:
            pages = 0

        response = {
            'events': events,
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

        observables = None
        _tags = []

        if 'observables' in api2.payload:
            observables = api2.payload.pop('observables')

        event = Event(**api2.payload)

        if observables:
            event.add_observable(observables)

        event.set_new()
        print(event.status.name)

        return {'message': 'Successfully created the event.'}


@ns_event_v2.route("/<uuid>")
class EventDetails(Resource):

    @api2.marshal_with(mod_event_details)
    def get(self, uuid):

        event = Event.get_by_uuid(uuid)
        if event:
            return event
        else:
            ns_event_v2.abort(404, 'Event not found.')


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

        event_rule = EventRule(**api2.payload)
        event_rule.hash_observables()
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


@ns_case_status_v2.route("")
class CaseStatusList(Resource):

    @api2.doc(security="Bearer")
    @api2.marshal_with(mod_case_status_list, as_list=True)
    @token_required
    def get(self, current_user):
        ''' Returns a list of case_statuss '''
        statuses = CaseStatus.search().execute()
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


@ns_close_reason_v2.route("")
class CloseReasonList(Resource):

    @api2.doc(security="Bearer")
    @api2.marshal_with(mod_close_reason_list, as_list=True)
    @token_required
    def get(self, current_user):
        ''' Returns a list of close_reasons '''
        close_reasons = CloseReason.search().execute()
        if close_reasons:
            return [c for c in close_reasons]
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

        # TODO: REIMPLIMENT ALL THE FILTERING LOGIC
        if args['page'] == 1:
            args['page'] = 0

        cases = Case.search()

        # Apply filters
        if 'status' in args and args['status']:
            cases = cases.filter('match', status__name=args['status'])

        if 'severity' in args and args['severity']:
            cases = cases.filter('terms', severity=args['severity'])

        # Paginate the cases
        cases = cases[args['page']:args['page_size']+args['page']]

        # TODO: REIMPLEMENT PAGINATION

        response = {
            'cases': [c for c in cases],
            'pagination': {
                'total_results': 0,
                'pages': 0,
                'page': 0,
                'page_size': 0
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
            #api2.payload['case_template'] = case_template

        if 'owner_uuid' in api2.payload:
            owner_uuid = api2.payload.pop('owner_uuid')
        else:
            # Automatically assign the case to the creator if they didn't pick an owner
            if settings.assign_case_on_create:
                owner_uuid = current_user.uuid

        """ TODO: MIGRATE THIS
        if 'events' in api.payload:
            api.payload['observables'] = []
            events = api.payload.pop('events')
            api.payload['events'] = []
            observable_collection = {}

            # Pull all the observables out of the events
            # so they can be added to the case
            for uuid in events:
                event = Event.query.filter_by(uuid=uuid, organization_uuid=current_user.organization.uuid).first()
                if event:
                    api.payload['events'].append(event)
                if event.observables:
                    for observable in event.observables:
                        if observable.value in observable_collection:
                            observable_collection[observable.value].append(
                                observable)
                        else:
                            observable_collection[observable.value] = [
                                observable]

            # Sort and pull out the most recent observable in the group
            # of observables
            for observable in observable_collection:
                observable_collection[observable] = sorted(
                    observable_collection[observable], key=lambda x: x.created_at, reverse=True)
                api.payload['observables'].append(
                    observable_collection[observable][0])
        """

        case = Case(**api2.payload)

        # Set the default status to New
        case.status = CaseStatus.get_by_name(name="New")
        case.set_owner(owner_uuid)

        if 'events' in api2.payload:
            for event in api2.payload['events']:
                e = Event.get_by_uuid(event)
                e.set_open()
                e.set_case(uuid=case.uuid)

                case_observables += Event.get_by_uuid(event).observables

        # Deduplicate case observables
        #print([type(o) for o in case_observables])
        case_observables = list(set([Observable(
            tags=o.tags, value=o.value, data_type=o.data_type, ioc=o.ioc, spotted=o.spotted, tlp=o.tlp, case=case.uuid) for o in case_observables]))
        case.observables = case_observables

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
            # case.case_template = {k:case_template_uuid[k]
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
        case = Case.get_by_uuid(uuid=uuid)

        if case:
            return {'observables': case.observables, 'pagination': {}}
        else:
            ns_case_v2.abort(404, 'Case not found.')

@ns_case_v2.route("/<uuid>/observables/<value>")
class CaseObservable(Resource):

    @api2.doc(security="Bearer")
    @api2.response('200', 'Success')
    @api2.response('404', 'Observable not found')
    @api2.marshal_with(mod_observable_list)
    @token_required
    @user_has('update_case') # TODO: Make this update_case_observables
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
        case = Case.get_by_uuid(uuid=uuid)
        if case:

            observable = case.get_observable_by_value(value=value)
            if observable:

                # Update all the attributes in the payload
                for k in api2.payload:
                    setattr(observable, k, api2.payload[k])
                
                # Can not flag an observable as safe if it is also flagged as an ioc
                if observable.ioc and (observable.ioc == observable.safe):
                    ns_case_v2.abort(400, 'An observable can not be safe if it is an ioc.')

                # Save the case
                case.save()
                return observable
            else:
                ns_case_v2.abort(404, 'Observable not found.')
        else:
            ns_case_v2.abort(404, 'Case not found.')
        return


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
            return {'observables': case.observables}
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
        _cases = []
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

        history = CaseHistory.get_by_case(uuid=args['case_uuid'])

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
    @api2.expect(mod_comment_create)
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
        case_comment = CaseComment(**api2.payload)
        case_comment.save()

        case = Case.get_by_uuid(uuid=api2.payload['case_uuid'])
        case.add_history(message="Commented added to case")
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
            case_templates = CaseTemplate.title_search(s=args['title'])
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
                return [t for t in tasks]
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
            ns_tag.abort(409, 'Tag already exists.')


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
            role = Role.get_by_name(name='Agent')
            role.add_user_to_role(agent.uuid)
            agent.save()

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


@ns_agent_group_v2.route("")
class AgentGroupList(Resource):

    def get(self):
        return []


@ns_credential_v2.route('/encrypt')
class EncryptPassword(Resource):

    @api2.doc(security="Bearer")
    @api2.expect(mod_credential_create)
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


@ns_credential_v2.route("")
class CredentialList(Resource):

    @api2.doc(security="Bearer")
    @api2.marshal_with(mod_credential_list)
    @token_required
    @user_has('view_credentials')
    def get(self, current_user):
        credentials = Credential.search().execute()
        if credentials:
            return [c for c in credentials]
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
            ns_credential_v2.abort(409, 'Credential not found.')

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
    @api2.expect(mod_list_create)
    @api2.marshal_with(mod_list_list)
    @api2.response('409', 'ThreatList already exists.')
    @api2.response('200', "Successfully created the list.")
    @token_required
    @user_has('add_list')
    def post(self, current_user):
        '''
        Creates a new ThreatList 

        Supported list types: `values|pattern`

        '''

        if api2.payload['list_type'] not in ['values', 'pattern']:
            ns_list_v2.abort(400, "Invalid list type.")

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

        value_list = ThreatList.get_by_name(name=api2.payload['name'])

        if not value_list:
            value_list = ThreatList(**api2.payload)
            value_list.save()
            return value_list
        else:
            ns_list_v2.abort(409, "ThreatList already exists.")


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
                current_values = [v for v in value_list.values]

                # Determine what the new values should be, current, new or removed
                _values = api2.payload.pop('values')

                # Detect if the user sent it as a list or a \n delimited string
                if not isinstance(_values, list):
                    _values = _values.split('\n')

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
