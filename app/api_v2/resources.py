import base64
import math
import datetime
import random
import string
import os
import json
import hashlib

from app.api_v2.model.user import Organization
import pyqrcode
import time
from io import BytesIO
from zipfile import ZipFile
#import pyminizip
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
    A,
    Search,
    EventStatus,
    TaskNote,
    ObservableHistory,
    Q
)

from .utils import default_org, ip_approved, check_org, page_results, token_required, user_has, generate_token, log_event, check_password_reset_token, escape_special_characters_rql
from .resource.utils import redistribute_detections

from .resource import (
    ns_playbook_v2,
    ns_audit_log_v2,
    ns_list_v2,
    ns_organization_v2,
    ns_event_v2,
    ns_auth_v2,
    ns_event_rule_v2,
    ns_role_v2,
    ns_task_v2,
    ns_detection_v2
)

from .. import ep

# Instantiate a new API object
api_v2 = Blueprint("api2", __name__, url_prefix="/api/v2.0")
api2 = Api(api_v2)

# All the API namespaces
ns_user_v2 = api2.namespace(
    'User', description='User operations', path='/user')
#ns_role_v2 = api2.namespace(
 #   'Role', description='Role operations', path='/role')
ns_settings_v2 = api2.namespace(
    'Settings', description='Settings operations', path='/settings')
ns_credential_v2 = api2.namespace(
    'Credential', description='Credential operations', path='/credential')
ns_input_v2 = api2.namespace(
    'Input', description='Input operations', path='/input')
ns_agent_v2 = api2.namespace(
    'Agent', description='Agent operations', path='/agent')
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
ns_observable_v2 = api2.namespace('Observable', description="Observable operations", path='/observable')
ns_hunting_v2 = api2.namespace('Hunting', description="Threat hunting operaitons", path="/hunting")
api2.add_namespace(ns_playbook_v2)
api2.add_namespace(ns_audit_log_v2)
api2.add_namespace(ns_list_v2)
api2.add_namespace(ns_organization_v2)
api2.add_namespace(ns_event_v2)
api2.add_namespace(ns_auth_v2)
api2.add_namespace(ns_event_rule_v2)
api2.add_namespace(ns_role_v2)
api2.add_namespace(ns_task_v2)
api2.add_namespace(ns_detection_v2)

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


@ns_user_v2.route("/me")
class UserInfo(Resource):

    @api2.doc(security="Bearer")
    @api2.marshal_with(mod_user_self)
    @token_required
    @ip_approved
    def get(self, current_user):
        ''' Returns information about the currently logged in user '''
        role = Role.get_by_member(current_user.uuid)
        organization = Organization.get_by_uuid(current_user.organization)
        current_user.role = role
        current_user.default_org = organization.default_org
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


@ns_user_v2.route('/generate_mfa_qr')
class UserGenerateMFAQr(Resource):

    @api2.doc(security="Bearer")
    @token_required
    def get(self, current_user):
        ''' Returns a QR code that the user can use to add MFA this account '''
        url = pyqrcode.create(current_user.get_totp_uri())
        stream = BytesIO()
        url.svg(stream, scale=5)
        return stream.getvalue().decode('utf-8'), 200, {
            'Content-Type': 'image/svg+xml',
            'Cache-Control': 'no-cache, no-store, must-revalidate',
            'Pragma': 'no-cache',
            'Expires': '0'
        }

@ns_user_v2.route('/validate_mfa_setup')
class UserValidateMFASetup(Resource):

    @api2.doc(security="Bearer")
    @api2.expect(mod_mfa_token)
    @token_required
    def post(self, current_user):
        ''' Checks to see if the user has successfully completed the MFA setup
        by verifying the first TOTP given by their authenticator app
        '''
        if 'token' in api2.payload and api2.payload['token'] is not None:
            valid_token = current_user.verify_mfa_setup_complete(api2.payload['token'])
            if valid_token:
                return {'message': 'Succesfully enabled MFA'}, 200
            else:
                return {'message': 'Invalid TOTP Token'}, 400            
        else:
            ns_user_v2.abort(400, 'TOTP token required.')

@ns_user_v2.route('/enable_mfa')
class UserEnableMFA(Resource):

    @api2.doc(security="Bearer")
    @token_required
    def get(self, current_user):
        ''' Enables MFA for the current user '''
        current_user.generate_mfa_secret()
        return {'message': 'Secret Generated'}, 200


@ns_user_v2.route('/disable_mfa')
class UserDisableMFA(Resource):

    @api2.doc(security="Bearer")
    @token_required
    def get(self, current_user):
        ''' Enables MFA for the current user '''
        current_user.disable_mfa()
        return {'message': 'MFA disabled'}, 200


@ns_user_v2.route('/toggle_mfa')
class ToggleMFA(Resource):

    @api2.doc(security="Bearer")
    @api2.expect(mod_toggle_user_mfa)
    @token_required
    @user_has('update_user')
    def put(self, current_user):
        ''' Enables or disables MFA for multiple users '''
        
        if 'users' in api2.payload:
            users = User.get_by_uuid(uuid=api2.payload['users'])
        enabled_disabled = ''
        user_action = []
        if users:
            for user in users:
                if 'mfa_enabled' in api2.payload:
                    if api2.payload['mfa_enabled'] == True:
                        try:
                            user.enable_mfa()
                            enabled_disabled = 'enabled'
                            user_action.append({'uuid': user.uuid, 'success': True})
                        except Exception as e:
                            user_action.append({'uuid': user.uuid, 'success': False})
                    elif api2.payload['mfa_enabled'] == False:
                        try:
                            user.disable_mfa()
                            enabled_disabled = 'disabled'
                            user_action.append({'uuid': user.uuid, 'success': True})
                        except:
                            user_action.append({'uuid': user.uuid, 'success': False})
                else:
                    ns_user_v2.abort('Missing mfa_enable field.'), 400

        return {'message': f'MFA {enabled_disabled}'}, 200

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
user_parser.add_argument('organization', location='args', required=False)
user_parser.add_argument('deleted', type=xinputs.boolean, location='args',
                         required=False, default=False)
user_parser.add_argument(
    'page', type=int, location='args', default=1, required=False)
user_parser.add_argument(
    'page_size', type=int, location='args', default=10, required=False)
user_parser.add_argument(
    'sort_by', type=str, location='args', default='created_at', required=False
)
user_parser.add_argument(
    'sort_direction', type=str, location='args', default='desc', required=False
)

@ns_user_v2.route("")
class UserList(Resource):

    @api2.doc(security="Bearer")
    @api2.marshal_with(mod_user_list_paged, as_list=True)
    @api2.expect(user_parser)
    @token_required
    @user_has('view_users')
    @check_org
    def get(self, current_user):   
        ''' Returns a list of users '''

        args = user_parser.parse_args()

        users = User.search()

        if args['username']:
            users = users.filter('wildcard', username__keyword=args.username+"*")

        if args['organization']:
            users = users.filter('term', organization=args.organization)    

        if args.deleted:
            users = users.filter('match', deleted=True)
        else:
            users = users.filter('match', deleted=False)

        print(users.to_dict())

        users, total_results, pages = page_results(users, args.page, args.page_size)

        sort_by = args.sort_by

        # These fields are default Text but can only sort by Keyword so force them to keyword fields
        if sort_by in ['username','first_name','last_name','email']:
            sort_by = f"{sort_by}.keyword"

        if args.sort_direction == 'desc':
            sort_by = f"-{sort_by}"

        users = users.sort(sort_by)
        
        users = users.execute()
        [user.load_role() for user in users]

        response = {
            'users': list(users),
            'pagination': {
                'total_results': total_results,
                'pages': pages,
                'page': args['page'],
                'page_size': args['page_size']
            }
        }
        
        return response

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

            # Strip the organization field if the user is not a member of the default
            # organization
            # TODO: replace with @check_org wrapper
            if 'organization' in api2.payload and hasattr(current_user,'default_org') and not current_user.default_org:
                api2.payload.pop('organization')

            user_password = api2.payload.pop('password')
            user = User(**api2.payload)
            user.set_password(user_password)
            user.deleted = False
            user.save()

            role = Role.get_by_uuid(uuid=user_role)
            role.add_user_to_role(user.uuid)

            user.role = role

            return {'message': 'Successfully created the user.', 'user': user}


@ns_user_v2.route("/set_password")
class UserSetPassword(Resource):

    @api2.doc(security="Bearer")
    @api2.expect(mod_password_update)
    @api2.marshal_with(mod_user_full)
    @token_required
    def put(self, current_user):
        '''
        Allows the current_user to set their password, the current_user is targeted
        by the users access credentials
        '''

        if 'password' in api2.payload:
            current_user.set_password(api2.payload['password'])
            current_user.save()
        else:
            ns_user_v2.abort(400, 'Password required.')


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
                organization = Organization.get_by_uuid(user.organization)
                if organization:
                    if 'email' in api2.payload:
                        email_domain = api2.payload['email'].split('@')[1]
                        if email_domain not in organization.logon_domains:
                            ns_user_v2.abort(400, 'Invalid logon domain.')

            # Allow the user to save their own password regardless of their permissions
            if 'password' in api2.payload and user.uuid == current_user.uuid:
                user.set_password(pw)
                user.save()

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
                random_identifier = ''.join(random.choice(string.ascii_lowercase) for i in range(5))
                user.username = f"{user.username}-DELETED-{random_identifier}"
                user.locked = True
                user.save()
                return {'message': 'User successfully deleted.'}
        else:
            ns_user_v2.abort(404, 'User not found.')



data_type_parser = api2.parser()
data_type_parser.add_argument('organization', location='args', required=False)

@ns_data_type_v2.route("")
class DataTypeList(Resource):

    @api2.doc(security="Bearer")
    @api2.marshal_with(mod_data_type_list)
    @token_required
    @check_org
    def get(self, current_user):
        ''' Gets a list of all the data types '''

        args = data_type_parser.parse_args()

        data_types = DataType.search()

        if args.organization and hasattr(current_user,'default_org') and current_user.default_org:
            data_types = data_types.filter('term', organization=args.organization)

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



@ns_observable_v2.route("/history/<value>")
class ObservableHistoricalData(Resource):
    '''Provides historical information about an observable so that
    analysts can look at the observable over time and perform correlative
    research into how the observable appears in their environment
    '''

    def get(self, value):

        response = {
            'case_count': 0,
            'event_count': 0,
            'event_list': [],
            'case_list': [],
            'is_ioc': False,
            'tags': [],
            'timeline': []
        }
        observable = Observable.get_by_value(value=value, all_docs=True)

        # Determine how many cases and events this observable appears in
        for obs in list(observable):
            if obs.case:
                response['case_count'] += 1
                response['case_list'].append(obs.case)

            if obs.events:
                response['event_count'] += 1
                response['event_list'] += obs.events

            if obs.ioc:
                response['is_ioc'] = True

            if obs.tags is not None:
                response['tags'] += obs.tags
                response['tags'] = list(set(response['tags']))

        for event_uuid in response['event_list']:
            event = Event.get_by_uuid(event_uuid)
            timeline_item = {
                'type': 'event',
                'title': event.title,
                'uuid': event_uuid,
                'description': event.description,
                'tags': list(event.tags) if event.tags else [],
                #'observables': event.observables,
                'created_at': str(event.created_at)
            }
            response['timeline'].append(timeline_item)

        for case_uuid in response['case_list']:
            case = Case.get_by_uuid(case_uuid)
            timeline_item = {
                'type': 'case',
                'title': case.title,
                'uuid': case_uuid,
                'description': case.description,
                'tags': list(case.tags) if case.tags else [],
                #'observables': case.observables,
                'created_at': str(case.created_at)
            }
            response['timeline'].append(timeline_item)


        # Sort the timeline
        response['timeline'] = sorted(
                            response['timeline'],
                            key = lambda i: i['created_at'],
                            reverse=True)

        return response
        

case_status_parser = api2.parser()
case_status_parser.add_argument(
    'name', type=str, location='args', required=False)
case_status_parser.add_argument(
    'organization', type=str, location='args', required=False)

@ns_case_status_v2.route("")
class CaseStatusList(Resource):

    @api2.doc(security="Bearer")
    @api2.expect(case_status_parser)
    @api2.marshal_with(mod_case_status_list, as_list=True)
    @token_required
    @check_org
    def get(self, current_user):
        ''' Returns a list of case_statuss '''

        args = case_status_parser.parse_args()
        
        statuses = CaseStatus.search()

        if args.name is not None:
            statuses = statuses.filter('term', name=args.name)

        if hasattr(current_user,'default_org') and args.organization is not None:
            statuses = statuses.filter('term', organization=args.organization)

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
close_reason_parser.add_argument(
    'organization', type=str, location='args', required=False
)

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

        if args.organization:
            close_reasons = close_reasons.filter('term', organization=args.organization)
        
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
case_parser.add_argument('organization', location='args', required=False, type=str)
case_parser.add_argument('status', location='args', required=False, type=str)
case_parser.add_argument('close_reason', location='args', required=False, action="split", type=str)
case_parser.add_argument('severity', location='args', required=False, action="split", type=str)
case_parser.add_argument('owner', location='args', required=False, action="split", type=str)
case_parser.add_argument('tag', location='args', required=False, action="split", type=str)
case_parser.add_argument('search', location='args', required=False, action="split", type=str)
case_parser.add_argument('my_tasks', location='args', required=False, type=xinputs.boolean)
case_parser.add_argument('my_cases', location='args', required=False, type=xinputs.boolean)
case_parser.add_argument('escalated', location='args', required=False, type=xinputs.boolean)
case_parser.add_argument('page', type=int, location='args', default=1, required=False)
case_parser.add_argument('sort_by', type=str, location='args', default='created_at', required=False)
case_parser.add_argument(
    'sort_direction', type=str, location='args', default='desc', required=False
)
case_parser.add_argument('page_size', type=int, location='args', default=25, required=False)
case_parser.add_argument('start', location='args', type=str, required=False)
case_parser.add_argument('end', location='args', type=str, required=False)

@ns_case_v2.route("")
class CaseList(Resource):

    @api2.doc(security="Bearer")
    @api2.marshal_with(mod_case_paged_list)
    @api2.expect(case_parser)
    @token_required
    @user_has('view_cases')
    @check_org
    def get(self, current_user):
        ''' Returns a list of case '''

        args = case_parser.parse_args()

        # Set default start/end date filters if they are not set above
        # We do this here because default= on add_argument() is only calculated when the API is initialized
        #if not args.start:
        #    args.start = (datetime.datetime.utcnow()-datetime.timedelta(days=7)).strftime('%Y-%m-%dT%H:%M:%S')
        #if not args.end:
        #    args.end = (datetime.datetime.utcnow()+datetime.timedelta(days=1)).strftime('%Y-%m-%dT%H:%M:%S')

        cases = Case.search()        

        cases = cases.sort('-created_at')

        # Apply filters
        if 'title' in args and args['title']:
            cases = cases.filter('wildcard', title=args['title']+"*")

        if 'status' in args and args['status']:
            cases = cases.filter('match', status__name=args['status'])

        if 'severity' in args and args['severity']:
            cases = cases.filter('terms', severity=args['severity'])

        if 'tag' in args and args['tag']:
            cases = cases.filter('terms', tags=args['tag'])

        if 'organization' in args and args.organization:
            cases = cases.filter('term', organization=args.organization)

        if 'close_reason' in args and args.close_reason:
            cases = cases.filter('terms', close_reason__title__keyword=args.close_reason)

        if args.owner and args.owner not in ['', None, []] and not args.my_cases:
            cases = cases.filter('terms', **{'owner.username__keyword': args.owner})

        if args.escalated == True:
            cases = cases.filter('term', escalated=args.escalated)

        if args.my_cases:
            cases = cases.filter('term', **{'owner.username__keyword': current_user.username})

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
        if sort_by not in ['title','tlp','severity','status']:
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

    @api2.doc(security="Bearer")
    @api2.expect(mod_case_create)
    @api2.response('409', 'Case already exists.')
    @api2.response('200', "Successfully created the case.")
    @token_required
    @user_has('create_case')
    #@check_org
    def post(self, current_user):
        ''' Creates a new case '''

        _tags = []
        event_observables = []
        case_observables = []
        owner_uuid = None
        case_template = None

        organization = None
        if 'organization' in api2.payload:
            organization = api2.payload['organization']
        
        settings = Settings.load(organization=organization)

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

        if 'events' in api2.payload:
            events = api2.payload.pop('events')

        case = Case(**api2.payload)

        # Set the default status to New
        case.status = CaseStatus.get_by_name(name="New")
        case.set_owner(owner_uuid)

        events_to_update = []
        if isinstance(events, list) and len(events) > 0:
            uuids = []
            
            for event in events:
                e = Event.get_by_uuid(event)
                event_dict = e.to_dict()
                event_dict['_meta'] = {
                    'action': 'add_to_case',
                    'case': case.uuid,
                    '_id': e.meta.id
                }
                events_to_update.append(event_dict)
                #e.set_open()
                #e.set_case(uuid=case.uuid)
                uuids.append(e.uuid)

                if 'include_related_events' in api2.payload and api2.payload['include_related_events']:
                    
                    related_events = Event.get_by_signature_and_status(signature=e.signature, status='New', all_events=True)
                    for related_event in related_events:
                        related_dict = related_event.to_dict()
                        related_dict['_meta'] = {
                            'action': 'add_to_case',
                            'case': case.uuid,
                            '_id': related_event.meta.id
                        }
                        events_to_update.append(related_dict)
                        #related_event.set_open()
                        #related_event.set_case(uuid=case.uuid)

                        # PERFORMANCE ISSUE FIX ME
                        #case_observables += related_event.observables #Observable.get_by_event_uuid(related_event.uuid)
                        uuids.append(related_event.uuid)            

                observables = e.observables

                # Automatically generates an event rule for the event associated with this case
                if 'generate_event_rule' in api2.payload and api2.payload['generate_event_rule']:
                    rule_text = f'''# System generated base query
# Pin this rule to this event by it's title
title = "{e.title}"

# Default matching on all present observables
# Consider fine tuning this with expands function
and observables.value|all In ["{'","'.join([escape_special_characters_rql(o.value) for o in observables])}"]'''

                    event_rule = EventRule(
                        name=f"Automatic Rule for Case {case.title}",
                        description=f"Automatic Rule for Case {case.title}",
                        event_signature=f"{e.title}",
                        expire=False,
                        expire_days=0,
                        merge_into_case=True,
                        taget_case_uuid=case.uuid,
                        query=rule_text,
                        dismiss=False)
                    event_rule.active = True
                    event_rule.save()
            
            case.events = list(set(uuids))
        
        if len(events_to_update) > 0:
            [ep.enqueue(event) for event in events_to_update]

        # If the user selected a case template, take the template items
        # and copy them over to the case
        if 'case_template_uuid' in api2.payload:
            case.apply_template(api2.payload['case_template_uuid'])

        case.save()

        # Save the tags so they can be referenced in the future
        save_tags(api2.payload['tags'])

        case.add_history(message='Case created')

        time.sleep(0.5)

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

            for f in ['severity', 'tlp', 'status_uuid', 'owner', 'description', 'owner_uuid', 'escalated']:
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

                    elif f == 'escalated':
                        if api2.payload[f]:
                            message = 'Case escalated'
                        else:
                            message = 'Case de-escalated'

                    if message:
                        case.add_history(message=message)
                    else:
                        case.add_history(
                            message="**{}** changed to **{}**".format(f.title(), value))

            if 'tags' in api2.payload:
                save_tags(api2.payload['tags'])

            if 'case_template_uuid' in api2.payload:
                remove_successful = case.remove_template()
                if remove_successful:
                    case.apply_template(api2.payload['case_template_uuid'])

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
            #if observables and len(observables) > 0:
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
            events_to_update = []
            uuids = []
            for event in events:
                event_dict = event.to_dict()
                event_dict['_meta'] = {
                    'action': 'add_to_case',
                    'case': case.uuid,
                    '_id': event.meta.id
                }
                events_to_update.append(event_dict)
                uuids.append(event.uuid)

                if 'include_related_events' in api2.payload and api2.payload['include_related_events'] == True:
                    related_events = Event.get_by_signature_and_status(signature=event.signature,
                                                                       status='New',
                                                                       all_events=True)
                    if related_events:
                        for related_event in related_events:
                            if related_event.uuid != event.uuid:
                                related_dict = related_event.to_dict()
                                related_dict['_meta'] = {
                                    'action': 'add_to_case',
                                    'case': case.uuid,
                                    '_id': related_event.meta.id
                                }
                                events_to_update.append(related_dict)
                                uuids.append(related_event.uuid)
            
            if case.events:
                [case.events.append(uuid) for uuid in uuids]
            else:
                case.events = uuids

            if len(events_to_update) > 0:
                [ep.enqueue(event) for event in events_to_update]

            case.add_history(message=f'{len(events_to_update)} events added')
            case.save()
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

            search = Event.search()
            search = search[0:1]
            search = search.filter('term', case=uuid)
            search = search.query('nested', path='event_observables', query=Q({"terms": {"event_observables.value": value}}))

            return {}
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

        observable = None

        value = base64.b64decode(value).decode()

        search = Event.search()
        search = search[0:1]
        search = search.filter('term', case=uuid)
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
            if 'safe' in api2.payload:
                observable.safe = api2.payload['safe']

            if 'ioc' in api2.payload:
                observable.ioc = api2.payload['ioc']

            if 'spotted' in api2.payload:
                observable.spotted = api2.payload['spotted']

            if getattr(observable,'ioc') and getattr(observable,'safe'):
                ns_case_v2.abort(400, 'An observable can not be an ioc if it is flagged safe.')

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
            return ns_case_v2.abort(404, 'Observable not found.')


@ns_case_v2.route("/<uuid>/add_observables/_bulk")
class CaseAddObservables(Resource):

    @api2.doc(security="Bearer")
    @api2.response('200', 'Success')
    @api2.expect(mod_bulk_add_observables)
    @api2.marshal_with(mod_case_observables)
    @token_required
    @user_has('update_case')
    @check_org
    def post(self, uuid, current_user):
        ''' Adds multiple observables to a case '''
        case = Case.get_by_uuid(uuid=uuid)

        if case:

            organization = case.organization
            if 'organization' in api2.payload:
                organization = api2.payload['organization']  
            
            if 'observables' in api2.payload:
                _observables = api2.payload['observables']
                observables = []

                # Make sure tags are in the observables
                for observable in _observables:
                    if 'tag' not in observable:
                        observable['tag'] = []

                    # If any of the values are not False, which is the default, add a history item
                    # for this observable
                    if True in (observable['ioc'], observable['spotted'], observable['safe']):
                        observable_history = ObservableHistory(**observable, organization=organization)
                        observable_history.save()

                    observables.append(observable)

                status = EventStatus.get_by_name(name='Open', organization=organization)

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
                return Case.get_by_uuid(uuid=case.related_cases)
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


case_stats_parser = api2.parser()
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
case_stats_parser.add_argument('top', location='args', default=10, type=int, required=False)
case_stats_parser.add_argument('my_cases', location='args', required=False, type=xinputs.boolean)
case_stats_parser.add_argument('escalated', location='args', required=False, type=xinputs.boolean)
case_stats_parser.add_argument('interval', location='args', default='day', required=False, type=str)
case_stats_parser.add_argument('start', location='args', type=str, required=False)
case_stats_parser.add_argument('end', location='args', type=str, required=False)
case_stats_parser.add_argument('metrics', location='args', action='split', default=['title','tag','status','severity','close_reason','owner','organization','escalated'])
case_stats_parser.add_argument('organization', location='args', action='split', required=False)

@ns_case_v2.route('/stats')
class CaseStats(Resource):

    @api2.doc(security="Bearer")
    @api2.expect(case_stats_parser)
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
        #if not args.start:
        #    args.start = (datetime.datetime.utcnow()-datetime.timedelta(days=7)).strftime('%Y-%m-%dT%H:%M:%S')
        #if not args.end:
        #    args.end = (datetime.datetime.utcnow()+datetime.timedelta(days=1)).strftime('%Y-%m-%dT%H:%M:%S')

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

        for arg in ['severity','title','tags','organization']:
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
            search = search.filter(_filter['type'], **{_filter['field']: _filter['value']})

        search.aggs.bucket('range', 'filter', range={'created_at': {
            'gte': args.start,
            'lte': args.end
        }})

        if 'title' in args.metrics:
            max_title = args.top if args.top != 10 else 100
            search.aggs['range'].bucket('title', 'terms', field='title', size=max_title)

        if 'tag' in args.metrics:
            max_tags = args.top if args.top != 10 else 50
            search.aggs['range'].bucket('tags', 'terms', field='tags', size=max_tags)

        if 'close_reason' in args.metrics:
            max_reasons = args.top if args.top != 10 else 10
            search.aggs['range'].bucket('close_reason', 'terms', field='close_reason.title.keyword', size=max_reasons)

        if 'status' in args.metrics:
            max_status = args.top if args.top != 10 else 5
            search.aggs['range'].bucket('status', 'terms', field='status.name.keyword', size=max_status)

        if 'owner' in args.metrics:
            max_status = args.top if args.top != 10 else 5
            search.aggs['range'].bucket('owner', 'terms', field='owner.username.keyword', size=max_status)

        if 'severity' in args.metrics:
            max_severity = args.top if args.top != 10 else 10
            search.aggs['range'].bucket('severity', 'terms', field='severity', size=max_severity)

        if 'organization' in args.metrics:
            max_organizations = args.top if args.top != 10 else 10
            search.aggs['range'].bucket('organization', 'terms', field='organization', size=max_organizations)

        if 'escalated' in args.metrics:
            search.aggs['range'].bucket('escalated', 'terms', field='escalated', size=2)

        search = search[0:0]

        cases = search.execute()

        if 'cases_over_time' in args.metrics:
            cases_over_time = Case.search()
       
            cases_over_time = cases_over_time[0:0]

            cases_over_time.aggs.bucket('range', 'filter', range={'created_at': {
                        'gte': args.start,
                        'lte': args.end
                    }})

            cases_over_time.aggs['range'].bucket('cases_per_day', 'date_histogram', field='created_at', format='yyyy-MM-dd', calendar_interval=args.interval, min_doc_count=0)

            cases_over_time = cases_over_time.execute()

        metrics = {}

        if 'title' in args.metrics:
            metrics['title'] = {v['key']: v['doc_count'] for v in cases.aggs.range.title.buckets}

        if 'tag' in args.metrics:
            metrics['tags'] = {v['key']: v['doc_count'] for v in cases.aggs.range.tags.buckets}

        if 'close_reason' in args.metrics:
            metrics['close reason'] = {v['key']: v['doc_count'] for v in cases.aggs.range.close_reason.buckets}

        if 'status' in args.metrics:
            metrics['status'] = {v['key']: v['doc_count'] for v in cases.aggs.range.status.buckets}

        if 'owner' in args.metrics:
            metrics['owner'] = {v['key']: v['doc_count'] for v in cases.aggs.range.owner.buckets}

        if 'severity' in args.metrics:
            metrics['severity'] = {v['key']: v['doc_count'] for v in cases.aggs.range.severity.buckets}

        if 'organization' in args.metrics:
            metrics['organization'] = {v['key']: v['doc_count'] for v in cases.aggs.range.organization.buckets}
          
        if 'cases_over_time' in args.metrics:
            metrics['cases_over_time'] = {v['key_as_string']: v['doc_count'] for v in cases_over_time.aggs.range.cases_per_day.buckets}

        if 'escalated' in args.metrics:
            metrics['escalated'] = {v['key']: v['doc_count'] for v in cases.aggs.range.escalated.buckets}

        return metrics

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

            for comment in comments:
                if comment.cross_organization:
                    organization = Organization.get_by_uuid(comment.other_organization)
                    comment.__dict__['other_organization_name'] = organization.name

            if comments:
                return list(comments)
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

            # Append the organization of the case to the comment
            api2.payload['organization'] = case.organization

            # Appends the commenters organization if commenting across organizations
            # useful when the default tenant comments on a sub-tenants cases
            if current_user.organization != case.organization:
                api2.payload['cross_organization'] = True
                api2.payload['other_organization'] = current_user.organization

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
case_template_parser.add_argument('organization', location='args', required=False)


@ns_case_template_v2.route("")
class CaseTemplateList(Resource):

    @api2.doc(security="Bearer")
    @api2.marshal_with(mod_case_template_full, as_list=True)
    @api2.expect(case_template_parser)
    @token_required
    @user_has('view_case_templates')
    @check_org
    def get(self, current_user):
        ''' Returns a list of case_template '''

        args = case_template_parser.parse_args()

        case_templates = CaseTemplate.search()

        if args['title']:
            case_templates = case_templates.filter('term', title=args.title)

        if args['organization']:
            case_templates = case_templates.filter('term', organization=args.organization)
        
        case_templates = list(case_templates.scan())
        if case_templates:
            return case_templates
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
            if 'organization' in api2.payload:
                if case_template.organization == api2.payload['organization']:
                    ns_case_template_v2.abort(409, 'Case Template with that name already exists.')

            elif case_template.organization == current_user.organization:
                ns_case_template_v2.abort(409, 'Case Template with that name already exists.')

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
    @check_org
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
            tasks = CaseTask.get_by_case(uuid=args['case_uuid'], all_results=True)
            if tasks:
                
                #return [t for t in sorted(tasks, key = lambda t: t.order) if t is not None]
                return tasks
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

            case = Case.get_by_uuid(uuid=case_uuid)
            task = case.add_task(**api2.payload)

            if 'owner_uuid' in api2.payload:
                owner = api2.payload.pop('owner_uuid')            
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

        
        task = CaseTask.get_by_uuid(uuid=uuid)

        settings = Settings.load(organization=task.organization)

        if task:
            if 'name' in api2.payload and CaseTask.get_by_title(title=api2.payload['title'], case_uuid=api2.payload['case_uuid']):
                ns_case_task_v2.abort(409, 'Case Task name already exists.')
            else:
                if 'status' in api2.payload:

                    # Start a task
                    if api2.payload['status'] == 1:

                        # If set, automatically assign the task to the user starting the task
                        if task.owner == [] and settings and settings.assign_task_on_start:
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


input_list_parser = api2.parser()
input_list_parser.add_argument('name', location='args', required=False)
input_list_parser.add_argument('organization', location='args', required=False)
input_list_parser.add_argument(
    'page', type=int, location='args', default=1, required=False)
input_list_parser.add_argument(
    'page_size', type=int, location='args', default=10, required=False)
input_list_parser.add_argument(
    'sort_by', type=str, location='args', default='created_at', required=False
)
input_list_parser.add_argument(
    'sort_direction', type=str, location='args', default='desc', required=False
)

@ns_input_v2.route("")
class InputList(Resource):

    @api2.doc(security="Bearer")
    @api2.marshal_with(mod_input_list_paged, as_list=True)
    @api2.expect(input_list_parser)
    @token_required
    @default_org
    @user_has('view_inputs')
    def get(self, user_in_default_org, current_user):
        ''' Returns a list of inputs '''

        args = input_list_parser.parse_args()

        inputs = Input.search()

        if user_in_default_org:
            if args.organization:
                inputs = inputs.filter('term', organization=args.organization)

        if args.name:
            inputs = inputs.filter('wildcard', name=args.name+'*')

        inputs, total_results, pages = page_results(inputs, args.page, args.page_size)

        sort_by = args.sort_by
        if args.sort_direction == 'desc':
            sort_by = f"-{sort_by}"

        inputs = inputs.sort(sort_by)

        inputs = inputs.execute()

        response = {
            'inputs': list(inputs),
            'pagination': {
                'total_results': total_results,
                'pages': pages,
                'page': args['page'],
                'page_size': args['page_size']
            }
        }

        return response
        

    @api2.doc(security="Bearer")
    @api2.expect(mod_input_create)
    @api2.response('409', 'Input already exists.')
    @api2.response('200', 'Successfully create the input.')
    @token_required
    @default_org
    @user_has('add_input')
    def post(self, user_in_default_org, current_user):
        ''' Creates a new input '''
        _tags = []

        if user_in_default_org:
            if 'organization' in api2.payload:
                inp = Input.get_by_name(name=api2.payload['name'], organization=api2.payload['organization'])
            else:
                inp = Input.get_by_name(name=api2.payload['name'], organization=current_user.organization)
        else:
            inp = Input.get_by_name(name=api2.payload['name'], organization=current_user.organization)

        if not inp:

            if 'credential' in api2.payload:
                cred_uuid = api2.payload.pop('credential')
                api2.payload['credential'] = cred_uuid

            # Strip the organization field if the user is not a member of the default
            # organization
            # TODO: replace with @check_org wrapper
            if 'organization' in api2.payload and hasattr(current_user,'default_org') and not current_user.default_org:
                api2.payload.pop('organization')

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
            else:
                ns_input_v2.abort(
                    400, 'Field mappings are required.'
                )

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
        return generate_token(None, settings.agent_pairing_token_valid_minutes, current_user.organization, 'pairing')


agent_list_parser = api2.parser()
agent_list_parser.add_argument('organization', location='args', required=False)
agent_list_parser.add_argument(
    'page', type=int, location='args', default=1, required=False)
agent_list_parser.add_argument(
    'page_size', type=int, location='args', default=10, required=False)
agent_list_parser.add_argument(
    'sort_by', type=str, location='args', default='created_at', required=False
)
agent_list_parser.add_argument(
    'sort_direction', type=str, location='args', default='desc', required=False
)

@ns_agent_v2.route("")
class AgentList(Resource):

    @api2.doc(security="Bearer")
    @api2.marshal_with(mod_agent_list_paged, as_list=True)
    @api2.expect(agent_list_parser)
    @token_required
    @default_org
    @user_has('view_agents')
    def get(self, user_in_default_org, current_user):
        ''' Returns a list of Agents '''

        args = agent_list_parser.parse_args()

        agents = Agent.search()

        if user_in_default_org:
            if args.organization:
                agents = agents.filter('term', organization=args.organization)

        sort_by = args.sort_by
        if args.sort_direction == 'desc':
            sort_by = f"-{sort_by}"

        agents = agents.sort(sort_by)

        agents, total_results, pages = page_results(agents, args.page, args.page_size)

        response = {
            'agents': list(agents),
            'pagination': {
                'total_results': total_results,
                'pages': pages,
                'page': args['page'],
                'page_size': args['page_size']
            }
        }

        return response

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

            groups = None
            if 'groups' in api2.payload:
                groups = api2.payload.pop('groups')
                groups = AgentGroup.get_by_name(name=groups, organization=current_user['organization'])
                if groups:
                    if isinstance(groups, AgentGroup):
                        api2.payload['groups'] = [groups.uuid]
                    else:
                        api2.payload['groups'] = [g.uuid for g in groups]

            agent = Agent(**api2.payload)
            agent.save(refresh=True)

            # Add the agent to the groups
            if groups:
                if isinstance(groups, list):
                    [group.add_agent(agent.uuid) for group in groups]
                else:
                    groups.add_agent(agent.uuid)
            
            # Add the agent to the agent role
            role = Role.get_by_name(name='Agent', organization=agent.organization)
            role.add_user_to_role(agent.uuid)

            token = generate_token(str(agent.uuid), 525600*5, token_type='agent', organization=current_user['organization'])

            redistribute_detections(agent.organization)

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
            role = Role.get_by_name(name='Agent', organization=agent.organization)
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
    @default_org
    @user_has('update_agent_group')
    def put(self, uuid, user_in_default_org, current_user):

        group = AgentGroup.get_by_uuid(uuid)

        exists = None
        if 'name' in api2.payload:
            if user_in_default_org:
                if 'organization' in api2.payload:
                    exists = AgentGroup.get_by_name(api2.payload['name'], organization=api2.payload['organization'])
                else:
                    exists = AgentGroup.get_by_name(api2.payload['name'])
            else:
                exists = AgentGroup.get_by_name(api2.payload['name'])
       
            if exists and exists.uuid != uuid:
                ns_agent_group_v2.abort(409, "Group with this name already exists")

        if group:
            group.update(**api2.payload, refresh=True)
        
        return group

    @api2.doc(security="Bearer")
    @token_required
    @user_has('delete_agent_group')
    def delete(self, uuid, current_user):

        group = AgentGroup.get_by_uuid(uuid)

        # Do not allow for deleting groups with agents assigned
        if group:
            if group.agents and len(group.agents) > 0:
                ns_agent_group_v2.abort(400, 'Can not delete a group with agents assigned')

            group.delete()
            return {'message': f'Successfully deleted Agent Group {group.name}'}, 200
        else:
            ns_agent_group_v2.abort(404, 'Agent Group not found')


agent_group_list_parser = api2.parser()
agent_group_list_parser.add_argument('organization', location='args', required=False)
agent_group_list_parser.add_argument(
    'page', type=int, location='args', default=1, required=False)
agent_group_list_parser.add_argument(
    'page_size', type=int, location='args', default=10, required=False)
agent_group_list_parser.add_argument(
    'sort_by', type=str, location='args', default='created_at', required=False
)
agent_group_list_parser.add_argument(
    'sort_direction', type=str, location='args', default='desc', required=False
)


@ns_agent_group_v2.route("")
class AgentGroupList(Resource):

    @api2.doc(security="Bearer")
    @api2.marshal_with(mod_paged_agent_group_list)
    @api2.expect(mod_agent_group_list_paged)
    @token_required
    @default_org
    @user_has('view_agent_groups')
    def get(self, user_in_default_org, current_user):

        args = agent_group_list_parser.parse_args()

        groups = AgentGroup.search()

        if user_in_default_org:
            if args.organization:
                groups = groups.filter('term', organization=args.organization)

        sort_by = args.sort_by
        if sort_by not in ['name']:
            sort_by = "created_at"

        if args.sort_direction == 'desc':
            sort_by = f"-{sort_by}"

        groups = groups.sort(sort_by)

        groups, total_results, pages = page_results(groups, args.page, args.page_size)

        groups = groups.execute()

        response = {
            'groups': list(groups),
            'pagination': {
                'total_results': total_results,
                'pages': pages,
                'page': args['page'],
                'page_size': args['page_size']
            }
        }

        return response

    @api2.doc(security="Bearer")
    @api2.expect(mod_agent_group_create)
    @api2.marshal_with(mod_agent_group_list)
    @api2.response('200', 'Successfully created agent group.')
    @api2.response('409', 'Agent group already exists.')
    @token_required
    @default_org
    @user_has('add_agent_group')
    def post(self, user_in_default_org, current_user):
        '''
        Creates a new agent group that can be used to assign 
        certain stack features to specific agents
        '''
       
        if user_in_default_org:
            if 'organization' in api2.payload:
                group = AgentGroup.get_by_name(name=api2.payload['name'], organization=api2.payload['organization'])
            else:
                group = AgentGroup.get_by_name(name=api2.payload['name'])
        else:
            group = AgentGroup.get_by_name(name=api2.payload['name'])

        if not group:

            group = AgentGroup(**api2.payload)
            group.save()
        else:
            ns_agent_group_v2.abort(409, 'Group with that name already exists.')
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
cred_parser.add_argument('organization', location='args', required=False, type=str)
cred_parser.add_argument('page', type=int, location='args', default=1, required=False)
cred_parser.add_argument('sort_by', type=str, location='args', default='-created_at', required=False)
cred_parser.add_argument('page_size', type=int, location='args', default=10, required=False)
cred_parser.add_argument(
    'sort_by', type=str, location='args', default='created_at', required=False
)
cred_parser.add_argument(
    'sort_direction', type=str, location='args', default='desc', required=False
)

@ns_credential_v2.route("")
class CredentialList(Resource):

    @api2.doc(security="Bearer")
    @api2.marshal_with(mod_credential_list_paged)
    @api2.expect(cred_parser)
    @token_required
    @user_has('view_credentials')
    def get(self, current_user):

        args = cred_parser.parse_args()

        credentials = Credential.search()

        if 'name' in args and args.name not in [None, '']:
            credentials = credentials.filter('match', name=args.name)

        if 'organization' in args and args.organization not in [None, '']:
            credentials = credentials.filter('term', organization=args.organization)

        credentials = credentials.sort(args.sort_by)

        sort_by = args.sort_by
        if args.sort_direction == 'desc':
            sort_by = f"-{sort_by}"

        credentials = credentials.sort(sort_by)

        credentials, total_results, pages = page_results(credentials, args.page, args.page_size)        

        credentials = credentials.execute()

        response = {
            'credentials': list(credentials),
            'pagination': {
                'total_results': total_results,
                'pages': pages,
                'page': args['page'],
                'page_size': args['page_size']
            }
        }

        return response


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

            # Strip the organization field if the user is not a member of the default
            # organization
            # TODO: replace with @check_org wrapper
            if 'organization' in api2.payload and hasattr(current_user,'default_org') and not current_user.default_org:
                api2.payload.pop('organization')
                
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

            # Prevent deletion from other organizations unless its from the default org
            if current_user.default_org or current_user.organization == credential.organization:
                credential.delete()
                return {'message': 'Credential successfully deleted.'}
            else:
                ns_credential_v2.abort(401, 'Unauthorized.')
        else:
            ns_credential_v2.abort(404, 'Credential not found.')


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
        return plugins

settings_parser = api2.parser()
settings_parser.add_argument('organization', location='args', required=False)

@ns_settings_v2.route("")
class GlobalSettings(Resource):

    @api2.doc(security="Bearer")
    @api2.marshal_with(mod_settings)
    @api2.expect(settings_parser)
    @token_required
    @default_org
    @user_has('view_settings')
    def get(self, user_in_default_org, current_user):
        ''' Retrieves the global settings for the system '''

        args = settings_parser.parse_args()

        if user_in_default_org:
            if args.organization:
                settings = Settings.load(organization=args.organization)
            else:
                settings = Settings.load(organization=current_user.organization)
        else:
            settings = Settings.load(organization=current_user.organization)
            
        return settings

    @api2.doc(security="Bearer")
    @api2.expect(mod_settings)
    @token_required
    @user_has('update_settings')
    @check_org
    def put(self, current_user):

        organization = None
        if 'organization' in api2.payload:
            organization = api2.payload.pop('organization')
        else:
            organization = current_user.organization

        if 'agent_pairing_token_valid_minutes' in api2.payload:
            if int(api2.payload['agent_pairing_token_valid_minutes']) > 525600:
                ns_settings_v2.abort(
                    400, 'agent_pairing_token_valid_minutes can not be greated than 365 days.')

        if 'approved_ips' in api2.payload and api2.payload['approved_ips'] is not None:
            api2.payload['approved_ips'] = api2.payload['approved_ips'].split('\n')

        if 'disallowed_password_keywords' in api2.payload and api2.payload['disallowed_password_keywords'] is not None:
            api2.payload['disallowed_password_keywords'] = api2.payload['disallowed_password_keywords'].split('\n')
             
        settings = Settings.load(organization=organization)
        settings.update(**api2.payload)

        return {'message': 'Succesfully updated settings'}


@ns_settings_v2.route("/backup")
class BackupData(Resource):

    @api2.doc(security="Bearer")
    @api2.expect(mod_create_backup)
    @token_required
    @user_has('view_settings')
    def post(self, current_user):
        '''
        Backs up all the data from the platform into a compressed archive
        containing a JSON file for each index
        '''

        if 'password' in api2.payload:

            models = [
                Event,Tag,ExpiredToken,Credential,Agent,ThreatList,EventStatus,EventRule,
                CaseComment,CaseHistory,Case,CaseTask,CaseTemplate,Observable,AgentGroup,
                TaskNote,Plugin,PluginConfig,EventLog,User,Role,DataType,CaseStatus,CloseReason,
                Settings,Input
            ]

            backup_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'backup/')
            lock_file = os.path.join(backup_path, 'backup.lock')

            # Check to see if a backup is already in progress
            if os.path.exists(lock_file):
                ns_settings_v2.abort(400, 'Backup already in progress.')

            for f in os.listdir(backup_path):
                os.remove(os.path.join(backup_path, f))

            # Create a lock file so other admins can't start a backup
            with open(lock_file, 'w') as f:
                f.write(f'BACKUP STARTED {datetime.datetime.utcnow()} by {current_user.username}')

            if not os.path.exists(backup_path):
                os.makedirs(backup_path)

            for model in models:

                filename = f'{model.Index.name}.json'
                file_path = os.path.join(backup_path, filename)
                search = model.search()
                search = search[0:search.count()]
                results = search.execute()
                results = [r.to_dict() for r in results]
                with open(file_path, 'w') as fout:
                    json.dump(results, fout, default=str)

                if not os.path.exists(file_path) or os.path.getsize(file_path) == 0:
                    ns_settings_v2.abort(400, f'Unable to backup to {filename}')

            archive_name = f'backup-{datetime.datetime.utcnow().strftime("%Y-%m-%d")}.zip'
            backup_archive = os.path.join(backup_path, archive_name)
            
            files_to_zip = []
            for folderName, subfolders, filenames in os.walk(backup_path):
                for filename in filenames:
                    if filename.endswith('.json'):
                        filepath = os.path.join(folderName,filename)
                        files_to_zip.append(filepath)

            #pyminizip.compress_multiple(files_to_zip, [], backup_archive, api2.payload['password'], 9)
            if os.path.exists(backup_archive):
                os.remove(os.path.join(lock_file))
                return send_from_directory(backup_path, archive_name, as_attachment=True)
            else:
                ns_settings_v2.abort(400, 'Backup failed.')
        else:
            ns_settings_v2.abort(400, 'Password missing.')

persistent_token_parser = api2.parser()
persistent_token_parser.add_argument('organization', location='args', required=False, type=str)

@ns_settings_v2.route("/generate_persistent_pairing_token")
class PersistentPairingToken(Resource):

    @api2.doc(security="Bearer")
    @api2.marshal_with(mod_persistent_pairing_token)
    @api2.expect(persistent_token_parser)
    @token_required
    @default_org
    @user_has('create_persistent_pairing_token')
    def get(self, user_in_default_org, current_user):
        ''' Returns a new API key for the user making the request '''

        args = persistent_token_parser.parse_args()

        
        settings = Settings.load(organization=current_user.organization)

        if user_in_default_org:
            if args.organization:
                settings = Settings.load(organization=args.organization)           
                
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

@ns_hunting_v2.route("/query")
class HuntingQuery(Resource):

    @token_required
    def post(self, current_user):

        search = Search(index='winlogbeat-*')
        search = search.query('query_string', query=api2.payload['query'])
        results = search.execute()
        return results.to_dict()

