import base64
import math
import copy
import datetime
import itertools
import os
from queue import Queue
import threading
import uuid
import json
import hashlib

from app.api_v2.model.exceptions import EventRuleFailure
from .rql.parser import QueryParser
import pyqrcode
import jwt
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
    TaskNote
)

from app.api_v2.model.utils import escape_special_characters

from .utils import ip_approved, token_required, user_has, generate_token, log_event, check_password_reset_token, escape_special_characters_rql

from .resource import ns_playbook_v2, ns_audit_log_v2, ns_list_v2

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
#ns_list_v2 = api2.namespace(
#    'List', description='Lists API endpoints for managing indicator lists, lists may be string values or regular expressions', path='/list', validate=True)
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
ns_observable_v2 = api2.namespace('Observable', description="Observable operations", path='/observable')
ns_hunting_v2 = api2.namespace('Hunting', description="Threat hunting operaitons", path="/hunting")
api2.add_namespace(ns_playbook_v2)
api2.add_namespace(ns_audit_log_v2)
api2.add_namespace(ns_list_v2)

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

@ns_auth_v2.route('/mfa')
class MultiFactor(Resource):

    @api2.expect(mod_mfa_challenge)
    @api2.response(200, 'Success', mod_auth_success_token)
    @api2.response(401, 'Incorrect token')
    def post(self):
        '''Check the users challenge against their TOTP'''

        user = check_password_reset_token(api2.payload['mfa_challenge_token'])
        if user:
            if user.verify_totp(api2.payload['token']):
                # Generate an access token
                _access_token = user.create_access_token()

                # Generate a refresh tokenn
                _refresh_token = user.create_refresh_token(
                request.user_agent.string.encode('utf-8'))
                log_event(event_type="Authentication", source_user=user.username, source_ip=request.remote_addr, message="Successful MFA Check.", status="Success")
                return {'access_token': _access_token, 'refresh_token': _refresh_token, 'user': user.uuid}, 200
            log_event(event_type="Authentication", source_user=user.username, source_ip=request.remote_addr, message="Failed MFA Challenge", status="Failure")

        ns_auth_v2.abort(401, 'Invalid TOTP token')

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

            if user.mfa_enabled:
                return {'mfa_challenge_token': user.create_mfa_challenge_token()}
            else:
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
        
        print(api2.payload)
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
                            print(e)
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
event_list_parser.add_argument('source', action='split', location='args', required=False)
event_list_parser.add_argument(
    'severity', action='split', location='args', required=False)
event_list_parser.add_argument(
    'grouped', type=xinputs.boolean, location='args', required=False)
event_list_parser.add_argument(
    'case_uuid', type=str, location='args', required=False)
event_list_parser.add_argument('search', type=str, action='split', default=[
], location='args', required=False)
#event_list_parser.add_argument('rql', type=str, default="", location="args", required=False)
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


@ns_event_v2.route("")
class EventListAggregated(Resource):

    @api2.doc(security="Bearer")
    @api2.marshal_with(mod_event_paged_list)
    @api2.expect(event_list_parser)
    @token_required
    @user_has('view_events')
    def get(self, current_user):

        args = event_list_parser.parse_args()

        start = (args.page - 1)*args.page_size
        end = (args.page * args.page_size)

        search_filters = []

        if args.status and args.status != ['']:
            search_filters.append({
                    'type': 'terms',
                    'field': 'status.name__keyword',
                    'value': args.status
                })

        if args.source and args.source != ['']:
            print(args.source)
            search_filters.append({
                'type': 'terms',
                'field': 'source__keyword',
                'value': args.source
            })

        for arg in ['severity','title','tags']:
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

        raw_event_count = 0
        
        # If not filtering by a signature
        if not args.signature:
            
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

            # SLATED FOR FUTURE RELEASE - BC
            # if args.rql:
            #    qp = QueryParser()
            #    parsed_query = qp.parser.parse(args.rql)
            #    events = [r for r in qp.run_search(list(events), parsed_query, marshaller=mod_event_rql)]
        
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
            event.set_filters(filters=search_filters)
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


    @api2.expect(mod_event_create)
    def post(self):
        ''' Creates a new event '''

        observables = []

        original_payload = copy.copy(api2.payload)

        # If the event has an observables pop them off the request payload
        # so that the Event can be generated using the remaining dictionary values
        if 'observables' in api2.payload:
            observables = api2.payload.pop('observables')

        event = Event.get_by_reference(api2.payload['reference'])

        if not event:

            # Generate a default signature based off the rule name and the current time
            # signatures are required in the system but user's don't need to supply them
            # these events will remain ungrouped
            if 'signature' not in api2.payload or api2.payload['signature'] == '':
                hasher = hashlib.md5()
                date_string = datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
                hasher.update(f"{api2.payload['title']}{date_string}".encode('utf-8'))
                api2.payload['signature'] = hasher.hexdigest()

            event = Event(**api2.payload)
            event.save()

            if observables:
                event.add_observable(observables)

            event_rules = EventRule.get_all()
            if event_rules:
               
                matched = False
                for event_rule in event_rules:

                    # If the event matches the event rule criteria perform the rule actions
                    matched = event_rule.process_rql(original_payload)

                    # If the rule matched, process the event
                    if matched:
                        event_rule.process_event(event)
                        
                        # TODO: Allow for matching on multiple rules that don't have overlapping
                        # actions, e.g. one rule to move it to a case but a different rule to apply
                        # tags to the event
                        # Break out of the loop, we don't want to match on any more rules
                        break
                
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

                    # Generate a default signature based off the rule name and the current time
                    # signatures are required in the system but user's don't need to supply them
                    # these events will remain ungrouped
                    if 'signature' not in raw_event or raw_event['signature'] == '':
                        hasher = hashlib.md5()
                        date_string = datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
                        hasher.update(f"{raw_event['title']}{date_string}".encode('utf-8'))
                        raw_event['signature'] = hasher.hexdigest()

                    observables = []
                    #added_observables = []

                    # Start clocking event creation
                    start_event_process_dt = datetime.datetime.utcnow().timestamp()

                    original_payload = copy.copy(raw_event)

                    if 'observables' in raw_event:
                        observables = raw_event.pop('observables')

                    event = Event(**raw_event)
                    event.save()

                    if observables:
                        event.add_observable(observables)

                    event_rules = EventRule.get_all()
                    if event_rules:
                    
                        matched = False
                        for event_rule in event_rules:

                            # If the event matches the event rule criteria perform the rule actions
                            try:
                                matched = event_rule.process_rql(original_payload)
                            except EventRuleFailure as e:
                                log_event(event_type='Event Rule Processing', source_user="System", event_reference=event.reference, time_taken=0, status="Failed", message=f"Failed to process event rule. {e}")

                            # If the rule matched, process the event
                            if matched:
                                event_rule.process_event(event)
                                
                                # TODO: Allow for matching on multiple rules that don't have overlapping
                                # actions, e.g. one rule to move it to a case but a different rule to apply
                                # tags to the event
                                # Break out of the loop, we don't want to match on any more rules
                                break
                        
                        if not matched:
                            event.set_new()
                    else:
                        event.set_new()

                    end_event_process_dt = datetime.datetime.utcnow().timestamp()
                    event_process_time = end_event_process_dt - start_event_process_dt
                    #log_event(event_type='Bulk Event Insert', source_user="System", request_id=request_id, event_reference=event.reference, time_taken=event_process_time, status="Success", message="Event Inserted.", event_id=event.uuid)
                else:
                    log_event(event_type='Bulk Event Insert', source_user="System", request_id=request_id, event_reference=event.reference, time_taken=0, status="Failed", message="Event Already Exists.")

        
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

            for event in api2.payload['events']:
                e = Event.get_by_uuid(uuid=event)
                e.set_dismissed(reason=reason, comment=comment)
                related_events = Event.get_by_signature_and_status(signature=e.signature, status='New', all_events=True)
                if len(related_events) > 0:
                    for evt in related_events:
                        if evt.uuid not in api2.payload['events']:
                            evt.set_dismissed(reason=reason, comment=comment)

        time.sleep(1)

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

    @api2.doc(security="Bearer")
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

event_stats_parser = api2.parser()
event_stats_parser.add_argument('status', location='args', default=[
], type=str, action='split', required=False)
event_stats_parser.add_argument('tags', location='args', default=[
], type=str, action='split', required=False)
event_stats_parser.add_argument('signature', action='split', location='args', required=False)
event_stats_parser.add_argument(
    'severity', action='split', location='args', required=False)
event_stats_parser.add_argument(
    'title', type=str, location='args', action='split', required=False)
event_stats_parser.add_argument('observables', location='args', default=[
], type=str, action='split', required=False)
event_stats_parser.add_argument('source', location='args', default=[
], type=str, action='split', required=False)

@ns_event_v2.route("/stats")
class EventStats(Resource):

    @api2.doc(security="Bearer")
    @api2.expect(event_stats_parser)
    @token_required
    @user_has('view_events')
    def get(self, current_user):
        '''
        Returns metrics about events that can be used for easier filtering
        of events on the Events List page
        '''

        args = event_stats_parser.parse_args()
        
        search_filters = []

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

        for arg in ['severity','title','tags',]:
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

        event_uuids = []

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

        search = Event.search()

        # Apply all filters
        for _filter in search_filters:
            search = search.filter(_filter['type'], **{_filter['field']: _filter['value']})      

        search.aggs.bucket('title', 'terms', field='title', size=100)
        search.aggs.bucket('tags', 'terms', field='tags', size=50)
        search.aggs.bucket('status', 'terms', field='status.name.keyword', size=5)
        search.aggs.bucket('severity', 'terms', field='severity', size=10)
        search.aggs.bucket('signature', 'terms', field='signature', size=100)
        search.aggs.bucket('uuids', 'terms', field='uuid', size=10000)
        search.aggs.bucket('source', 'terms', field='source.keyword', size=10)

        events = search.execute()

        observable_search = Observable.search()
        observable_search = observable_search.filter('exists', field='events')

        observable_search = observable_search.filter('terms', **{'events': [v['key'] for v in events.aggs.uuids.buckets]})

        observable_search.aggs.bucket('data_type', 'terms', field='data_type.keyword', size=50)
        observable_search.aggs.bucket('value', 'terms', field='value', size=100)

        observable_search = observable_search.execute()

        data = {
            'title': {v['key']: v['doc_count'] for v in events.aggs.title.buckets},
            'observable value': {v['key']: v['doc_count'] for v in observable_search.aggs.value.buckets},
            'source': {v['key']: v['doc_count'] for v in events.aggs.source.buckets},
            'tag': {v['key']: v['doc_count'] for v in events.aggs.tags.buckets},
            'status': {v['key']: v['doc_count'] for v in events.aggs.status.buckets},
            'severity': {v['key']: v['doc_count'] for v in events.aggs.severity.buckets},
            'signature': {v['key']: v['doc_count'] for v in events.aggs.signature.buckets},
            'data type': {v['key']: v['doc_count'] for v in observable_search.aggs.data_type.buckets},            
        }

        return data

@ns_event_v2.route("/bulk_delete")
class BulkDeleteEvent(Resource):

    @api2.doc(security="Bearer")
    @api2.expect(mod_event_bulk_dismiss)
    @token_required
    @user_has('delete_event')
    def delete(self, current_user):
        '''
        Deletes an event and any related artifacts from the system

        Parameters:
            uuid (str): The unique identifier of the Event
            current_user (User): The current user making the API request
        '''

        if api2.payload['events']:
            for _event in api2.payload['events']:

                event = Event.get_by_uuid(uuid=_event)

                # Only support deleting events that are not in cases right now
                if event and not event.case:
                
                    # TODO: Add this back if we want to allow deleting events that are in cases
                    # Remove this event from any cases it may be associated with
                    #if event.case:
                    #    case = Case.get_by_uuid(uuid=event.case)
                    #    case.remove_event(uuid=event.uuid)

                    # Delete any observables from the observables index related to this event
                    observables = Observable.get_by_event_uuid(uuid=event.uuid)
                    for observable in observables:
                        observable.delete()

                    # Delete the event
                    event.delete()

        time.sleep(1)

        return {'message': 'Successfully deleted Events.'}, 200

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


event_bulk_select_parser = api2.parser()
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
@ns_event_v2.route("/bulk_select_all")
class BulkSelectAll(Resource):

    @api2.doc(security="Bearer")
    @api2.marshal_with(mod_bulk_event_uuids)
    @api2.expect(event_bulk_select_parser)
    @api2.response('200','Success')
    @token_required
    @user_has('view_events')
    def get(self, current_user):
        args = event_bulk_select_parser.parse_args()
        search_filters = []

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

        for arg in ['severity','title','tags']:
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

        # Apply all filters
        for _filter in search_filters:
            search = search.filter(_filter['type'], **{_filter['field']: _filter['value']})

        if not args.signature:
            search.aggs.bucket('signature', 'terms', field='signature', order={'max_date': 'desc'}, size=1000000)
            search.aggs['signature'].metric('max_date', 'max', field='created_at')
            search.aggs['signature'].bucket('uuid', 'terms', field='uuid', size=1, order={'max_date': 'desc'})
            search.aggs['signature']['uuid'].metric('max_date', 'max', field='created_at')

            events = search.execute()
            event_uuids = []
            for signature in events.aggs.signature.buckets:
                event_uuids.append(signature.uuid.buckets[0]['key'])
        else:
            events = search.scan()
            event_uuids = [e.uuid for e in events]

        return {
            'events': event_uuids
        }

@ns_event_v2.route("/<signature>/new_related_events")
class EventNewRelatedEvents(Resource):

    @api2.doc(security="Bearer")
    @api2.marshal_with(mod_related_events)
    @api2.response('200', 'Success')
    @api2.response('404', 'Event not found')
    @token_required
    @user_has('view_events')
    def get(self, signature, current_user):
        ''' Returns the UUIDs of all related events that are Open '''
        events = Event.get_by_signature(signature=signature, all_events=True)
        related_events = [e.uuid for e in events if hasattr(e.status,'name') and e.status.name == 'New']
        return {"events": related_events}


event_rule_list_parser = pager_parser.copy()
event_rule_list_parser.add_argument('page', type=int, location='args', default=1, required=False)
event_rule_list_parser.add_argument('sort_by', type=str, location='args', default='created_at', required=False)
event_rule_list_parser.add_argument('page_size', type=int, location='args', default=25, required=False)

@ns_event_rule_v2.route("")
class EventRuleList(Resource):

    @api2.doc(security="Bearer")
    @api2.marshal_with(mod_event_rule_list_paged)
    @api2.expect(event_rule_list_parser)
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

    @api2.doc(security="Bearer")
    @api2.expect(mod_event_rule_create)
    @api2.marshal_with(mod_event_rule_list)
    @api2.response('200', 'Successfully created event rule.')
    @token_required
    @user_has('create_event_rule')
    def post(self, current_user):
        ''' Creates a new event_rule set '''

        if 'expire_days' in api2.payload and not isinstance(api2.payload['expire_days'], int):
            ns_event_rule_v2.abort(400, 'expire_days should be an integer.')

        # Computer when the rule should expire
        if 'expire' in api2.payload and api2.payload['expire']:
            if 'expire_days' in api2.payload:
                expire_days = api2.payload['expire_days']

                expire_at = datetime.datetime.utcnow() + datetime.timedelta(days=expire_days)
                api2.payload['expire_at'] = expire_at
            else:
                ns_event_rule_v2.abort(400, 'Missing expire_days field.')

        event_rule = EventRule(**api2.payload)
        event_rule.active = True
        event_rule.save()

        return event_rule


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

            if 'expire_days' in api2.payload and not isinstance(api2.payload['expire_days'], int):
                ns_event_rule_v2.abort(400, 'expire_days should be an integer.')

            # Computer when the rule should expire
            if 'expire' in api2.payload and api2.payload['expire']:
                if 'expire_days' in api2.payload:
                    expire_days = api2.payload['expire_days']

                    expire_at = datetime.datetime.utcnow() + datetime.timedelta(days=expire_days)
                    api2.payload['expire_at'] = expire_at
                else:
                    ns_event_rule_v2.abort(400, 'Missing expire_days field.')

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
            event_rule.delete(refresh=True)
            return {'message': 'Sucessfully deleted the event rule.'}


@ns_event_rule_v2.route("/test_rule_rql")
class TestEventRQL(Resource):

    @api2.expect(mod_event_rule_test)
    def post(self):
        ''' Tests an RQL query against a target event to see if the RQL is valid '''

        date_filtered = False

        if api2.payload['query'] == '' or 'query' not in api2.payload:
            return {'message':'Missing RQL query.', "success": False}, 400

        if 'uuid' in api2.payload and api2.payload['uuid'] not in [None, '']:
            event = Event.get_by_uuid(uuid=api2.payload['uuid'])
            event_data = json.loads(json.dumps(marshal(event, mod_event_rql)))
        else:

            # A date filter is required when not supplying a single event UUID
            if 'start_date' in api2.payload and 'end_date' in api2.payload:
                date_filtered = True
            else:
                return {'message': 'A date range is required', "succes": False}, 400

            search = Event.search()
            search = search.sort('-created_at')
            search = search[0:api2.payload['event_count']]

            # Apply a date filter
            if date_filtered:
                search = search.filter('range', **{'created_at': {
                    'gte': api2.payload['start_date'],
                    'lte': api2.payload['end_date']
                }})

            events = search.execute()
            
            event_data = [json.loads(json.dumps(marshal(e, mod_event_rql))) for e in events]
       
        try:
            qp = QueryParser()
            parsed_query = qp.parser.parse(api2.payload['query'])
            result = [r for r in qp.run_search(event_data, parsed_query)]
            hits = len(result)

            if hits > 0:
                if 'return_results' in api2.payload and api2.payload['return_results']:
                    return {"message": f"Query matched {hits} Events", "success": True, "hits": [result]}, 200
                return {"message": f"Query matched {hits} Events", "success": True}, 200
            else:
                return {"message": "Query did not match target Event", "success": False}, 200
        except ValueError as e:
            return {"message":f"Invalid RQL query. {e}", "success": False}, 400
        

@ns_observable_v2.route("/history/<value>")
class ObservableHistory(Resource):
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
            print(args['title'])
            cases = cases.filter('wildcard', title=args['title']+"*")

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

        if 'events' in api2.payload:
            events = api2.payload.pop('events')

        case = Case(**api2.payload)

        # Set the default status to New
        case.status = CaseStatus.get_by_name(name="New")
        case.set_owner(owner_uuid)

        if isinstance(events, list) and len(events) > 0:
            uuids = []
            for event in events:
                e = Event.get_by_uuid(event)
                e.set_open()
                e.set_case(uuid=case.uuid)
                uuids.append(e.uuid)

                if 'include_related_events' in api2.payload and api2.payload['include_related_events']:
                    parent_uuid = e.uuid
                    related_events = Event.get_by_signature_and_status(signature=e.signature, status='New', all_events=True)
                    for related_event in related_events:
                        related_event.set_open()
                        related_event.set_case(uuid=case.uuid)
                        case_observables += Observable.get_by_event_uuid(related_event.uuid)
                        uuids.append(related_event.uuid)

                observables = Observable.get_by_event_uuid(event)
                case_observables += observables

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

        if 'approved_ips' in api2.payload and api2.payload['approved_ips'] is not None:
            api2.payload['approved_ips'] = api2.payload['approved_ips'].split('\n')

        if 'disallowed_password_keywords' in api2.payload and api2.payload['disallowed_password_keywords'] is not None:
            api2.payload['disallowed_password_keywords'] = api2.payload['disallowed_password_keywords'].split('\n')
             
        settings = Settings.load()
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

@ns_hunting_v2.route("/query")
class HuntingQuery(Resource):

    @token_required
    def post(self, current_user):

        search = Search(index='winlogbeat-*')
        search = search.query('query_string', query=api2.payload['query'])
        results = search.execute()
        return results.to_dict()

'''
TESTING NETWORK GRAPHS
@ns_observable_v2.route("/network")
class ObservablesNetwork(Resource):

    def get(self):

        search = Observable.search()

        search = search[0:]

        search.aggs.bucket('value', 'terms', field='value', size=1, order={'_count': 'desc'})
        search.aggs['value'].bucket('events', 'terms', field='events', size=25, order={'_count': 'desc'})

        #print(json.dumps(search.to_dict(),indent=4))

        results = search.execute()
        nodes = {}
        sources = []
        targets = []
        edges = {}

        #print(json.dumps(results.aggs.to_dict(), indent=4))
        for value in results.aggs.value:
            sources.append(value['key'])
            [targets.append(x['key']) for x in value.events.buckets]

        node_num = 1
        for s in sources:
            nodes[f"node{node_num}"] = { "name": s }
            node_num += 1

        for t in targets:
            nodes[f"node{node_num}"] = { "name": t }
            node_num += 1

        edge_num = 1
        for k in nodes:
            print(nodes[k]['name'])

        for x in sources:
            for t in targets:
                edges[f"edge{edge_num}"] = { 
                    "source": [k for k in nodes if nodes[k]['name'] == x][0], 
                    "target": [k for k in nodes if nodes[k]['name'] == t][0]
                }
                edge_num += 1

        return {'nodes': nodes, 'edges': edges}
'''
