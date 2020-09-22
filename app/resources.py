import os
import datetime
import jwt
import json
import base64
import hashlib
import cryptography
from zipfile import ZipFile
from flask import request, current_app, abort, make_response, send_from_directory, send_file, Blueprint
from flask_restx import Api, Resource, Namespace, fields, Model
from flask_socketio import emit
from werkzeug.utils import secure_filename
from werkzeug.datastructures import FileStorage
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy import desc, asc, func
from .models import User, UserGroup, db, RefreshToken, GlobalSettings, AuthTokenBlacklist, Role, Credential, Tag, Permission, Playbook, Event, Observable, DataType, Input, EventStatus, Agent, AgentRole, AgentGroup, Case, CaseTask, CaseHistory, CaseTemplate, CaseTemplateTask, CaseComment, CaseStatus, Plugin, PluginConfig
from .utils import token_required, user_has, _get_current_user, generate_token
from .schemas import *

api_v1 = Blueprint("api", __name__, url_prefix="/api/v1.0")

api = Api(api_v1)

# Namespaces
ns_user = api.namespace('User', description='User operations', path='/user')
ns_user_group = api.namespace(
    'UserGroup', description='User Group operations', path='/user_group')
ns_auth = api.namespace(
    'Auth', description='Authentication operations', path='/auth')
ns_role = api.namespace('Role', description='Role operations', path='/role')
ns_perms = api.namespace(
    'Permission', description='Permission operations', path='/permission')
ns_playbook = api.namespace(
    'Playbook', description='Playbook operations', path='/playbook')
ns_input = api.namespace(
    'Input', description='Input operations', path='/input')
ns_tag = api.namespace('Tag', description='Tag operations', path='/tag')
ns_event = api.namespace(
    'Event', description='Event operations', path='/event')
ns_case = api.namespace('Case', description='Case operations', path='/case')
ns_case_template = api.namespace(
    'CaseTemplate', description='Case Template operations', path='/case_template')
ns_case_template_task = api.namespace(
    'CaseTemplateTask', description='Case Template Task operations', path='/case_template_task')
ns_credential = api.namespace(
    'Credential', description='Credential operations', path='/credential')
ns_agent = api.namespace(
    'Agent', description='Agent operations', path='/agent')
ns_agent_group = api.namespace(
    'AgentGroup', description='Agent Group operations', path='/agent_group')
ns_plugin = api.namespace(
    'Plugin', description='Plugin operations', path='/plugin')
ns_plugin_config = api.namespace(
    'PluginConfig', description='Plugin Config operations', path='/plugin_config')
ns_test = api.namespace('Test', description='Test', path='/test')
ns_case_comment = api.namespace(
    'CaseComment', description='Case Comments', path='/case_comment')
ns_case_status = api.namespace(
    'CaseStatus', description='Case Status operations', path='/case_status')
ns_case_task = api.namespace(
    'CaseTask', description='Case Task operations', path='/case_task'
)
ns_settings = api.namespace(
    'GlobalSettings', description='Global settings for the Reflex system', path='/settings'
)


# Expect an API token
expect_token = api.parser()
expect_token.add_argument('Authorization', location='headers')

# Register all the models this is redundant when using api.model() but we don't use this
# TODO: Fix this so this hack isn't required, app factory is jacking this up
for model in schema_models:
    api.models[model.name] = model

upload_parser = api.parser()
upload_parser.add_argument('files', location='files',
                           type=FileStorage, required=True, action="append")

pager_parser = api.parser()
pager_parser.add_argument('page_size', location='args',
                          required=False, type=int)
pager_parser.add_argument('page', location='args', required=False, type=int)

def parse_tags(tags, organization_uuid):
    ''' Tags a list of supplied tags and creates Tag objects for each one '''
    _tags = []
    for t in tags:
        tag = Tag.query.filter_by(name=t, organization_uuid=organization_uuid, ).first()
        if not tag:
            tag = Tag(organization_uuid=organization_uuid, **{'name': t, 'color': '#fffff'})
            tag.create()
            _tags += [tag]
        else:
            _tags += [tag]
    return _tags


def create_observables(observables, organization_uuid):
    _observables = []
    _tags = []
    for o in observables:
        if 'tags' in o:
            tags = o.pop('tags')
            _tags = parse_tags(tags, organization_uuid)

        observable_type = DataType.query.filter_by(name=o['dataType'], organization_uuid=organization_uuid).first()
        if observable_type:
            o['dataType'] = observable_type
            observable = Observable(organization_uuid=organization_uuid, **o)
            observable.create()
            _observables += [observable]

            if len(_tags) > 0:
                observable.tags += _tags
                observable.save()
    return _observables


@ns_auth.route("/login")
class auth(Resource):

    @api.expect(mod_auth)
    @api.response(200, 'Success', mod_auth_success_token)
    @api.response(401, 'Incorrect username or password')
    def post(self):
        ''' Authenticate the user and return their api token '''

        # Check if the user exists
        user = User.query.filter_by(username=api.payload['username'], locked=False).first()
        if not user:
            ns_auth.abort(401, 'Incorrect username or password')

        # Check if the user has entered a good password
        if user.check_password(api.payload['password']):

            # Generate an access token
            _access_token = user.create_access_token()

            # Generate a refresh token
            _refresh_token = user.create_refresh_token(
                request.user_agent.string.encode('utf-8'))

            user.last_logon = datetime.datetime.utcnow()
            user.save()

            return {'access_token': _access_token, 'refresh_token': _refresh_token, 'user': user.uuid}, 200
        
        # If the user fails to logon more than 5 times
        # lock out their account, the counter will reset
        # when an admin unlocks them
        settings = GlobalSettings.query.first()

        if user.failed_logons == None:
            user.failed_logons = 0

        if user.failed_logons > settings.logon_password_attempts:
            user.locked = True
            user.save()
        else:
            user.failed_logons += 1
            user.save()

        ns_auth.abort(401, 'Incorrect username or password')


@ns_auth.route('/refresh')
class refresh(Resource):

    @ns_auth.expect(mod_refresh_token, validate=True)
    @ns_auth.response(200, 'Success', mod_auth_success_token)
    def post(self):
        ''' Refreshes a users access token if their refresh token is still valid '''
        if 'refresh_token' not in api.payload:
            ns_auth.abort(400, 'Invalid request. A refresh token is required.')

        _refresh_token = api.payload['refresh_token']
        try:
            payload = jwt.decode(
                _refresh_token, current_app.config['SECRET_KEY'])

            refresh_token = RefreshToken.query.filter_by(
                user_uuid=payload['uuid'], refresh_token=_refresh_token).first()

            if not refresh_token:
                ns_auth.abort(401, 'Invalid token issuer.')

            # Generate a new pair
            user = User.query.filter_by(uuid=payload['uuid']).first()
            if user:
                access_token = user.create_access_token()
                refresh_token = user.create_refresh_token(
                    request.user_agent.string.encode('utf-8'))
                return {'access_token': access_token, 'refresh_token': refresh_token}, 200
            else:
                return {'message': 'Unauthorized.'}, 401

        except jwt.ExpiredSignatureError as e:
            ns_auth.abort(401, 'Refresh token has expired.')
        except (jwt.DecodeError, jwt.InvalidTokenError)as e:
            ns_auth.abort(401, 'Invalid refresh token.')
        except Exception as e:
            ns_auth.abort(401, 'Unknown token error')


@ns_auth.route('/logout')
class logout(Resource):

    @api.doc(security="Bearer")
    @api.response(200, 'Successfully logged out.')
    @api.response(401, 'Not logged in.')
    @token_required
    def get(self, current_user):
        ''' Logs the user out of their session and blacklists the token so it can't be used again '''
        try:
            auth_header = request.headers.get('Authorization')
            access_token = auth_header.split(' ')[1]
            b_token = AuthTokenBlacklist(auth_token=access_token)
            b_token.create()
            return {'message': 'Successfully logged out.'}, 200
        except:
            return {'message': 'Not logged in.'}, 401

        ns_auth.abort(401, 'Not logged in.')


@ns_user.route("/me")
class Whoami(Resource):

    @api.doc(security="Bearer")
    @api.marshal_with(mod_user_self)
    @token_required
    def get(self, current_user):
        ''' Returns all the details about the current user '''
        current_user = _get_current_user()
        return current_user


user_parser = api.parser()
user_parser.add_argument('username', location='args', required=False)


@ns_user.route("")
class UserList(Resource):

    @api.doc(security="Bearer")
    @api.marshal_with(mod_user_full, as_list=True)
    @api.expect(user_parser)
    @token_required
    @user_has('view_users')
    def get(self, current_user):
        ''' Returns a list of users '''

        args = user_parser.parse_args()

        if args['username']:
            users = User.query.filter(
                User.username.like(args['username']+"%"),User.deleted.like(False), User.organization_uuid.equals(current_user().organization_uuid)).all()
        else:
            users = User.query.filter_by(deleted=False, organization_uuid=current_user().organization_uuid).all()
        return users

    # TODO: Add a lock to this so only the Admin users and those with 'add_user' permission can do this
    @api.doc(security="Bearer")
    @api.expect(mod_user_create)
    @api.marshal_with(mod_user_create_success)
    @api.response('409', 'User already exists.')
    @api.response('200', "Successfully created the user.")
    @token_required
    @user_has('add_user')
    def post(self, current_user):
        ''' Creates a new users '''

        user = User.query.filter_by(email=api.payload['email'], organization_uuid=current_user().organization_uuid).first()

        if user:
            ns_user.abort(409, "User with this email already exists.")
        
        user = User.query.filter_by(username=api.payload['username'], organization_uuid=current_user().organization_uuid).first()
    
        if user:
            ns_user.abort(409, "User with this username already exists.")

        if not user:
            user = User(organization_uuid=current_user().organization_uuid, **api.payload)
            user.create()
            return {'message': 'Successfully created the user.', 'user': user}
        else:
            ns_user.abort(409, "User already exists.")


@ns_user.route("/<uuid>/unlock")
class UnlockUser(Resource):

    @api.doc(security="Bearer")
    @api.marshal_with(mod_user_full)
    @token_required
    @user_has('unlock_user')
    def put(self, uuid, current_user):
        ''' Unlocks a user and resets their failed logons back to 0 '''

        user = User.query.filter_by(uuid=uuid, organization_uuid=current_user().organization_uuid).first()
        if user:
            user.locked = False
            user.failed_logons = 0
            user.save()
            return user
        else:
            ns_user.abort(404, 'User not found.')


@ns_user.route("/<uuid>")
class UserDetails(Resource):

    @api.doc(security="Bearer")
    @api.marshal_with(mod_user_full)
    @token_required
    @user_has('view_users')
    def get(self, uuid, current_user):
        ''' Returns information about a user '''
        user = User.query.filter_by(uuid=uuid, organization_uuid=current_user().organization_uuid).first()
        if user:
            return user
        else:
            ns_user.abort(404, 'User not found.')

    @api.doc(security="Bearer")
    @api.expect(mod_user_create)
    @api.marshal_with(mod_user_full)
    @token_required
    @user_has('update_user')
    def put(self, uuid, current_user):
        ''' Updates information for a user '''

        user = User.query.filter_by(uuid=uuid, organization_uuid=current_user().organization_uuid).first()
        if user:
            if 'username' in api.payload:
                target_user = User.query.filter_by(username=api.payload['username'], organization_uuid=current_user().organization_uuid).first()
                if target_user:
                    if target_user.uuid == uuid:
                        del api.payload['username']
                    else:
                        ns_user.abort(409, 'Username already taken.')

            if 'email' in api.payload:
                target_user = User.query.filter_by(email=api.payload['email'], organization_uuid=current_user().organization_uuid).first()
                if target_user:
                    if target_user.uuid == uuid:
                        del api.payload['email']
                    else:
                        ns_user.abort(409, 'Email already taken.')

            user.update(api.payload)
            return user
        else:
            ns_user.abort(404, 'User not found.')

    @api.doc(security="Bearer")
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
        user = User.query.filter_by(uuid=uuid, organization_uuid=current_user().organization_uuid).first()
        if user:
            if current_user().uuid == user.uuid:
                ns_user.abort(403, 'User can not delete themself.')
            else:
                user.deleted = True
                user.save()
                return {'message': 'User successfully deleted.'}
        else:
            ns_user.abort(404, 'User not found.')


@ns_perms.route("")
class PermissionList(Resource):

    @api.marshal_with(mod_permission_list)
    def get(self):
        ''' Gets a list of all the permission sets '''
        return Permission.query.filter_by(organization_uuid=current_user().organization_uuid).all()

    @api.expect(mod_permission_full)
    @api.response('200', 'Successfully created permission set.')
    def post(self):
        ''' Creates a new permission set '''
        perm = Permission(organization_uuid=current_user().organization_uuid, **api.payload)
        perm.create()
        return {'message': 'Successfully created permission set.', 'uuid': perm.uuid}


@ns_perms.route("/<uuid>")
class PermissionDetails(Resource):

    @api.marshal_with(mod_permission_list)
    def get(self, uuid):
        ''' Gets the permissions based '''
        perm = Permission.query.filter_by(uuid=uuid, organization_uuid=current_user().organization_uuid).first()
        if perm:
            return perm
        else:
            ns_perms.abort(404, 'Permission set not found.')

    @api.doc(security="Bearer")
    @api.expect(mod_permission_full)
    @api.marshal_with(mod_permission_list)
    @token_required
    @user_has('set_role_permissions')
    def put(self, uuid, current_user):
        ''' Updates the permission set '''
        perm = Permission.query.filter_by(uuid=uuid, organization_uuid=current_user().organization_uuid).first()
        if perm:
            perm.update(api.payload)
            return perm
        else:
            ns_perms.abort(404, 'Permission set not found.')

    @api.doc(security="Bearer")
    @token_required
    @user_has('delete_role')
    def delete(self, uuid, current_user):
        ''' Removes the permission set '''
        perm = Permission.query.filter_by(uuid=uuid, organization_uuid=current_user().organization_uuid).first()
        if perm:
            if(len(perm.roles) > 0):
                ns_perms.abort(
                    400, 'Cannot delete a permission set attached to an active Role.')
            else:
                perm.delete()
                return {'message': 'Successfully deleted the Permission set.'}
            return perm
        else:
            ns_perms.abort(404, 'Permission set not found.')
        return


@ns_case.route("/<uuid>/add_observables/_bulk")
class CaseBulkAddObservables(Resource):

    @api.doc(security="Bearer")
    @api.expect(mod_bulk_add_observables)
    @api.marshal_with(mod_case_observables)
    @api.response(200, 'Success')
    # @token_required
    # @user_has('update_case')
    def post(self, uuid):
        ''' 
        Adds a collection of observables to a Case 

        Expects a list of observables using the Observable model.  Note: Duplicate observables are ignored

        '''
        # Fetch the case via its UUID
        case = Case.get_or_404(uuid)

        # Remove observables that are already in the case
        observable_values = [
            observable.value for observable in case.observables]
        observables_list = [observable for observable in api.payload['observables']
                            if observable['value'] not in observable_values]

        # Process all the observables in the API call
        observables = create_observables(observables_list, current_user().organization_uuid)

        # Add the observables to the case
        if(len(case.observables) == 0):
            case.observables = observables
        else:
            case.observables += observables
        case.save()

        case.add_history('%s new observable(s) added' % (len(observables)))

        return case


@ns_case.route("")
class CaseList(Resource):

    @api.doc(security="Bearer")
    @api.marshal_with(mod_case_full, as_list=True)
    @api.expect(pager_parser)
    @token_required
    @user_has('view_cases')
    def get(self, current_user):
        ''' Returns a list of case '''

        args = pager_parser.parse_args()
        if args:
            cases = Case.query.paginate(
                args['page'], args['page_size'], False).items
        else:
            cases = Case.query.filter_by(organization_uuid=current_user().organization_uuid).all()

        return cases

    @api.doc(security="Bearer")
    @api.expect(mod_case_create)
    @api.response('409', 'Case already exists.')
    @api.response('200', "Successfully created the case.")
    #@token_required
    #@user_has('create_case')
    def post(self):
        ''' Creates a new case '''

        _tags = []
        event_observables = []
        case_template_uuid = None

        if 'case_template_uuid' in api.payload:
            case_template_uuid = api.payload.pop('case_template_uuid')

        if 'tags' in api.payload:
            tags = api.payload.pop('tags')
            _tags = parse_tags(tags, current_user().organization_uuid)

        if 'owner' in api.payload:
            owner = api.payload.pop('owner')
            user = User.query.filter_by(uuid=owner).first()
            if user:
                api.payload['owner'] = user

        if 'observables' in api.payload:
            observables = api.payload.pop('observables')
            api.payload['observables'] = []
            for uuid in observables:
                observable = Observable.query.filter_by(uuid=uuid, organization_uuid=current_user().organization_uuid).first()
                if observable:
                    api.payload['observables'].append(observable)

        if 'events' in api.payload:
            api.payload['observables'] = []
            events = api.payload.pop('events')
            api.payload['events'] = []
            observable_collection = {}

            # Pull all the observables out of the events
            # so they can be added to the case
            for uuid in events:
                event = Event.query.filter_by(uuid=uuid, organization_uuid=current_user().organization_uuid).first()
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

        case = Case(organization_uuid=current_user().organization_uuid, **api.payload)
        case.create()

        if len(_tags) > 0:
            case.tags += _tags
            case.save()

        # Set the default status to New
        case_status = CaseStatus.query.filter_by(name="New").first()
        case.status = case_status
        case.save()

        
        # If the user selected a case template, take the template items
        # and copy them over to the case
        if case_template_uuid:
            case_template = CaseTemplate.query.filter_by(
                uuid=case_template_uuid).first()

            # Append the default tags
            for tag in case_template.tags:

                # If the tag does not already exist
                if tag not in case.tags:
                    case.tags.append(tag)

            # Append the default tasks
            for task in case_template.tasks:
                case_task = CaseTask(title=task.title, description=task.description,
                                     order=task.order, owner=task.owner, group=task.group,
                                     from_template=True)
                case.tasks.append(case_task)

            # Set the default severity
            case.severity = case_template.severity
            case.tlp = case_template.tlp
            case.save()


        for event in case.events:
            event.status = EventStatus.query.filter_by(name='Imported').first()
            event.save()

        return {'message': 'Successfully created the case.', 'uuid': case.uuid}


@ns_case.route("/<uuid>")
class CaseDetails(Resource):

    @api.doc(security="Bearer")
    @api.marshal_with(mod_case_full)
    @api.response('200', 'Success')
    @api.response('404', 'Case not found')
    @token_required
    @user_has('view_cases')
    def get(self, uuid, current_user):
        ''' Returns information about a case '''
        case = Case.query.filter_by(uuid=uuid, organization_uuid=current_user().organization_uuid).first()
        if case:
            return case
        else:
            ns_case.abort(404, 'Case not found.')

    @api.doc(security="Bearer")
    @api.expect(mod_case_create)
    @api.marshal_with(mod_case_full)
    @token_required
    @user_has('update_case')
    def put(self, uuid, current_user):
        ''' Updates information for a case '''
        case = Case.query.filter_by(uuid=uuid, organization_uuid=current_user().organization_uuid).first()
        if case:
            for f in ['severity', 'tlp', 'status_uuid', 'owner', 'description', 'owner_uuid']:
                value = ""
                message = None

                # TODO: handle notifications here, asynchronous of course to not block this processing
                if f in api.payload:
                    if f == 'status_uuid':
                        status = CaseStatus.query.filter_by(
                            uuid=api.payload['status_uuid']).first()
                        value = status.name
                        f = 'status'

                    elif f == 'severity':
                        value = {1: 'Low', 2: 'Medium', 3: 'High',
                                 4: 'Critical'}[api.payload[f]]

                    elif f == 'description':
                        message = '**Description** updated'

                    elif f == 'owner_uuid':
                        owner = User.query.filter_by(
                            uuid=api.payload['owner_uuid']).first()
                        value = owner.username
                        message = 'Case assigned to **{}**'.format(
                            owner.username)

                    if message:
                        case.add_history(message=message)
                    else:
                        case.add_history(
                            message="**{}** changed to **{}**".format(f.title(), value))
            case.update(api.payload)
            return case
        else:
            ns_case.abort(404, 'Case not found.')

    @api.doc(security="Bearer")
    @token_required
    @user_has('delete_case')
    def delete(self, uuid, current_user):
        ''' Deletes a case '''
        case = Case.query.filter_by(uuid=uuid, organization_uuid=current_user().organization_uuid).first()
        if case:
            case.delete()
            return {'message': 'Sucessfully deleted case.'}


@ns_case_task.route("")
class CaseTaskList(Resource):

    @api.doc(security="Bearer")
    @api.marshal_with(mod_case_task_full, as_list=True)
    @token_required
    @user_has('view_case_tasks')
    def get(self, current_user):
        ''' Returns a list of case_task '''
        return CaseTask.query.filter_by(organization_uuid=current_user().organization_uuid).all()

    @api.doc(security="Bearer")
    @api.expect(mod_case_task_create)
    @api.marshal_with(mod_case_task_full)
    @api.response('409', 'Case Task already exists.')
    @api.response('200', "Successfully created the case task.")
    #@token_required
    #@user_has('create_case_task')
    def post(self):
        
        ''' Creates a new case_task '''

        case_task = CaseTask.query.filter_by(
            title=api.payload['title'], case_uuid=api.payload['case_uuid']).first()
        if not case_task:

            case_task = CaseTask(organization_uuid=current_user().organization_uuid, **api.payload)
            case_task.create()

            case = Case.query.filter_by(uuid=api.payload['case_uuid']).first()
            case.add_history("New task added")

            return case_task
        else:
            ns_case_task.abort(
                409, 'Case Task already exists.')


@ns_case_task.route("/<uuid>")
class CaseTaskDetails(Resource):

    @api.doc(security="Bearer")
    @api.marshal_with(mod_case_task_full)
    @api.response('200', 'Success')
    @api.response('404', 'Case Task not found')
    @token_required
    @user_has('view_case_tasks')
    def get(self, uuid, current_user):
        ''' Returns information about a case task '''
        case_task = CaseTask.query.filter_by(
            uuid=uuid, organization_uuid=current_user().organization_uuid).first()
        if case_task:
            return case_task
        else:
            ns_case_task.abort(404, 'Case Task not found.')

    @api.doc(security="Bearer")
    @api.expect(mod_case_task_create)
    @api.marshal_with(mod_case_task_full)
    @token_required
    @user_has('update_case_task')
    def put(self, uuid, current_user):
        ''' Updates information for a case_task '''
        case_task = CaseTask.query.filter_by(
            uuid=uuid, organization_uuid=current_user().organization_uuid).first()
        if case_task:
            if 'name' in api.payload and CaseTask.query.filter_by(title=api.payload['title'], case_uuid=api.payload['case_uuid']).first():
                ns_case_task.abort(
                    409, 'Case Task name already exists.')
            else:
                case_task.update(api.payload)
                return case_task
        else:
            ns_case_task.abort(404, 'Case Task not found.')

    @api.doc(security="Bearer")
    @token_required
    @user_has('delete_case_task')
    def delete(self, uuid, current_user):
        ''' Deletes a case_task '''
        case_task = CaseTask.query.filter_by(
            uuid=uuid, organization_uuid=current_user().organization_uuid).first()
        if case_task:
            case_task.delete()
            return {'message': 'Sucessfully deleted case task.'}


case_template_parser = api.parser()
case_template_parser.add_argument('title', location='args', required=False)


@ns_case_template.route("")
class CaseTemplateList(Resource):

    @api.doc(security="Bearer")
    @api.marshal_with(mod_case_template_full, as_list=True)
    @api.expect(case_template_parser)
    @token_required
    @user_has('view_case_templates')
    def get(self, current_user):
        ''' Returns a list of case_template '''

        args = case_template_parser.parse_args()

        if args['title']:
            case_template = CaseTemplate.query.filter(
                CaseTemplate.title.like(args['title']+"%")).all()
        else:
            case_template = CaseTemplate.query.filter_by(organization_uuid=current_user().organization_uuid).all()

        return case_template

    @api.doc(security="Bearer")
    @api.expect(mod_case_template_create)
    @api.response('409', 'Case Template already exists.')
    @api.response('200', "Successfully created the case_template.")
    @api.marshal_with(mod_case_template_full)
    @token_required
    @user_has('create_case_template')
    def post(self, current_user):

        # Check to see if the case template already exists and
        # return an error indicating as such
        case_template = CaseTemplate.query.filter_by(
            title=api.payload['title']).first()
        if case_template:
            ns_case_template.abort(409, 'Case Template already exists.')
        else:
            _tags = []
            ''' Creates a new case_template template '''
            if 'tags' in api.payload:
                tags = api.payload.pop('tags')
                _tags = parse_tags(tags, current_user().organization_uuid)

            '''if 'owner' in api.payload:
                owner = api.payload.pop('owner')
                user = User.query.filter_by(uuid=owner).first()
                if user:
                    api.payload['owner'] = user'''

            if 'tasks' in api.payload:
                _tasks = []
                tasks = api.payload.pop('tasks')
                for _task in tasks:
                    task = CaseTemplateTask(**_task)
                    _tasks.append(task)
            api.payload['tasks'] = _tasks

            case_template = CaseTemplate(organization_uuid=current_user().organization_uuid, **api.payload)
            case_template.create()

            if len(_tags) > 0:
                case_template.tags += _tags
                case_template.save()

            # Set the default status to New
            case_template_status = CaseStatus.query.filter_by(
                name="New").first()
            case_template.status = case_template_status
            case_template.save()

            return case_template


@ns_case_template.route("/<uuid>/update-tasks")
class AddTasksToCaseTemplate(Resource):

    @api.doc(security="Bearer")
    @api.response('409', 'Task already assigned to this Case Template')
    @api.response('404', 'Case Template not found.')
    @api.response('404', 'Task not found.')
    @api.response('207', 'Tasks added to Case Template.')
    @api.expect(mod_add_tasks_to_case)
    @token_required
    @user_has('update_case_templates')
    def put(self, uuid, current_user):
        ''' Adds a user to a specified Role '''

        _tasks = []
        response = {
            'results': [],
            'success': True
        }
        if 'tasks' in api.payload:
            tasks = api.payload.pop('tasks')
            for task_uuid in tasks:
                task = CaseTemplateTask.query.filter_by(uuid=task_uuid).first()
                if task:
                    _tasks.append(task)
                    response['results'].append(
                        {'reference': task_uuid, 'message': 'Task successfully added.'})
                else:
                    response['results'].append(
                        {'reference': task_uuid, 'message': 'Task not found.'})
                    response['success'] = False

        template = CaseTemplate.query.filter_by(uuid=uuid, organization_uuid=current_user().organization_uuid).first()
        if template:
            template.tasks = _tasks
            template.save()
            return response, 207
        else:
            ns_case_template.abort(404, 'Case Template not found.')


@ns_case_template.route("/<uuid>")
class CaseTemplateDetails(Resource):

    @api.doc(security="Bearer")
    @api.marshal_with(mod_case_template_full)
    @api.response('200', 'Success')
    @api.response('404', 'Case Template not found')
    @token_required
    @user_has('view_case_templates')
    def get(self, uuid):
        ''' Returns information about a case_template '''
        case_template = CaseTemplate.query.filter_by(uuid=uuid, organization_uuid=current_user().organization_uuid).first()
        if case_template:
            return case_template
        else:
            ns_case_template.abort(404, 'Case Template not found.')

    @api.doc(security="Bearer")
    @api.expect(mod_case_template_create)
    @api.marshal_with(mod_case_template_full)
    @token_required
    @user_has('update_case_template')
    def put(self, uuid):
        ''' Updates information for a case_template '''
        case_template = CaseTemplate.query.filter_by(uuid=uuid, organization_uuid=current_user().organization_uuid).first()
        if case_template:
            if 'name' in api.payload and CaseTemplate.query.filter_by(name=api.payload['name']).first():
                ns_case_template.abort(
                    409, 'Case Template name already exists.')
            else:
                case_template.update(api.payload)
                return case_template
        else:
            ns_case_template.abort(404, 'Case Template not found.')

    @api.doc(security="Bearer")
    @token_required
    @user_has('delete_case_template')
    def delete(self, uuid):
        ''' Deletes a case_template '''
        case_template = CaseTemplate.query.filter_by(uuid=uuid, organization_uuid=current_user().organization_uuid).first()
        if case_template:
            case_template.delete()
            return {'message': 'Sucessfully deleted case_template.'}


@ns_case_template_task.route("")
class CaseTemplateTaskList(Resource):

    @api.doc(security="Bearer")
    @api.marshal_with(mod_case_template_task_full, as_list=True)
    @token_required
    @user_has('view_case_template_tasks')
    def get(self, current_user):
        ''' Returns a list of case_template_task '''
        return CaseTemplateTask.query.filter_by(organization_uuid=current_user().organization_uuid).all()

    @api.doc(security="Bearer")
    @api.expect(mod_case_template_task_create)
    @api.response('409', 'CaseTemplateTask already exists.')
    @api.response('200', "Successfully created the case_template_task.")
    @token_required
    @user_has('create_case_template_task')
    def post(self, current_user):
        _tags = []
        ''' Creates a new case_template_task '''
        case_template_task = CaseTemplateTask.query.filter_by(
            title=api.payload['title'], case_template_uuid=api.payload['case_template_uuid']).first()
        if not case_template_task:

            case_template_task = CaseTemplateTask(organization_uuid=current_user().organization_uuid, **api.payload)
            case_template_task.create()

            if len(_tags) > 0:
                case_template_task.tags += _tags
                case_template_task.save()

            return {'message': 'Successfully created the case_template_task.'}
        else:
            ns_case_template_task.abort(
                409, 'CaseTemplateTask already exists.')


@ns_case_template_task.route("/<uuid>")
class CaseTemplateTaskDetails(Resource):

    @api.doc(security="Bearer")
    @api.marshal_with(mod_case_template_task_full)
    @api.response('200', 'Success')
    @api.response('404', 'CaseTemplateTask not found')
    @token_required
    @user_has('view_case_template_tasks')
    def get(self, uuid, current_user):
        ''' Returns information about a case_template_task '''
        case_template_task = CaseTemplateTask.query.filter_by(
            uuid=uuid, organization_uuid=current_user().organization_uuid).first()
        if case_template_task:
            return case_template_task
        else:
            ns_case_template_task.abort(404, 'Case Template Task not found.')

    @api.doc(security="Bearer")
    @api.expect(mod_case_template_task_create)
    @api.marshal_with(mod_case_template_task_full)
    @token_required
    @user_has('update_case_template_task')
    def put(self, uuid, current_user):
        ''' Updates information for a case_template_task '''
        case_template_task = CaseTemplateTask.query.filter_by(
            uuid=uuid, organization_uuid=current_user().organization_uuid).first()
        if case_template_task:
            if 'name' in api.payload and CaseTemplateTask.query.filter_by(title=api.payload['title']).first():
                ns_case_template_task.abort(
                    409, 'Case Template Task name already exists.')
            else:
                case_template_task.update(api.payload)
                return case_template_task
        else:
            ns_case_template_task.abort(404, 'Case Template Task not found.')

    @api.doc(security="Bearer")
    @token_required
    @user_has('delete_case_template_task')
    def delete(self, uuid, current_user):
        ''' Deletes a case_template_task '''
        case_template_task = CaseTemplateTask.query.filter_by(
            uuid=uuid, organization_uuid=current_user().organization_uuid).first()
        if case_template_task:
            case_template_task.delete()
            return {'message': 'Sucessfully deleted case_template_task.'}


@ns_case_comment.route("")
class CaseCommentList(Resource):

    @api.doc(security="Bearer")
    @api.marshal_with(mod_comment, as_list=True)
    @token_required
    @user_has('view_case_comments')
    def get(self, current_user):
        ''' Returns a list of comments '''
        return CaseComment.query.filter_by(organization_uuid=current_user().organization_uuid).all()

    @api.doc(security="Bearer")
    @api.expect(mod_comment_create)
    @api.response(200, 'AMAZING', mod_comment)
    @api.marshal_with(mod_comment)
    @token_required
    @user_has('create_case_comment')
    def post(self, current_user):
        _tags = []
        ''' Creates a new comment '''
        case_comment = CaseComment(organization_uuid=current_user().organization_uuid, **api.payload)
        case_comment.create()

        case = Case.query.filter_by(uuid=api.payload['case_uuid']).first()
        case.add_history(message="Commented added to case")
        return case_comment


@ns_case_comment.route("/<uuid>")
class CaseCommentDetails(Resource):

    @api.doc(security="Bearer")
    @api.marshal_with(mod_comment)
    @api.response('200', 'Success')
    @api.response('404', 'Comment not found')
    @token_required
    @user_has('view_case_comments')
    def get(self, uuid, current_user):
        ''' Returns information about a comment '''
        case_comment = CaseComment.query.filter_by(uuid=uuid, organization_uuid=current_user().organization_uuid).first()
        if case_comment:
            return case_comment
        else:
            ns_case_comment.abort(404, 'Comment not found.')

    @api.doc(security="Bearer")
    @api.expect(mod_comment_create)
    @api.marshal_with(mod_comment)
    @token_required
    @user_has('update_case_comment')
    def put(self, uuid, current_user):
        ''' Updates information for a comment '''
        case_comment = CaseComment.query.filter_by(uuid=uuid, organization_uuid=current_user().organization_uuid).first()
        if case_comment:
            case_comment.update(api.payload)
            return case_comment
        else:
            ns_case_comment.abort(404, 'Comment not found.')

    @api.doc(security="Bearer")
    @token_required
    @user_has('delete_case_comment')
    def delete(self, uuid, current_user):
        ''' Deletes a comment '''
        case_comment = CaseComment.query.filter_by(uuid=uuid, organization_uuid=current_user().organization_uuid).first()
        if case_comment:
            case_comment.delete()
            return {'message': 'Sucessfully deleted comment.'}


@ns_case_status.route("")
class CaseStatusList(Resource):

    @api.doc(security="Bearer")
    @api.marshal_with(mod_case_status_list, as_list=True)
    @token_required
    def get(self, current_user):
        ''' Returns a list of case_statuss '''
        return CaseStatus.query.filter_by(organization_uuid=current_user().organization_uuid).all()

    @api.doc(security="Bearer")
    @api.expect(mod_case_status_create)
    @api.response('409', 'Case Status already exists.')
    @api.response('200', 'Successfully create the CaseStatus.')
    @token_required
    @user_has('add_case_status')
    def post(self, current_user):
        ''' Creates a new Case Status '''
        case_status = CaseStatus.query.filter_by(
            name=api.payload['name']).first()

        if not case_status:
            case_status = CaseStatus(organization_uuid=current_user().organization_uuid, **api.payload)
            case_status.create()
        else:
            ns_case_status.abort(409, 'Case Status already exists.')
        return {'message': 'Successfully created the Case Status.'}


@ns_case_status.route("/<uuid>")
class CaseStatusDetails(Resource):

    @api.doc(security="Bearer")
    @api.marshal_with(mod_case_status_list)
    @token_required
    def get(self, uuid, current_user):
        ''' Returns information about an CaseStatus '''
        case_status = CaseStatus.query.filter_by(uuid=uuid, organization_uuid=current_user().organization_uuid).first()
        if case_status:
            return case_status
        else:
            ns_case_status.abort(404, 'Case Status not found.')

    @api.doc(security="Bearer")
    @api.expect(mod_case_status_create)
    @api.marshal_with(mod_case_status_list)
    @token_required
    @user_has('update_case_status')
    def put(self, uuid, current_user):
        ''' Updates information for an Case Status '''
        case_status = CaseStatus.query.filter_by(uuid=uuid, organization_uuid=current_user().organization_uuid).first()
        if case_status:
            if 'name' in api.payload and CaseStatus.query.filter_by(name=api.payload['name']).first():
                ns_case_status.abort(409, 'Case Status name already exists.')
            else:
                case_status.update(api.payload)
                return case_status
        else:
            ns_case_status.abort(404, 'Case Status not found.')

    @api.doc(security="Bearer")
    @token_required
    @user_has('delete_case_status')
    def delete(self, uuid, current_user):
        ''' Deletes an CaseStatus '''
        case_status = CaseStatus.query.filter_by(uuid=uuid, organization_uuid=current_user().organization_uuid).first()
        if case_status:
            case_status.delete()
            return {'message': 'Sucessfully deleted Case Status.'}


@ns_playbook.route("")
class PlaybookList(Resource):

    @api.doc(security="Bearer")
    @api.marshal_with(mod_playbook_list, as_list=True)
    @token_required
    @user_has('view_playbooks')
    def get(self, current_user):
        ''' Returns a list of playbook '''
        return Playbook.query.filter_by(organization_uuid=current_user().organization_uuid).all()

    @api.doc(security="Bearer")
    @api.expect(mod_playbook_create)
    @api.response('409', 'Playbook already exists.')
    @api.response('200', "Successfully created the playbook.")
    @token_required
    @user_has('create_playbook')
    def post(self, current_user):
        _tags = []
        ''' Creates a new playbook '''
        playbook = Playbook.query.filter_by(name=api.payload['name']).first()
        if not playbook:
            if 'tags' in api.payload:
                tags = api.payload.pop('tags')
                _tags = parse_tags(tags, current_user().organization_uuid)

            playbook = Playbook(organization_uuid=current_user().organization_uuid, **api.payload)
            playbook.create()

            if len(_tags) > 0:
                playbook.tags += _tags
                playbook.save()

            return {'message': 'Successfully created the playbook.'}
        else:
            ns_playbook.abort(409, 'Playbook already exists.')


@ns_playbook.route("/<uuid>")
class PlaybookDetails(Resource):

    @api.doc(security="Bearer")
    @api.marshal_with(mod_playbook_full)
    @api.response('200', 'Success')
    @api.response('404', 'Playbook not found')
    @token_required
    @user_has('view_playbooks')
    def get(self, uuid):
        ''' Returns information about a playbook '''
        playbook = Playbook.query.filter_by(uuid=uuid, organization_uuid=current_user().organization_uuid).first()
        if playbook:
            return playbook
        else:
            ns_playbook.abort(404, 'Playbook not found.')

    @api.doc(security="Bearer")
    @api.expect(mod_playbook_create)
    @api.marshal_with(mod_playbook_full)
    @token_required
    @user_has('update_playbook')
    def put(self, uuid):
        ''' Updates information for a playbook '''
        playbook = Playbook.query.filter_by(uuid=uuid, organization_uuid=current_user().organization_uuid).first()
        if playbook:
            if 'name' in api.payload and Playbook.query.filter_by(name=api.payload['name']).first():
                ns_playbook.abort(409, 'Playbook name already exists.')
            else:
                playbook.update(api.payload)
                return playbook
        else:
            ns_playbook.abort(404, 'Playbook not found.')

    @api.doc(security="Bearer")
    @token_required
    @user_has('delete_playbook')
    def delete(self, uuid):
        ''' Deletes a playbook '''
        playbook = Playbook.query.filter_by(uuid=uuid, organization_uuid=current_user().organization_uuid).first()
        if playbook:
            playbook.delete()
            return {'message': 'Sucessfully deleted playbook.'}


@ns_playbook.route('/<uuid>/remove_tag/<name>')
class DeletePlaybookTag(Resource):

    @api.doc(security="Bearer")
    @token_required
    @user_has('remove_tag_from_playbook')
    def delete(self, uuid, name, current_user):
        ''' Removes a tag from an playbook '''
        tag = Tag.query.filter_by(name=name).first()
        if not tag:
            ns_playbook.abort(404, 'Tag not found.')
        playbook = Playbook.query.filter_by(uuid=uuid, organization_uuid=current_user().organization_uuid).first()
        if playbook:
            playbook.tags.remove(tag)
            playbook.save()
        else:
            ns_playbook.abort(404, 'Playbook not found.')
        return {'message': 'Successfully rmeoved tag from playbook.'}


@ns_playbook.route("/<uuid>/tag/<name>")
class TagPlaybook(Resource):

    @api.doc(security="Bearer")
    @token_required
    @user_has('add_tag_to_playbook')
    def post(self, uuid, name, current_user):
        ''' Adds a tag to an playbook '''
        tag = Tag.query.filter_by(name=name).first()
        if not tag:
            tag = Tag(**{'name': name, 'color': '#fffff'})
            tag.create()

        playbook = Playbook.query.filter_by(uuid=uuid, organization_uuid=current_user().organization_uuid).first()
        if playbook:
            playbook.tags += [tag]
            playbook.save()
        else:
            ns_event.abort(404, 'Playbook not found.')
        return {'message': 'Successfully added tag to playbook.'}


@ns_playbook.route("/<uuid>/bulktag")
class BulkTagPlaybook(Resource):

    @api.doc(security="Bearer")
    @api.expect(mod_bulk_tag)
    @token_required
    @user_has('add_tag_to_playbook')
    def post(self, uuid, current_user):
        ''' Adds a tag to an playbook '''
        _tags = []
        if 'tags' in api.payload:
            tags = api.payload['tags']
            for t in tags:
                tag = Tag.query.filter_by(name=t).first()
                if not tag:
                    tag = Tag(**{'name': t, 'color': '#fffff'})
                    tag.create()
                    _tags += [tag]
                else:
                    _tags += [tag]

        playbook = Playbook.query.filter_by(uuid=uuid, organization_uuid=current_user().organization_uuid).first()
        if playbook:
            playbook.tags += _tags
            playbook.save()
        else:
            ns_playbook.abort(404, 'Playbook not found.')
        return {'message': 'Successfully added tag to playbook.'}


@ns_input.route("")
class InputList(Resource):

    @api.doc(security="Bearer")
    @api.marshal_with(mod_input_list, as_list=True)
    @token_required
    @user_has('view_inputs')
    def get(self, current_user):
        ''' Returns a list of inputs '''
        return Input.query.filter_by(organization_uuid=current_user().organization_uuid).all()

    @api.doc(security="Bearer")
    @api.expect(mod_input_create)
    @api.response('409', 'Input already exists.')
    @api.response('200', 'Successfully create the input.')
    @token_required
    @user_has('add_input')
    def post(self, current_user):
        ''' Creates a new input '''
        _tags = []
        inp = Input.query.filter_by(name=api.payload['name']).first()

        if not inp:

            if 'credential' in api.payload:
                cred_uuid = api.payload.pop('credential')
                cred = Credential.query.filter_by(uuid=cred_uuid).first()
                api.payload['credential'] = cred

            if 'config' in api.payload:
                try:
                    api.payload['config'] = json.loads(base64.b64decode(
                        api.payload['config']).decode('ascii').strip())
                except Exception:
                    ns_input.abort(
                        400, 'Invalid JSON configuration, check your syntax')

            if 'field_mapping' in api.payload:
                try:
                    api.payload['field_mapping'] = json.loads(base64.b64decode(
                        api.payload['field_mapping']).decode('ascii').strip())
                except Exception:
                    ns_input.abort(
                        400, 'Invalid JSON in field_mapping, check your syntax')

            if 'tags' in api.payload:
                tags = api.payload.pop('tags')
                _tags = parse_tags(tags, current_user().organization_uuid)

            inp = Input(organization_uuid=current_user().organization_uuid, **api.payload)
            inp.create()

            if len(_tags) > 0:
                inp.tags += _tags
                inp.save()
        else:
            ns_input.abort(409, 'Input already exists.')
        return {'message': 'Successfully created the input.'}


@ns_input.route("/<uuid>")
class InputDetails(Resource):

    @api.doc(security="Bearer")
    @api.marshal_with(mod_input_list)
    @token_required
    @user_has('view_inputs')
    def get(self, uuid, current_user):
        ''' Returns information about an input '''
        inp = Input.query.filter_by(uuid=uuid, organization_uuid=current_user().organization_uuid).first()
        if inp:
            return inp
        else:
            ns_input.abort(404, 'Input not found.')

    @api.expect(mod_input_create)
    @api.marshal_with(mod_input_list)
    @token_required
    @user_has('update_input')
    def put(self, uuid, current_user):
        ''' Updates information for an input '''
        inp = Input.query.filter_by(uuid=uuid, organization_uuid=current_user().organization_uuid).first()
        if inp:
            if 'name' in api.payload and Input.query.filter_by(name=api.payload['name']).first():
                ns_input.abort(409, 'Input name already exists.')
            else:
                inp.update(api.payload)
                return inp
        else:
            ns_input.abort(404, 'Input not found.')

    @token_required
    @user_has('delete_input')
    def delete(self, uuid, current_user):
        ''' Deletes an input '''
        inp = Input.query.filter_by(uuid=uuid, organization_uuid=current_user().organization_uuid).first()
        if inp:
            inp.delete()
            return {'message': 'Sucessfully deleted input.'}


@ns_plugin.route("/download/<path:path>")
class DownloadPlugin(Resource):

    # TODO: MAKE THIS ONLY ACCESSIBLE FROM AGENT TOKENS
    @api.doc(security="Bearer")
    @token_required
    def get(self, path, current_user):
        plugin_dir = os.path.join(current_app.config['PLUGIN_DIRECTORY'], current_user().organization_uuid)
        return send_from_directory(plugin_dir, path, as_attachment=True)


@ns_plugin.route('/upload')
class UploadPlugin(Resource):

    @api.doc(security="Bearer")
    @api.expect(upload_parser)
    @api.marshal_with(mod_plugin_list, as_list=True)
    @token_required
    @user_has('create_plugin')
    def post(self, current_user):

        plugins = []

        args = upload_parser.parse_args()

        def allowed_file(filename):
            return '.' in filename and filename.rsplit('.', 1)[1].lower() in current_app.config['PLUGIN_EXTENSIONS']

        if 'files' not in request.files:
            ns_plugin.abort(400, 'No file selected.')

        uploaded_files = args['files']
        for uploaded_file in uploaded_files:

            if uploaded_file.filename == '':
                ns_plugin.abort(400, 'No file selected.')

            if uploaded_file and allowed_file(uploaded_file.filename):

                # Make sure the file is one that can be uploaded
                # TODO: Add mime-type checking
                filename = secure_filename(uploaded_file.filename)
                
                # Check to see if the organizations plugin directory exists
                plugin_dir = os.path.join(current_app.config['PLUGIN_DIRECTORY'], current_user().organization_uuid)
                plugin_dir = os.path.join(os.path.dirname(os.path.realpath(__file__)), plugin_dir)
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
                                config_template = None

                plugin = Plugin.query.filter_by(filename=filename).first()
                if plugin:
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
                                    file_hash=hasher.hexdigest(),
                                    organization_uuid=current_user().organization_uuid)
                    plugin.create()
                plugins.append(plugin)
        return plugins


@ns_plugin_config.route("")
class PluginConfigList(Resource):

    @api.doc(security="Bearer")
    @api.marshal_with(mod_plugin_config_list, as_list=True)
    @token_required
    @user_has('view_plugins')
    def get(self, current_user):
        ''' Returns a list of plugin_configs '''
        return PluginConfig.query.filter_by(organization_uuid=current_user().organization_uuid).all()

    @api.doc(security="Bearer")
    @api.expect(mod_plugin_config_create)
    @api.response('409', 'Plugin Config already exists.')
    @api.response('200', "Successfully created the event.")
    @token_required
    @user_has('create_plugin')
    def post(self, current_user):
        ''' Creates a new plugin_config '''
        plugin_config = PluginConfig.query.filter_by(
            name=api.payload['name']).first()
        if not plugin_config:
            plugin_config = PluginConfig(organization_uuid=current_user().organization_uuid, **api.payload)
            plugin_config.create()
        else:
            ns_plugin_config.abort(409, 'Plugin Config already exists.')
        return {'message': 'Successfully created the plugin config.', 'uuid': plugin_config.uuid}


@ns_plugin_config.route("/<uuid>")
class PluginConfigDetails(Resource):

    @api.doc(security="Bearer")
    @api.marshal_with(mod_plugin_config_list)
    @api.response('200', 'Success')
    @api.response('404', 'PluginConfig not found')
    @token_required
    @user_has('view_plugins')
    def get(self, current_user, uuid):
        ''' Returns information about a plugin_config '''
        plugin_config = PluginConfig.query.filter_by(uuid=uuid, organization_uuid=current_user().organization_uuid).first()
        if plugin_config:
            return plugin_config
        else:
            ns_plugin_config.abort(404, 'Plugin Config not found.')

    @api.doc(security="Bearer")
    @api.expect(mod_plugin_config_create)
    @api.marshal_with(mod_plugin_config_list)
    @token_required
    @user_has('update_plugin')
    def put(self, current_user, uuid):
        ''' Updates information for a plugin_config '''
        plugin_config = PluginConfig.query.filter_by(uuid=uuid, organization_uuid=current_user().organization_uuid).first()
        if plugin_config:
            if 'name' in api.payload and PluginConfig.query.filter_by(name=api.payload['name']).first():
                ns_plugin_config.abort(
                    409, 'Plugin Config name already exists.')
            else:
                plugin_config.update(api.payload)
                return plugin_config
        else:
            ns_plugin_config.abort(404, 'Plugin Config not found.')

    @api.doc(security="Bearer")
    @token_required
    @user_has('delete_plugin')
    def delete(self, current_user, uuid):
        ''' Deletes a plugin_config '''
        plugin_config = PluginConfig.query.filter_by(uuid=uuid, organization_uuid=current_user().organization_uuid).first()
        if plugin_config:
            plugin_config.delete()
            return {'message': 'Sucessfully deleted plugin config.'}


@ns_plugin.route("")
class PluginList(Resource):

    @api.doc(security="Bearer")
    @api.marshal_with(mod_plugin_list, as_list=True)
    @token_required
    @user_has('view_plugins')
    def get(self, current_user):
        ''' Returns a list of plugins '''
        return Plugin.query.filter_by(organization_uuid=current_user().organization_uuid).all()

    @api.doc(security="Bearer")
    @api.expect(mod_plugin_create)
    @api.response('409', 'Plugin already exists.')
    @api.response('200', "Successfully created the event.")
    @token_required
    @user_has('create_plugin')
    def post(self, current_user):
        ''' Creates a new plugin '''
        plugin = Plugin.query.filter_by(name=api.payload['name']).first()
        if not plugin:
            plugin = Plugin(organization_uuid=current_user().organization_uuid, **api.payload)
            plugin.create()
        else:
            ns_plugin.abort(409, 'Plugin already exists.')
        return {'message': 'Successfully created the plugin.', 'uuid': plugin.uuid}


@ns_plugin.route("/<uuid>")
class PluginDetails(Resource):

    @api.doc(security="Bearer")
    @api.marshal_with(mod_plugin_list)
    @api.response('200', 'Success')
    @api.response('404', 'Plugin not found')
    @token_required
    @user_has('view_plugins')
    def get(self, current_user, uuid):
        ''' Returns information about a plugin '''
        plugin = Plugin.query.filter_by(uuid=uuid, organization_uuid=current_user().organization_uuid).first()
        if plugin:
            return plugin
        else:
            ns_plugin.abort(404, 'Plugin not found.')

    @api.doc(security="Bearer")
    @api.expect(mod_plugin_create)
    @api.marshal_with(mod_plugin_list)
    @token_required
    @user_has('update_plugin')
    def put(self, current_user, uuid):
        ''' Updates information for a plugin '''
        plugin = Plugin.query.filter_by(uuid=uuid, organization_uuid=current_user().organization_uuid).first()
        if plugin:
            if 'name' in api.payload and Plugin.query.filter_by(name=api.payload['name']).first():
                ns_plugin.abort(409, 'Plugin name already exists.')
            else:
                plugin.update(api.payload)
                return plugin
        else:
            ns_plugin.abort(404, 'Plugin not found.')

    @api.doc(security="Bearer")
    @token_required
    @user_has('delete_plugin')
    def delete(self, current_user, uuid):
        ''' Deletes a plugin '''
        plugin = Plugin.query.filter_by(uuid=uuid, organization_uuid=current_user().organization_uuid).first()
        if plugin:
            plugin.delete()
            return {'message': 'Sucessfully deleted plugin.'}


@ns_event.route("/_bulk")
class CreateBulkEvents(Resource):

    @api.expect(mod_event_create_bulk)
    @api.response('200', 'Sucessfully created events.')
    @api.response('207', 'Multi-Status')
    def post(self):
        ''' Creates Events in bulk '''
        response = {
            'results': [],
            'success': True
        }
        event_status = EventStatus.query.filter_by(name="New").first()

        events = api.payload['events']
        for item in events:
            _tags = []
            _observables = []
            event = Event.query.filter_by(reference=item['reference']).first()
            if not event:
                if 'tags' in item:
                    tags = item.pop('tags')
                    _tags = parse_tags(tags, current_user().organization_uuid)

                if 'observables' in item:
                    observables = item.pop('observables')
                    _observables = create_observables(observables, current_user().organization_uuid)

                event = Event(**item)
                event.create()

                event.status = event_status
                event.save()

                if len(_tags) > 0:
                    event.tags += _tags
                    event.save()

                if len(_observables) > 0:
                    event.observables += _observables
                    event.save()

                response['results'].append(
                    {'reference': item['reference'], 'status': 200, 'message': 'Event successfully created.'})
            else:
                response['results'].append(
                    {'reference': item['reference'], 'status': 409, 'message': 'Event already exists.'})
                response['success'] = False
        return response, 207


@ns_event.route("")
class EventList(Resource):

    @api.doc(security="Bearer")
    @api.marshal_with(mod_event_list, as_list=True)
    @token_required
    @user_has('view_events')
    def get(self, current_user):
        ''' Returns a list of event '''
        return Event.query.order_by(desc(Event.created_at)).all()

    @api.doc(security="Bearer")
    @api.expect(mod_event_create)
    @api.response(409, 'Event already exists.')
    @api.response(200, "Successfully created the event.")
    @token_required
    @user_has('add_event')
    def post(self, current_user):
        _observables = []
        _tags = []
        ''' Creates a new event '''
        event = Event.query.filter_by(
            reference=api.payload['reference']).first()
        if not event:
            if 'tags' in api.payload:
                tags = api.payload.pop('tags')
                _tags = parse_tags(tags, current_user().organization_uuid)

            if 'observables' in api.payload:
                observables = api.payload.pop('observables')
                _observables = create_observables(observables, current_user().organization_uuid)

            event = Event(organization_uuid=current_user().organization_uuid, **api.payload)
            event.create()

            # Set the default status to New
            event_status = EventStatus.query.filter_by(name="New").first()
            event.status = event_status
            event.save()

            if len(_tags) > 0:
                event.tags += _tags
                event.save()

            if len(_observables) > 0:
                event.observables += _observables
                event.save()

            return {'message': 'Successfully created the event.'}
        else:
            ns_event.abort(409, 'Event already exists.')


@ns_event.route("/<uuid>")
class EventDetails(Resource):

    @api.doc(security="Bearer")
    @api.marshal_with(mod_event_details)
    @api.response('200', 'Success')
    @api.response('404', 'Event not found')
    @token_required
    @user_has('view_events')
    def get(self, current_user, uuid):
        ''' Returns information about a event '''
        event = Event.query.filter_by(uuid=uuid, organization_uuid=current_user().organization_uuid).first()
        if event:
            return event
        else:
            ns_event.abort(404, 'Event not found.')

    @api.doc(security="Bearer")
    @api.expect(mod_event_create)
    @api.marshal_with(mod_event_details)
    @token_required
    @user_has('update_event')
    def put(self, current_user, uuid):
        ''' Updates information for a event '''
        event = Event.query.filter_by(uuid=uuid, organization_uuid=current_user().organization_uuid).first()
        if event:
            if 'name' in api.payload and Event.query.filter_by(name=api.payload['name']).first():
                ns_event.abort(409, 'Event name already exists.')
            else:
                event.update(api.payload)
                return event
        else:
            ns_event.abort(404, 'Event not found.')

    @api.doc(security="Bearer")
    @token_required
    @user_has('delete_event')
    def delete(self, current_user, uuid):
        ''' Deletes a event '''
        event = Event.query.filter_by(uuid=uuid, organization_uuid=current_user().organization_uuid).first()
        if event:
            event.delete()
            return {'message': 'Sucessfully deleted event.'}


@ns_event.route('/<uuid>/remove_tag/<name>')
class DeleteEventTag(Resource):

    @api.doc(security="Bearer")
    @token_required
    # @user_has('remove_tag_from_event')
    def delete(self, uuid, name, current_user):
        ''' Removes a tag from an event '''
        tag = Tag.query.filter_by(name=name).first()
        if not tag:
            ns_event.abort(404, 'Tag not found.')
        event = Event.query.filter_by(uuid=uuid, organization_uuid=current_user().organization_uuid).first()
        if event:
            event.tags.remove(tag)
            event.save()
        else:
            ns_event.abort(404, 'Event not found.')
        return {'message': 'Successfully removed tag from event.'}


@ns_event.route("/<uuid>/tag/<name>")
class TagEvent(Resource):

    @api.doc(security="Bearer")
    @token_required
    @user_has('add_tag_to_event')
    def post(self, uuid, name, current_user):
        ''' Adds a tag to an event '''
        tag = Tag.query.filter_by(name=name).first()
        if not tag:
            tag = Tag(**{'name': name, 'color': '#fffff'})
            tag.create()

        event = Event.query.filter_by(uuid=uuid, organization_uuid=current_user().organization_uuid).first()
        if event:
            event.tags += [tag]
            event.save()
        else:
            ns_event.abort(404, 'Event not found.')
        return {'message': 'Successfully added tag to event.'}


@ns_event.route("/<uuid>/bulktag")
class BulkTagEvent(Resource):

    @api.doc(security="Bearer")
    @api.expect(mod_bulk_tag)
    @token_required
    @user_has('add_tag_to_event')
    def post(self, uuid, current_user):
        ''' Adds a tag to an event '''
        _tags = []
        if 'tags' in api.payload:
            tags = api.payload['tags']
            for t in tags:
                tag = Tag.query.filter_by(name=t).first()
                if not tag:
                    tag = Tag(**{'name': t, 'color': '#fffff'})
                    tag.create()
                    _tags += [tag]
                else:
                    _tags += [tag]

        event = Event.query.filter_by(uuid=uuid, organization_uuid=current_user().organization_uuid).first()
        if event:
            event.tags += _tags
            event.save()
        else:
            ns_event.abort(404, 'Event not found.')
        return {'message': 'Successfully added tag to event.'}


@ns_agent.route("/pair_token")
class AgentPairToken(Resource):

    @api.doc(security="Bearer")
    @token_required
    @user_has('pair_agent')
    def get(self, current_user):
        ''' 
        Generates a short lived pairing token used by the agent
        to get a long running JWT
        '''
        return generate_token(None, current_user().organization_uuid, 900, 'pairing')


@ns_agent.route("")
class AgentList(Resource):

    @api.doc(security="Bearer")
    @api.marshal_with(mod_agent_list, as_list=True)
    @token_required
    @user_has('view_agents')
    def get(self, current_user):
        ''' Returns a list of Agents '''
        return Agent.query.filter_by(organization_uuid=current_user().organization_uuid).all()

    @api.doc(security="Bearer")
    @api.expect(mod_agent_create)
    @api.response('409', 'Agent already exists.')
    @api.response('200', "Successfully created the agent.")
    @token_required
    @user_has('add_agent')
    def post(self, current_user):
        ''' Creates a new Agent '''

        groups = None

        print(current_user())

        agent = Agent.query.filter_by(name=api.payload['name'], organization_uuid=current_user()['organization_uuid']).first()
        if not agent:

            if 'roles' in api.payload:
                roles = api.payload.pop('roles')

            if 'groups' in api.payload:
                groups = api.payload.pop('groups')

            agent = Agent(organization_uuid=current_user()['organization_uuid'], **api.payload)
            for role in roles:
                agent_role = AgentRole.query.filter_by(name=role).first()
                if agent_role:
                    agent.roles.append(agent_role)
                else:
                    ns_agent.abort(400, 'Invalid agent role type')

            if groups:
                for group_name in groups:
                    group = AgentGroup.query.filter_by(name=group_name, organization_uuid=current_user()['organization_uuid']).first()
                    if group:
                        agent.groups.append(group)
                    else:
                        ns_agent.abort(400, 'Agent Group not found.')

            role = Role.query.filter_by(name='Agent').first()
            agent.role = role

            agent.create()

            return {'message': 'Successfully created the agent.', 'uuid': agent.uuid, 'token': generate_token(agent.uuid, current_user()['organization_uuid'], 86400, token_type='agent')}
        else:
            ns_agent.abort(409, "Agent already exists.")


@ns_agent.route("/heartbeat/<uuid>")
class AgentHeartbeat(Resource):

    @api.doc(security="Bearer")
    @token_required
    def get(self, uuid, current_user):
        agent = Agent.query.filter_by(uuid=uuid, organization_uuid=current_user().organization_uuid).first()
        if agent:
            agent.last_heartbeat = datetime.datetime.utcnow()
            agent.save()
            return {'message': 'Your heart still beats!'}
        else:
            ns_agent.abort(400, 'Your heart stopped.')


@ns_agent.route("/<uuid>")
class AgentDetails(Resource):

    @api.doc(security="Bearer")
    @api.expect(mod_agent_create)
    @api.marshal_with(mod_agent_list)
    @token_required
    @user_has('update_agent')
    def put(self, uuid, current_user):
        ''' Updates an Agent '''
        agent = Agent.query.filter_by(uuid=uuid, organization_uuid=current_user().organization_uuid).first()
        if agent:
            if 'inputs' in api.payload:
                _inputs = []
                inputs = api.payload.pop('inputs')
                if len(inputs) > 0:
                    for inp in inputs:
                        _input = Input.query.filter_by(uuid=inp).first()
                        if _input:
                            _inputs.append(_input)
                agent.inputs = _inputs
                agent.save()

            if 'groups' in api.payload:
                _groups = []
                groups = api.payload.pop('groups')
                if len(groups) > 0:
                    for grp in groups:
                        group = AgentGroup.query.filter_by(uuid=grp).first()
                        if group:
                            _groups.append(group)
                agent.groups = _groups
                agent.save()

            agent.update(api.payload)
            return agent
        else:
            ns_agent.abort(404, 'Agent not found.')

    @api.doc(security="Bearer")
    @token_required
    @user_has('delete_agent')
    def delete(self, uuid, current_user):
        ''' Removes a Agent '''
        agent = Agent.query.filter_by(uuid=uuid, organization_uuid=current_user().organization_uuid).first()
        if agent:
            agent.delete()
            return {'message': 'Agent successfully delete.'}
        else:
            ns_agent.abort(404, 'Agent not found.')

    @api.doc(security="Bearer")
    @api.marshal_with(mod_agent_list)
    @token_required
    @user_has('view_agents')
    def get(self, uuid, current_user):
        ''' Gets the details of a Agent '''
        agent = Agent.query.filter_by(uuid=uuid, organization_uuid=current_user().organization_uuid).first()
        if agent:
            return agent
        else:
            ns_agent.abort(404, 'Agent not found.')

user_group_parser = api.parser()
user_group_parser.add_argument('name', location='args', required=False)

@ns_user_group.route("")
class UserGroupList(Resource):

    @api.doc(security="Bearer")
    @api.marshal_with(mod_user_group_list, as_list=True)
    @token_required
    @user_has('view_user_groups')
    def get(self, current_user):
        ''' Gets a list of user_groups '''

        args = user_group_parser.parse_args()

        if args['name']:
            groups = UserGroup.query.filter_by(UserGroup.name.like(args['name']+"%"), organization_uuid=current_user().organization_uuid).all()
        else:
            groups = UserGroup.query.filter_by(organization_uuid=current_user().organization_uuid).all()

        return groups

    @api.doc(security="Bearer")
    @api.expect(mod_user_group_create)
    @api.response('409', 'User Group already exists.')
    @api.response('200', "Successfully created the User Group.")
    @token_required
    @user_has('create_user_group')
    def post(self, current_user):
        ''' Creates a new user_group '''
        user_group = UserGroup.query.filter_by(
            name=api.payload['name']).first()
        if not user_group:
            user_group = UserGroup(organization_uuid=current_user().organization_uuid, **api.payload)
            user_group.create()
            return {'message': 'Successfully created the User Group.'}
        else:
            ns_user_group.abort(409, 'User Group already exists.')
        return

@ns_user_group.route('/<uuid>')
class UserGroupDetails(Resource):

    @api.doc(security="Bearer")
    @api.marshal_with(mod_user_group_list)
    @api.response('200', 'Success')
    @api.response('404', 'UserGroup not found')
    @token_required
    @user_has('view_user_groups')
    def get(self, uuid, current_user):
        ''' Gets details on a specific user_group '''
        user_group = UserGroup.query.filter_by(uuid=uuid, organization_uuid=current_user().organization_uuid).first()
        if user_group:
            return user_group
        else:
            ns_user_group.abort(404, 'User Group not found.')
        return

    @api.doc(security="Bearer")
    @api.expect(mod_user_group_create)
    @api.marshal_with(mod_user_group_list)
    @token_required
    @user_has('update_user_groups')
    def put(self, uuid, current_user):
        ''' Updates a user_group '''
        user_group = UserGroup.query.filter_by(uuid=uuid, organization_uuid=current_user().organization_uuid).first()

        if user_group:
            # TODO: Improve the query function so that organization_uuid=current_user().organization_uuid is just natively
            # called on all database calls
            if 'name' in api.payload and UserGroup.query.filter_by(name=api.payload['name'], organization_uuid=current_user().organization_uuid).first():
                ns_user_group.abort(409, 'User Group name already exists.')
            else:
                user_group.update(api.payload)
                return user_group
        else:
            ns_user_group.abort(404, 'User Group not found.')
        return

    @api.doc(security="Bearer")
    @token_required
    @user_has('delete_user_group')
    def delete(self, uuid, current_user):
        ''' Deletes a user_group '''
        user_group = UserGroup.query.filter_by(uuid=uuid, organization_uuid=current_user().organization_uuid).first()
        if user_group:
            user_group.delete()
            return {'message': 'Sucessfully deleted User Group.'}


@ns_user_group.route("/<uuid>/update-users")
class UpdateUserToGroup(Resource):

    @api.doc(security="Bearer")
    @api.response('409', 'User already a member of this Group.')
    @api.response('404', 'Group not found.')
    @api.response('404', 'User not found.')
    @api.response('207', 'Users added to Group.')
    @api.expect(mod_add_user_to_group)
    @token_required
    @user_has('update_user_groups')
    def put(self, uuid, current_user):
        ''' Adds a user to a specified Role '''

        _users = []
        response = {
            'results': [],
            'success': True
        }
        if 'members' in api.payload:
            users = api.payload.pop('members')
            for user_uuid in users:
                user = User.query.filter_by(uuid=user_uuid, organization_uuid=current_user().organization_uuid).first()
                if user:
                    _users.append(user)
                    response['results'].append(
                        {'reference': user_uuid, 'message': 'User successfully added.'})
                else:
                    response['results'].append(
                        {'reference': user_uuid, 'message': 'User not found.'})
                    response['success'] = False

        group = UserGroup.query.filter_by(uuid=uuid, organization_uuid=current_user().organization_uuid).first()
        if group:
            group.members = _users
            group.save()
            return response, 207
        else:
            ns_user_group.abort(404, 'Group not found.')


@ns_agent_group.route("")
class AgentGroupList(Resource):

    @api.doc(security="Bearer")
    @api.marshal_with(mod_agent_group_list, as_list=True)
    @token_required
    @user_has('view_agent_groups')
    def get(self, current_user):
        ''' Gets a list of agent_groups '''
        return AgentGroup.query.filter_by(organization_uuid=current_user().organization_uuid).all()

    @api.doc(security="Bearer")
    @api.expect(mod_agent_group_create)
    @api.response('409', 'AgentGroup already exists.')
    @api.response('200', "Successfully created the Agent Group.")
    @token_required
    @user_has('create_agent_group')
    def post(self, current_user):
        ''' Creates a new agent_group '''
        agent_group = AgentGroup.query.filter_by(
            name=api.payload['name']).first()
        if not agent_group:
            agent_group = AgentGroup(organization_uuid=current_user().organization_uuid, **api.payload)
            agent_group.create()
            return {'message': 'Successfully created the Agent Group.'}
        else:
            ns_agent_group.abort(409, 'Agent Group already exists.')
        return


@ns_agent_group.route('/<uuid>')
class AgentGroupDetails(Resource):

    @api.doc(security="Bearer")
    @api.marshal_with(mod_agent_group_list)
    @api.response('200', 'Success')
    @api.response('404', 'AgentGroup not found')
    @token_required
    @user_has('view_agent_groups')
    def get(self, uuid, current_user):
        ''' Gets details on a specific agent_group '''
        agent_group = AgentGroup.query.filter_by(uuid=uuid, organization_uuid=current_user().organization_uuid).first()
        if agent_group:
            return agent_group
        else:
            ns_agent_group.abort(404, 'Agent Group not found.')
        return

    @api.doc(security="Bearer")
    @api.expect(mod_agent_group_create)
    @api.marshal_with(mod_agent_group_list)
    @token_required
    @user_has('update_agent_group')
    def put(self, uuid, current_user):
        ''' Updates a agent_group '''
        agent_group = AgentGroup.query.filter_by(uuid=uuid, organization_uuid=current_user().organization_uuid).first()

        if agent_group:
            if 'name' in api.payload and AgentGroup.query.filter_by(name=api.payload['name']).first():
                ns_agent_group.abort(409, 'Agent Group name already exists.')
            else:
                agent_group.update(api.payload)
                return agent_group
        else:
            ns_agent_group.abort(404, 'Agent Group not found.')
        return

    @api.doc(security="Bearer")
    @token_required
    @user_has('delete_agent_group')
    def delete(self, uuid):
        ''' Deletes a agent_group '''
        agent_group = AgentGroup.query.filter_by(uuid=uuid, organization_uuid=current_user().organization_uuid).first()
        if agent_group:
            agent_group.delete()
            return {'message': 'Sucessfully deleted Agent Group.'}


@ns_role.route("")
class RoleList(Resource):

    @api.doc(security="Bearer")
    @api.marshal_with(mod_role_list, as_list=True)
    @token_required
    @user_has('view_roles')
    def get(self, current_user):
        ''' Returns a list of Roles '''
        return Role.query.filter_by(organization_uuid=current_user().organization_uuid).all()

    @api.doc(security="Bearer")
    @api.expect(mod_role_create)
    @api.response('409', 'Role already exists.')
    @api.response('200', "Successfully created the role.")
    @token_required
    @user_has('add_role')
    def post(self, current_user):
        ''' Creates a new Role '''
        role = Role.query.filter_by(name=api.payload['name'], organization_uuid=current_user().organization_uuid).first()
        if not role:
            role = Role(organization_uuid=current_user().organization_uuid, **api.payload)
            role.create()
            return {'message': 'Successfully created the role.', 'uuid': role.uuid}
        else:
            ns_user.abort(409, "Role already exists.")


@ns_role.route("/<uuid>")
class RoleDetails(Resource):

    @api.doc(security="Bearer")
    @api.marshal_with(mod_role_list)
    @token_required
    @user_has('update_role')
    def put(self, uuid, current_user):
        ''' Updates an Role '''
        role = Role.query.filter_by(uuid=uuid, organization_uuid=current_user().organization_uuid).first()
        if role:
            if 'name' in api.payload and Role.query.filter_by(name=api.payload['name'], organization_uuid=current_user().organization_uuid).first():
                ns_role.abort(409, 'Role with that name already exists.')
            else:
                role.update(api.payload)
                return role
        else:
            ns_role.abort(404, 'Role not found.')

    @api.doc(security="Bearer")
    @token_required
    @user_has('delete_role')
    def delete(self, uuid, current_user):
        ''' Removes a Role '''
        role = Role.query.filter_by(uuid=uuid, organization_uuid=current_user().organization_uuid).first()
        if role:
            if len(role.users) > 0:
                ns_role.abort(
                    400, 'Can not delete a role with assigned users.  Assign the users to a new role first.')
            else:
                role.delete()
                return {'message': 'Role successfully delete.'}
        else:
            ns_role.abort(404, 'Role not found.')

    @api.doc(security="Bearer")
    @api.marshal_with(mod_role_list)
    @token_required
    @user_has('view_roles')
    def get(self, uuid, current_user):
        ''' Gets the details of a Role '''
        role = Role.query.filter_by(uuid=uuid, organization_uuid=current_user().organization_uuid).first()
        if role:
            return role
        else:
            ns_role.abort(404, 'Role not found.')


@ns_role.route("/<uuid>/add-user/<user_uuid>")
class AddUserToRole(Resource):

    @api.doc(security="Bearer")
    @api.response('409', 'User already a member of this Role.')
    @api.response('404', 'Role not found.')
    @api.response('404', 'User not found.')
    @api.response('200', 'User added to Role.')
    @token_required
    @user_has('add_user_to_role')
    def put(self, uuid, user_uuid, current_user):
        ''' Adds a user to a specified Role '''
        user = User.query.filter_by(uuid=user_uuid, organization_uuid=current_user().organization_uuid).first()
        if user:
            role = Role.query.filter_by(uuid=uuid, organization_uuid=current_user().organization_uuid).first()
            if role:
                user.role = role
                user.save()
                return {'message': 'Successfully added {} to the {} role.'.format(user.username, role.name)}
            else:
                ns_role.abort(404, 'Role not found.')
        else:
            ns_role.abort(404, 'User not found.')


@ns_role.route("/<uuid>/remove-user/<user_uuid>")
class RemoveUserFromRole(Resource):

    @api.doc(security="Bearer")
    @api.response('404', 'User not a member of this Role.')
    @api.response('404', 'Role not found.')
    @api.response('200', 'User removed from Role.')
    @token_required
    @user_has('remove_user_from_role')
    def put(self, uuid, user_uuid, current_user):
        ''' Removes a user to a specified Role '''
        user = User.query.filter_by(uuid=user_uuid, organization_uuid=current_user().organization_uuid).first()
        if not user:
            ns_role.abort(404, 'User not found.')

        role = Role.query.filter_by(uuid=uuid, organization_uuid=current_user().organization_uuid).first()
        if role:
            role.users = [u for u in role.users if u.uuid != user.uuid]
            role.save()
            return {'message': 'Successfully removed User from Role.'}
        else:
            ns_role.abort(404, 'Role not found.')


@ns_credential.route('/encrypt')
class EncryptPassword(Resource):

    @api.doc(security="Bearer")
    @api.expect(mod_credential_create)
    @api.response('400', 'Successfully created credential.')
    @api.response('409', 'Credential already exists.')
    @token_required
    @user_has('add_credential')
    def post(self, current_user):
        ''' Encrypts the password '''
        credential = Credential.query.filter_by(
            name=api.payload['name'], organization_uuid=current_user().organization_uuid).first()
        if not credential:
            credential = Credential(organization_uuid=current_user().organization_uuid, **api.payload)
            credential.encrypt(api.payload['secret'].encode(
            ), current_app.config['MASTER_PASSWORD'])
            credential.create()
            return {'message': 'Successfully created credential.', 'uuid': credential.uuid}, 200
        else:
            ns_credential.abort(409, 'Credential already exists.')


@ns_credential.route("")
class CredentialList(Resource):

    @api.doc(security="Bearer")
    @api.marshal_with(mod_credential_list)
    @token_required
    @user_has('view_credentials')
    def get(self, current_user):
        credentials = Credential.query.filter_by(organization_uuid=current_user().organization_uuid).all()
        if credentials:
            return credentials
        else:
            return []
            #ns_credential.abort(404,'No credentials found.')


@ns_credential.route('/decrypt/<uuid>')
class DecryptPassword(Resource):

    @api.doc(security="Bearer")
    @api.marshal_with(mod_credential_return)
    @api.response('404', 'Credential not found.')
    @token_required
    @user_has('decrypt_credential')
    def get(self, uuid, current_user):
        ''' Decrypts the credential for use '''
        credential = Credential.query.filter_by(uuid=uuid, organization_uuid=current_user().organization_uuid).first()
        if credential:
            value = credential.decrypt(current_app.config['MASTER_PASSWORD'])
            if value:
                return {'secret': value}
            else:
                ns_credential.abort(401, 'Invalid master password.')
        else:
            ns_credential.abort(404, 'Credential not found.')


@ns_credential.route('/<uuid>')
class DeletePassword(Resource):

    @api.doc(security="Bearer")
    @api.marshal_with(mod_credential_full)
    @api.response('404', 'Credential not found.')
    @token_required
    @user_has('view_credentials')
    def get(self, uuid, current_user):
        ''' Gets the full details of a credential '''
        credential = Credential.query.filter_by(uuid=uuid, organization_uuid=current_user().organization_uuid).first()
        if credential:
            return credential
        else:
            ns_credential.abort(409, 'Credential not found.')

    @api.doc(security="Bearer")
    @api.expect(mod_credential_update, validate=True)
    @api.marshal_with(mod_credential_full)
    @api.response('404', 'Credential not found.')
    @api.response('409', 'Credential name already exists.')
    @token_required
    @user_has('update_credential')
    def put(self, uuid, current_user):
        ''' Updates a credential '''
        credential = Credential.query.filter_by(uuid=uuid, organization_uuid=current_user().organization_uuid).first()
        if credential:
            if 'name' in api.payload and Credential.query.filter_by(name=api.payload['name']).first():
                ns_credential.abort(409, 'Credential name already exists.')
            else:
                credential.encrypt(api.payload['secret'].encode(
                ), current_app.config['MASTER_PASSWORD'])
                credential.save()
                return credential
        else:
            ns_credential.abort(404, 'Credential not found.')

    @api.doc(security="Bearer")
    @api.response('404', 'Credential not found.')
    @api.response('200', "Credential sucessfully deleted.")
    @token_required
    @user_has('delete_credential')
    def delete(self, uuid, current_user):
        ''' Deletes a credential '''
        credential = Credential.query.filter_by(uuid=uuid, organization_uuid=current_user().organization_uuid).first()
        if credential:
            credential.delete()
            return {'message': 'Credential successfully deleted.'}
        else:
            ns_credential.abort(404, 'Credential not found.')


@ns_tag.route("")
class TagList(Resource):

    @api.doc(security="Bearer")
    @api.marshal_with(mod_tag_list, as_list=True)
    @token_required
    def get(self, current_user):
        ''' Gets a list of tags '''
        return Tag.query.filter_by(organization_uuid=current_user().organization_uuid).all()

    @api.doc(security="Bearer")
    @api.expect(mod_tag)
    @api.response('409', 'Tag already exists.')
    @api.response('200', "Successfully created the tag.")
    @token_required
    def post(self, current_user):
        ''' Creates a new tag '''
        tag = Tag.query.filter_by(name=api.payload['name']).first()
        if not tag:
            tag = Tag(organization_uuid=current_user().organization_uuid, **api.payload)
            tag.create()
            return {'message': 'Successfully created the tag.'}
        else:
            ns_tag.abort(409, 'Tag already exists.')
        return


@ns_tag.route('/<uuid>')
class TagDetails(Resource):

    @api.doc(security="Bearer")
    @api.marshal_with(mod_tag_list)
    @api.response('200', 'Success')
    @api.response('404', 'Tag not found')
    @token_required
    def get(self, uuid, current_user):
        ''' Gets details on a specific tag '''
        tag = Tag.query.filter_by(uuid=uuid, organization_uuid=current_user().organization_uuid).first()
        if tag:
            return tag
        else:
            ns_tag.abort(404, 'Tag not found.')
        return

    @api.doc(security="Bearer")
    @api.expect(mod_tag)
    @api.marshal_with(mod_tag)
    @token_required
    def put(self, uuid, current_user):
        ''' Updates a tag '''
        tag = Tag.query.filter_by(uuid=uuid, organization_uuid=current_user().organization_uuid).first()
        if tag:
            if 'name' in api.payload and Tag.query.filter_by(name=api.payload['name']).first():
                ns_tag.abort(409, 'Tag name already exists.')
            else:
                tag.update(api.payload)
                return tag
        else:
            ns_tag.abort(404, 'Tag not found.')
        return

    @api.doc(security="Bearer")
    @token_required
    def delete(self, uuid, current_user):
        ''' Deletes a tag '''
        tag = Tag.query.filter_by(uuid=uuid, organization_uuid=current_user().organization_uuid).first()
        if tag:
            tag.delete()
            return {'message': 'Sucessfully deleted tag.'}


@ns_settings.route("")
class Settings(Resource):

    @api.doc(security="Bearer")
    @api.marshal_with(mod_settings)
    @token_required
    @user_has('update_settings')    
    def get(self, current_user):
        ''' Retrieves the global settings for the system '''
        settings = GlobalSettings.query.first()
        return settings

    @api.doc(security="Bearer")
    @api.expect(mod_settings)
    @token_required    
    @user_has('update_settings')
    def put(self, current_user):

        settings = GlobalSettings.query.first()
        settings.update(organization_uuid=current_user().organization_uuid, **api.payload)

        return {'message': 'Succesfully updated settings'}