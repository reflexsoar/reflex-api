import datetime
import jwt
import json
import base64
import cryptography
from flask import request, current_app, abort, make_response
from flask_restx import Api, Resource, Namespace, fields, Model
from .models import User, db, RefreshToken, AuthTokenBlacklist, Role, Credential, Tag, Permission, Playbook, Alert, Observable, DataType, Input, AlertStatus
from sqlalchemy.dialects.postgresql import UUID
from .utils import token_required, user_has, _get_current_user
from .schemas import *

api = Api()

# Namespaces
ns_user = api.namespace('User', description='User operations', path='/user')
ns_auth = api.namespace('Auth', description='Authentication operations', path='/auth')
ns_role = api.namespace('Role', description='Role operations', path='/role')
ns_perms = api.namespace('Permission', description='Permission operations', path='/permission')
ns_playbook = api.namespace('Playbook', description='Playbook operations', path='/playbook')
ns_input = api.namespace('Input', description='Input operations', path='/input')
ns_tag = api.namespace('Tag', description='Tag operations', path='/tag')
ns_alert = api.namespace('Alert', description='Alert operations', path='/alert')
ns_credential = api.namespace('Credential', description='Credential operations', path='/credential')

# Expect an API token
expect_token = api.parser()
expect_token.add_argument('Authorization', location='headers')

# Register all the models this is redundant when using api.model() but we don't use this
# TODO: Fix this so this hack isn't required, app factory is jacking this up
for model in schema_models:
    api.models[model.name] = model


def parse_tags(tags):
    ''' Tags a list of supplied tags and creates Tag objects for each one '''
    _tags = []
    for t in tags:
        tag = Tag.query.filter_by(name=t).first()
        if not tag:
            tag = Tag(**{'name': t, 'color':'#fffff'})
            tag.create()
            _tags += [tag]
        else:
            _tags += [tag]
    return _tags


def create_observables(observables):
    _observables = []
    _tags = []
    for o in observables:
        if 'tags' in o:
            tags = o.pop('tags')
            _tags = parse_tags(tags)

        observable_type = DataType.query.filter_by(name=o['dataType']).first()
        if observable_type:
            observable = Observable.query.filter_by(value=o['value'],dataType_id=observable_type.uuid).first()
            if not observable:
                o['dataType'] = observable_type
                observable = Observable(**o)
                observable.create()
                _observables += [observable]
            else:
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
        user = User.query.filter_by(username=api.payload['username']).first()
        if not user:
            ns_auth.abort(401, 'Incorrect username or password')
        
        # Check if the user has entered a good password
        if user.check_password(api.payload['password']):
        
            # Generate an access token
            _access_token = user.create_access_token()

            # Generate a refresh token
            _refresh_token = user.create_refresh_token(request.user_agent.string.encode('utf-8'))   

            return {'access_token': _access_token, 'refresh_token': _refresh_token}, 200

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
            payload = jwt.decode(_refresh_token, current_app.config['SECRET_KEY'])

            refresh_token = RefreshToken.query.filter_by(user_uuid=payload['uuid'], refresh_token=_refresh_token).first()

            if not refresh_token:
                ns_auth.abort(401, 'Invalid token issuer.')

            # Generate a new pair
            user = User.query.filter_by(uuid=payload['uuid']).first()
            if user:
                access_token = user.create_access_token()
                refresh_token = user.create_refresh_token(request.user_agent.string.encode('utf-8'))
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
            return {'message':'Successfully logged out.'}, 200
        except:
            return {'message':'Not logged in.'}, 401

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


@ns_user.route("")
class UserList(Resource):
    
    @api.doc(security="Bearer")
    @api.marshal_with(mod_user_list, as_list=True)
    @token_required
    @user_has('view_users')
    def get(self, current_user):
        ''' Returns a list of users '''
        return User.query.all()

    # TODO: Add a lock to this so only the Admin users and those with 'add_user' permission can do this
    @api.doc(security="Bearer")
    @api.expect(mod_user_create)
    @api.response('409', 'User already exists.')
    @api.response('200', "Successfully created the user.")
    @token_required
    @user_has('add_user')
    def post(self, current_user):
        ''' Creates a new users '''
        user = User.query.filter_by(email=api.payload['email']).first()
        if not user:
            user = User(**api.payload)
            user.create()
            return {'message':'Successfully created the user.', 'uuid': user.uuid}
        else:
            ns_user.abort(409, "User already exists.")


@ns_user.route("/<uuid>")
class UserDetails(Resource):

    @api.doc(security="Bearer")
    @api.marshal_with(mod_user_full)
    @token_required
    @user_has('view_users')
    def get(self, uuid, current_user):
        ''' Returns information about a user '''
        user = User.query.filter_by(uuid=uuid).first()
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
        user = User.query.filter_by(uuid=uuid).first()
        if user:
            if 'username' in api.payload and User.query.filter_by(username=api.payload['username']).first():
                ns_user.abort(409, 'Username already taken.')
            else:
                user.update(api.payload)
                return user
        else:
            ns_user.abort(404, 'User not found.')

    @api.doc(security="Bearer")
    @token_required
    @user_has('delete_user')
    def delete(self, uuid, current_user):
        ''' Deletes a user '''
        user = User.query.filter_by(uuid=uuid).first()
        if user:
            if _get_current_user().uuid == user.uuid:
                ns_user.abort(403, 'User can not delete themself.')
            else:
                user.delete()
                return {'message': 'User successfully deleted.'}
        else:
            ns_user.abort(404, 'User not found.')


@ns_perms.route("")
class PermissionList(Resource):

    @api.marshal_with(mod_permission_list)
    def get(self):
        ''' Gets a list of all the permission sets '''
        return Permission.query.all()
    
    @api.expect(mod_permission_full)
    @api.response('200', 'Successfully created permission set.')
    def post(self):
        ''' Creates a new permission set '''
        perm = Permission(**api.payload)
        perm.create()
        return {'message': 'Successfully created permission set.', 'uuid': perm.uuid}


@ns_perms.route("/<uuid>")
class PermissionDetails(Resource):

    @api.marshal_with(mod_permission_list)
    def get(self, uuid):
        ''' Gets the permissions based '''
        perm = Permission.query.filter_by(uuid=uuid).first()
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
        perm = Permission.query.filter_by(uuid=uuid).first()
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
        perm = Permission.query.filter_by(uuid=uuid).first()
        if perm:
            if(len(perm.roles) > 0):
                ns_perms.abort(400, 'Cannot delete a permission set attached to an active Role.')
            else:
                perm.delete()
                return { 'message': 'Successfully deleted the Permission set.'}
            return perm
        else:
            ns_perms.abort(404, 'Permission set not found.')
        return


@ns_playbook.route("")
class PlaybookList(Resource):
    
    @api.doc(security="Bearer")
    @api.marshal_with(mod_playbook_list, as_list=True)
    @token_required
    @user_has('view_playbooks')
    def get(self, current_user):
        ''' Returns a list of playbook '''
        return Playbook.query.all()

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
                _tags = parse_tags(tags)

            playbook = Playbook(**api.payload)
            playbook.create()

            if len(_tags) > 0:
                playbook.tags += _tags
                playbook.save()

            return {'message':'Successfully created the playbook.'}
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
        playbook = Playbook.query.filter_by(uuid=uuid).first()
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
        playbook = Playbook.query.filter_by(uuid=uuid).first()
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
        playbook = Playbook.query.filter_by(uuid=uuid).first()
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
        playbook = Playbook.query.filter_by(uuid=uuid).first()
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
            tag = Tag(**{'name': name, 'color':'#fffff'})
            tag.create()
        
        playbook = Playbook.query.filter_by(uuid=uuid).first()
        if playbook:
            playbook.tags += [tag]
            playbook.save()
        else:
            ns_alert.abort(404, 'Playbook not found.')
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
                    tag = Tag(**{'name': t, 'color':'#fffff'})
                    tag.create()
                    _tags += [tag]
                else:
                    _tags += [tag]

        playbook = Playbook.query.filter_by(uuid=uuid).first()
        if playbook:
            playbook.tags += _tags
            playbook.save()
        else:
            ns_playbook.abort(404, 'Playbook not found.')
        return {'message': 'Successfully added tag to playbook.'}

@ns_input.route("")
class InputList(Resource):

    @api.marshal_with(mod_input_list, as_list=True)
    @token_required
    @user_has('view_inputs')
    def get(self, current_user):
        ''' Returns a list of inputs '''
        return Input.query.all()

    @api.expect(mod_input_create)
    @api.response('409', 'Input already exists.')
    @api.response('200', 'Successfully create the input.')
    @token_required
    @user_has('create_input')
    def post(self, current_user):
        _tags = []
        inp = Input.query.filter_by(name=api.payload['name']).first()

        if 'credential' in api.payload:
            cred_uuid = api.payload.pop('credential')
            cred = Credential.query.filter_by(uuid=cred_uuid).first()
            api.payload['credential'] = cred

        if not inp:
            if 'tags' in api.payload:
                tags = api.payload.pop('tags')
                _tags = parse_tags(tags)

            inp = Input(**api.payload)
            inp.create()

            if len(_tags) > 0:
                inp.tags += _tags
                inp.save()
        else:
            ns_input.abort(409,'Input already exists.')
        return {'message': 'Successfully created the input.'}


@ns_input.route("/<uuid>")
class InputDetails(Resource):

    @api.marshal_with(mod_input_list)
    @token_required
    @user_has('view_inputs')
    def get(self, uuid, current_user):
        ''' Returns information about an input '''
        inp = Input.query.filter_by(uuid=uuid).first()
        if inp:
            return inp
        else:
            ns_input.abort(404, 'Input not found.')

    @api.expect(mod_input_create)
    @api.marshal_with(mod_input_list)
    @token_required
    @user_has('create_input')
    def put(self, uuid, current_user):
        ''' Updates information for an input '''
        inp = Input.query.filter_by(uuid=uuid).first()
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
        inp = Input.query.filter_by(uuid=uuid).first()
        if inp:
            inp.delete()
            return {'message': 'Sucessfully deleted input.'}


@ns_alert.route("/_bulk")
class CreateBulkAlerts(Resource):

    @api.expect(mod_alert_create_bulk)
    @api.response('200', 'Sucessfully created alerts.')
    @api.response('207', 'Multi-Status')
    def post(self):
        ''' Creates Alerts in bulk '''
        response = {
            'results': [],
            'success': True
        }
        alerts = api.payload['alerts']
        for item in alerts:
            _tags = []
            alert = Alert.query.filter_by(reference=item['reference']).first()
            if not alert:
                if 'tags' in item:
                    tags = item.pop('tags')
                    _tags = parse_tags(tags)

                alert = Alert(**item)
                alert.create()

                if len(tags) > 0:
                    alert.tags += _tags
                    alert.save()

                response['results'].append({'reference': item['reference'], 'status': 200, 'message':'Alert successfully created.'})
            else:
                response['results'].append({'reference':item['reference'], 'status': 409, 'message':'Alert already exists.'})
                response['success'] = False
        return response,207


@ns_alert.route("")
class AlertList(Resource):
    
    @api.marshal_with(mod_alert_list, as_list=True)
    def get(self):
        ''' Returns a list of alert '''
        return Alert.query.all()

    @api.expect(mod_alert_create)
    @api.response('409', 'Alert already exists.')
    @api.response('200', "Successfully created the alert.")
    def post(self):
        _observables = []
        _tags = []
        ''' Creates a new alert '''
        alert = Alert.query.filter_by(reference=api.payload['reference']).first()
        if not alert:
            if 'tags' in api.payload:
                tags = api.payload.pop('tags')
                _tags = parse_tags(tags)

            if 'observables' in api.payload:
                observables = api.payload.pop('observables')
                _observables = create_observables(observables)
                
            alert = Alert(**api.payload)
            alert.create()

            # Set the default status to New
            alert_status = AlertStatus.query.filter_by(name="New").first()
            alert.status = alert_status
            alert.save()

            if len(_tags) > 0:
                alert.tags += _tags
                alert.save()

            if len(_observables) > 0:
                alert.observables += _observables
                alert.save()

            return {'message':'Successfully created the alert.'}
        else:
            ns_alert.abort(409, 'Alert already exists.')


@ns_alert.route("/<uuid>")
class AlertDetails(Resource):

    @api.marshal_with(mod_alert_details)
    @api.response('200', 'Success')
    @api.response('404', 'Alert not found')
    def get(self, uuid):
        ''' Returns information about a alert '''
        alert = Alert.query.filter_by(uuid=uuid).first()
        if alert:
            return alert
        else:
            ns_alert.abort(404, 'Alert not found.')

    @api.expect(mod_alert_create)
    @api.marshal_with(mod_alert_details)
    def put(self, uuid):
        ''' Updates information for a alert '''
        alert = Alert.query.filter_by(uuid=uuid).first()
        if alert:
            if 'name' in api.payload and Alert.query.filter_by(name=api.payload['name']).first():
                ns_alert.abort(409, 'Alert name already exists.')
            else:
                alert.update(api.payload)
                return alert
        else:
            ns_alert.abort(404, 'Alert not found.')

    def delete(self, uuid):
        ''' Deletes a alert '''
        alert = Alert.query.filter_by(uuid=uuid).first()
        if alert:
            alert.delete()
            return {'message': 'Sucessfully deleted alert.'}


@ns_alert.route('/<uuid>/remove_tag/<name>')
class DeleteAlertTag(Resource):

    @api.doc(security="Bearer")
    @token_required
    #@user_has('remove_tag_from_alert')
    def delete(self, uuid, name, current_user):
        ''' Removes a tag from an alert '''
        tag = Tag.query.filter_by(name=name).first()
        if not tag:
            ns_alert.abort(404, 'Tag not found.')
        alert = Alert.query.filter_by(uuid=uuid).first()
        if alert:
            alert.tags.remove(tag)
            alert.save()
        else:
            ns_alert.abort(404, 'Alert not found.')
        return {'message': 'Successfully rmeoved tag from alert.'}
                

@ns_alert.route("/<uuid>/tag/<name>")
class TagAlert(Resource):

    @api.doc(security="Bearer")
    @token_required
    @user_has('add_tag_to_alert')
    def post(self, uuid, name, current_user):
        ''' Adds a tag to an alert '''
        tag = Tag.query.filter_by(name=name).first()
        if not tag:
            tag = Tag(**{'name': name, 'color':'#fffff'})
            tag.create()
        
        alert = Alert.query.filter_by(uuid=uuid).first()
        if alert:
            alert.tags += [tag]
            alert.save()
        else:
            ns_alert.abort(404, 'Alert not found.')
        return {'message': 'Successfully added tag to alert.'}


@ns_alert.route("/<uuid>/bulktag")
class BulkTagAlert(Resource):

    @api.doc(security="Bearer")
    @api.expect(mod_bulk_tag)
    @token_required
    @user_has('add_tag_to_alert')    
    def post(self, uuid, current_user):
        ''' Adds a tag to an alert '''
        _tags = []
        if 'tags' in api.payload:
            tags = api.payload['tags']
            for t in tags:
                tag = Tag.query.filter_by(name=t).first()
                if not tag:
                    tag = Tag(**{'name': t, 'color':'#fffff'})
                    tag.create()
                    _tags += [tag]
                else:
                    _tags += [tag]

        alert = Alert.query.filter_by(uuid=uuid).first()
        if alert:
            alert.tags += _tags
            alert.save()
        else:
            ns_alert.abort(404, 'Alert not found.')
        return {'message': 'Successfully added tag to alert.'}


@ns_role.route("")
class RoleList(Resource):

    @api.doc(security="Bearer")
    @api.marshal_with(mod_role_list, as_list=True)
    @token_required
    @user_has('view_roles')
    def get(self, current_user):
        ''' Returns a list of Roles '''
        return Role.query.all()

    @api.doc(security="Bearer")
    @api.expect(mod_role_create)
    @api.response('409', 'Role already exists.')
    @api.response('200', "Successfully created the role.")
    @token_required
    @user_has('add_role')
    def post(self, current_user):
        ''' Creates a new Role '''
        role = Role.query.filter_by(name=api.payload['name']).first()
        if not role:
            role = Role(**api.payload)
            role.create()
            return {'message': 'Successfully created the role.', 'uuid': role.uuid }
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
        role = Role.query.filter_by(uuid=uuid).first()
        if role:
            if 'name' in api.payload and Role.query.filter_by(name=api.payload['name']).first():
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
        role = Role.query.filter_by(uuid=uuid).first()
        if role:
            if len(role.users) > 0:
                ns_role.abort(400, 'Can not delete a role with assigned users.  Assign the users to a new role first.')
            else:
                role.delete()
                return { 'message': 'Role successfully delete.'}
        else:
            ns_role.abort(404, 'Role not found.')
            

    @api.doc(security="Bearer")
    @api.marshal_with(mod_role_list)
    @token_required
    @user_has('view_roles')
    def get(self, uuid, current_user):
        ''' Gets the details of a Role '''
        role = Role.query.filter_by(uuid=uuid).first()
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
        user = User.query.filter_by(uuid=user_uuid).first()
        if user:
            role = Role.query.filter_by(uuid=uuid).first()
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
        user = User.query.filter_by(uuid=user_uuid).first()
        if not user:
            ns_role.abort(404, 'User not found.')
        
        role = Role.query.filter_by(uuid=uuid).first()
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
        credential = Credential.query.filter_by(name=api.payload['name']).first()
        if not credential:
            credential = Credential(**api.payload)
            credential.encrypt(api.payload['secret'].encode(), current_app.config['MASTER_PASSWORD'])
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
        credentials = Credential.query.all()
        if credentials:
            return credentials
        else:
            ns_credential.abort(404,'No credentials found.')


@ns_credential.route('/decrypt/<uuid>')
class DecryptPassword(Resource):
    
    @api.doc(security="Bearer")
    
    @api.marshal_with(mod_credential_return)
    @api.response('404', 'Credential not found.')
    @token_required
    @user_has('decrypt_credential')
    def get(self, uuid, current_user):
        ''' Decrypts the credential for use '''
        credential = Credential.query.filter_by(uuid=uuid).first()
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
        credential = Credential.query.filter_by(uuid=uuid).first()
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
        credential = Credential.query.filter_by(uuid=uuid).first()
        if credential:
            if 'name' in api.payload and Credential.query.filter_by(name=api.payload['name']).first():
                ns_credential.abort(409, 'Credential name already exists.')
            else:
                credential.encrypt(api.payload['secret'].encode(), current_app.config['MASTER_PASSWORD'])
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
        credential = Credential.query.filter_by(uuid=uuid).first()
        if credential:
            credential.delete()
            return {'message': 'Credential successfully deleted.'}
        else:
            ns_credential.abort(404, 'Credential not found.')


@ns_tag.route("")
class TagList(Resource):

    @api.marshal_with(mod_tag_list, as_list=True)
    def get(self):
        ''' Gets a list of tags '''
        return Tag.query.all()

    @api.expect(mod_tag)
    @api.response('409', 'Tag already exists.')
    @api.response('200', "Successfully created the tag.")
    def post(self):
        ''' Creates a new tag '''
        tag = Tag.query.filter_by(name=api.payload['name']).first()
        if not tag:
            tag = Tag(**api.payload)
            tag.create()
            return {'message':'Successfully created the tag.'}
        else:
            ns_project.abort(409, 'Tag already exists.')
        return

@ns_tag.route('/<uuid>')
class TagDetails(Resource):

    @api.marshal_with(mod_tag_list)
    @api.response('200', 'Success')
    @api.response('404', 'Tag not found')
    def get(self,uuid):
        ''' Gets details on a specific tag '''
        tag = Tag.query.filter_by(uuid=uuid).first()
        if tag:
            return tag
        else:
            ns_tag.abort(404, 'Tag not found.')
        return
    
    @api.expect(mod_tag)
    @api.marshal_with(mod_tag)
    def put(self, uuid):
        ''' Updates a tag '''
        tag = Tag.query.filter_by(uuid=uuid).first()
        if tag:
            if 'name' in api.payload and Tag.query.filter_by(name=api.payload['name']).first():
                ns_tag.abort(409, 'Tag name already exists.')
            else:
                tag.update(api.payload)
                return tag
        else:
            ns_tag.abort(404, 'Tag not found.')
        return

    def delete(self, uuid):
        ''' Deletes a tag '''
        tag = Tag.query.filter_by(uuid=uuid).first()
        if tag:
            tag.delete()
            return {'message': 'Sucessfully deleted tag.'}