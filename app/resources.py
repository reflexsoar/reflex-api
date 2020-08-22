import datetime
import jwt
import json
import base64
import cryptography
from flask import request, current_app, abort
from flask_restx import Api, Resource, Namespace, fields, Model
from .models import User, db, RefreshToken, AuthTokenBlacklist, Role, Credential, Tag, Permission
from sqlalchemy.dialects.postgresql import UUID
from .utils import token_required, user_has, _get_current_user
from .schemas import *

api = Api()

# Namespaces
ns_user = api.namespace('User', description='User operations', path='/user')
ns_auth = api.namespace('Auth', description='Authentication operations', path='/auth')
ns_role = api.namespace('Role', description='Role operations', path='/role')
ns_perms = api.namespace('Permission', description='Permission operations', path='/permission')
ns_tag = api.namespace('Tag', description='Tag operations', path='/tag')
ns_credential = api.namespace('Credential', description='Credential operations', path='/credential')

# Expect an API token
expect_token = api.parser()
expect_token.add_argument('Authorization', location='headers')

# Register all the models this is redundant when using api.model() but we don't use this
# TODO: Fix this so this hack isn't required, app factory is jacking this up
for model in schema_models:
    api.models[model.name] = model


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
    @token_required
    @user_has('add_credential')
    @api.expect(mod_credential_create)
    @api.response('400', 'Successfully created credential.')
    @api.response('409', 'Credential already exists.')
    def post(self, current_user):
        ''' Encrypts the password '''
        master_password = api.payload.pop('master_password')
        credential = Credential.query.filter_by(name=api.payload['name']).first()
        if not credential:
            credential = Credential(**api.payload)
            credential.encrypt(api.payload['password'].encode(), master_password)
            credential.create()
            return {'message': 'Successfully created credential.', 'uuid': credential.uuid}, 200
        else:
            ns_credential.abort(409, 'Credential already exists.')


@ns_credential.route('/decrypt')
class DecryptPassword(Resource):
    
    @api.doc(security="Bearer")
    @token_required
    @user_has('decrypt_credential')
    @api.expect(mod_credential_decrypt)
    @api.marshal_with(mod_credential_return)
    @api.response('404', 'Credential not found.')
    def post(self, current_user):
        ''' Decrypts the credential for use '''
        credential = Credential.query.filter_by(uuid=api.payload['uuid']).first()
        if credential:
            value = credential.decrypt(api.payload['master_password'])
            if value:
                return {'password': value}
            else:
                ns_credential.abort(401, 'Invalid master password.')
        else:
            ns_credential.abort(404, 'Credential not found.')
        
        
@ns_credential.route('/<uuid>')
class DeletePassword(Resource):
    
    @api.doc(security="Bearer")
    @token_required
    @user_has('view_credentials')
    @api.marshal_with(mod_credential_full)
    @api.response('404', 'Credential not found.')
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
                master_password = None
                if 'master_password' and 'password' in api.payload:
                    master_password = api.payload.pop('master_password')
                credential.update(api.payload)
                if master_password:
                    credential.encrypt(api.payload['password'].encode(), master_password)
                    credential.save()
                return credential
        else:
            ns_credential.abort(404, 'Credential not found.')

    @api.doc(security="Bearer")
    @token_required
    @user_has('delete_credential')
    @api.response('404', 'Credential not found.')
    @api.response('200', "Credential sucessfully deleted.")
    def delete(self, uuid, current_user):
        ''' Deletes a credential '''
        credential = Credential.query.filter_by(uuid=uuid).first()
        if credential:
            credential.delete()
            return {'message': 'Credential successfully deleted.'}
        else:
            ns_credential.abort(404, 'Credential not found.')