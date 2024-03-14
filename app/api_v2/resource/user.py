import random
import string
import base64
import imghdr
from io import BytesIO

import pyqrcode
from flask_restx import Namespace, Resource, fields
from flask_restx import inputs as xinputs
from flask import make_response, request
from werkzeug.utils import secure_filename

from ..model import Organization, Role, User
from ..utils import (check_org, ip_approved, log_event, page_results,
                     token_required, user_has, user_scope_has, request_user)
from .shared import ISO8601, mod_pagination, mod_permissions

api = Namespace('User', description='User related operations', path='/user')


mod_api_key = api.model('UserApiKey', {
    'api_key': fields.String
})

mod_toggle_user_mfa = api.model('UserUUIDs', {
    'users': fields.List(fields.String),
    'mfa_enabled': fields.Boolean
})

mod_user_update = api.model('UserUpdate', {
    'username': fields.String,
    'email': fields.String,
    'password': fields.String,
    'first_name': fields.String,
    'last_name': fields.String,
    'locked': fields.Boolean
})

mod_password_update = api.model('PasswordUpdate', {
    'password': fields.String
})

mod_user_role_no_perms = api.model('UserRoleNoPerms', {
    'uuid': fields.String,
    'name': fields.String,
    'description': fields.String
})

mod_user_full = api.model('UserFull', {
    'uuid': fields.String,
    'organization': fields.String,
    'username': fields.String,
    'email': fields.String,
    'first_name': fields.String,
    'last_name': fields.String,
    'last_logon': ISO8601(attribute='last_logon'),
    'locked': fields.Boolean,
    'mfa_enabled': fields.Boolean,
    'failed_logons': fields.Integer,
    'disabled': fields.Boolean,
    'created_at': ISO8601(attribute='created_at'),
    'updated_at': ISO8601(attribute='updated_at'),
    'role': fields.List(fields.Nested(mod_user_role_no_perms))
})

mod_user_brief = api.model('UserBrief', {
    'uuid': fields.String,
    'username': fields.String,
    'email': fields.String,
    'first_name': fields.String,
    'last_name': fields.String
})

mod_user_role_no_members = api.model('UserRole', {
    'uuid': fields.String,
    'permissions': fields.Nested(mod_permissions),
    'name': fields.String,
    'description': fields.String
})

mod_user_role_brief = api.model('UserRoleBrief', {
    'uuid': fields.String,
    'name': fields.String,
    'description': fields.String
})

mod_user_self = api.model('UserSelf', {
    'uuid': fields.String,
    'username': fields.String,
    'first_name': fields.String,
    'last_name': fields.String,
    'email': fields.String,
    'role': fields.List(fields.Nested(mod_user_role_brief)),
    'mfa_enabled': fields.Boolean,
    'organization': fields.String,
    'default_org': fields.Boolean,
    'permissions': fields.Nested(mod_permissions),
    'last_logon': ISO8601
})

mod_user_create_success = api.model('UserCreateSuccess', {
    'message': fields.String,
    'user': fields.Nested(mod_user_full)
})

mod_user_create = api.model('UserCreate', {
    'organization': fields.String(required=False),
    'username': fields.String(required=True),
    'email': fields.String(required=True),
    'password': fields.String(required=True),
    'first_name': fields.String(required=True),
    'last_name': fields.String(required=True),
    'locked': fields.Boolean,
    'role_uuid': fields.List(fields.String(required=True))
}, strict=True)

mod_user_list_paged = api.model('UserListPaged', {
    'users': fields.List(fields.Nested(mod_user_full)),
    'pagination': fields.Nested(mod_pagination)
})

mod_mfa_token = api.model('MFATOTP', {
    'token': fields.String
})

mod_user_notification_settings = api.model('UserNotificationSettings', {
    'email_mention': fields.Boolean,
    'email_case_comment': fields.Boolean,
    'email_case_status': fields.Boolean,
    'email_case_assign': fields.Boolean,
    'email_new_case': fields.Boolean,
    'email_case_task_status': fields.Boolean,
    'email_case_task_assign': fields.Boolean,
    'email_case_task_create': fields.Boolean,
    'email_case_task_status': fields.Boolean,
    'only_watched_cases': fields.Boolean
})


@api.route("/me")
class UserInfo(Resource):

    @api.doc(security="Bearer")
    @api.marshal_with(mod_user_self)
    @token_required
    @ip_approved
    def get(self, current_user):
        ''' Returns information about the currently logged in user '''
        if isinstance(current_user, User):
            role = Role.get_by_member(current_user.uuid)
            organization = Organization.get_by_uuid(current_user.organization)
            current_user.role = current_user.roles
            current_user.default_org = organization.default_org

        return current_user

scope_permission_parser = api.parser()
scope_permission_parser.add_argument('organization', location='args', type=str, action='split', required=False, help='Organization UUID')

@api.route("/test/scoped_user_list")
class TestScopedUserList(Resource):

    @api.doc(security="Bearer")
    @api.expect(scope_permission_parser)
    @api.marshal_with(mod_user_list_paged)
    @token_required
    @user_scope_has('view_users')
    def get(self, current_user):
        ''' TEST SCOPED GET REQUESTS '''

        users = User.scoped_search()

        return {
            'users': users,
            'pagination': {
                'total_results': len(users),
                'page': 1,
                'pages': 1,
                'page_size': len(users)
            }
        }

@api.route("/test/scoped_user_create")
class TestScopedUserCreate(Resource):

    @api.doc(security="Bearer")
    @api.expect(mod_user_create)
    @api.marshal_with(mod_user_create_success)
    @token_required
    @user_scope_has('add_user')
    def post(self, current_user):
        ''' TEST SCOPED POST REQUESTS '''

        data = api.payload

        return {'message': 'success', 'user': data}


@api.route('/generate_api_key')
class UserGenerateApiKey(Resource):

    @api.doc(security="Bearer")
    @api.marshal_with(mod_api_key)
    @token_required
    @user_has('use_api')
    def get(self, current_user):
        ''' Returns a new API key for the user making the request '''
        return current_user.generate_api_key()


@api.route('/generate_mfa_qr')
class UserGenerateMFAQr(Resource):

    @api.doc(security="Bearer")
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


@api.route('/validate_mfa_setup')
class UserValidateMFASetup(Resource):

    @api.doc(security="Bearer")
    @api.expect(mod_mfa_token)
    @token_required
    def post(self, current_user):
        ''' Checks to see if the user has successfully completed the MFA setup
        by verifying the first TOTP given by their authenticator app
        '''
        if 'token' in api.payload and api.payload['token'] is not None:
            valid_token = current_user.verify_mfa_setup_complete(
                api.payload['token'])
            if valid_token:
                return {'message': 'Succesfully enabled MFA'}, 200
            else:
                return {'message': 'Invalid TOTP Token'}, 400
        else:
            api.abort(400, 'TOTP token required.')


@api.route('/enable_mfa')
class UserEnableMFA(Resource):

    @api.doc(security="Bearer")
    @token_required
    def get(self, current_user):
        ''' Enables MFA for the current user '''
        current_user.generate_mfa_secret()
        return {'message': 'Secret Generated'}, 200


@api.route('/disable_mfa')
class UserDisableMFA(Resource):

    @api.doc(security="Bearer")
    @token_required
    def get(self, current_user):
        ''' Enables MFA for the current user '''
        current_user.disable_mfa()
        return {'message': 'MFA disabled'}, 200


@api.route('/toggle_mfa')
class ToggleMFA(Resource):

    @api.doc(security="Bearer")
    @api.expect(mod_toggle_user_mfa)
    @token_required
    @user_has('update_user')
    def put(self, current_user):
        ''' Enables or disables MFA for multiple users '''

        if 'users' in api.payload:
            users = User.get_by_uuid(uuid=api.payload['users'])
        enabled_disabled = ''
        user_action = []
        if users:
            for user in users:
                if 'mfa_enabled' in api.payload:
                    if api.payload['mfa_enabled'] == True:
                        try:
                            user.enable_mfa()
                            enabled_disabled = 'enabled'
                            user_action.append(
                                {'uuid': user.uuid, 'success': True})
                        except Exception as e:
                            user_action.append(
                                {'uuid': user.uuid, 'success': False})
                    elif api.payload['mfa_enabled'] == False:
                        try:
                            user.disable_mfa()
                            enabled_disabled = 'disabled'
                            user_action.append(
                                {'uuid': user.uuid, 'success': True})
                        except:
                            user_action.append(
                                {'uuid': user.uuid, 'success': False})
                else:
                    api.abort('Missing mfa_enable field.'), 400

        return {'message': f'MFA {enabled_disabled}'}, 200


@api.route("/<uuid>/unlock")
class UnlockUser(Resource):

    @api.doc(security="Bearer")
    @api.marshal_with(mod_user_full)
    @token_required
    @user_has('unlock_user')
    def put(self, uuid, current_user):
        ''' Unlocks a user and resets their failed logons back to 0 '''
        user = User.get_by_uuid(uuid)
        if user:
            user.unlock()
            log_event(event_type="User Management",
                      message=f"User {user.username} was unlocked.", source_user=current_user.username, status="Success")
            return user
        else:
            api.abort(404, 'User not found.')

def validate_image(stream):
    header = stream.read(512)
    stream.seek(0)
    format = imghdr.what(None, header)
    if not format:
        return None
    return (format if format in ['jpeg', 'png', 'jpg'] else 'jpg')

from werkzeug.datastructures import FileStorage
profile_picture_parser = api.parser()
profile_picture_parser.add_argument('profile_picture_input', location='files', type=FileStorage, required=True)
    
@api.route("/<uuid>/profile_picture")
class ProfilePicture(Resource):

    @api.doc(security="Bearer")
    @token_required
    def get(self, uuid, current_user):
        """ Returns an HTTP response containing the users profile picture.
        Sets the appropriate content-type header based on the file extension
        of the profile picture.  ANd informs the browser to cache the image
        for several minutes.
        """

        content_type_map = {
            'jpg': 'image/jpeg',
            'jpeg': 'image/jpeg',
            'png': 'image/png'
        }

        user = User.get_by_uuid(uuid)
        if user:
            if user.profile_picture:
                response_headers = {
                    'Accept': 'image/jpeg, image/png',
                    'Content-Type': content_type_map[user.profile_picture_type],
                    'Cache-Control': 'max-age=300',
                    'Pragma': 'cache',
                    'Expires': '300',
                }

                image_data = base64.b64decode(user.profile_picture)

                response = make_response(image_data, 200, response_headers)
                return response
            else:
                return {'message': 'User has no profile picture.'}, 400
        
        api.abort(404, 'File not found')

   
    @api.doc(security="Bearer")
    @api.expect(profile_picture_parser)
    @token_required
    def post(self, uuid, current_user):
        """ Updates the users profile picture.  The profile picture is stored
        as a base64 encoded string in the database.  The file extension is
        stored in the profile_picture_type field.
        """

        MAX_IMAGE_SIZE = 1024 * 1024 * 5 # 5MB
        SUPPORTED_EXTENSIONS = ['jpg', 'jpeg', 'png']

        user = User.get_by_uuid(uuid)
        if user:
            if user != current_user:
                api.abort(404, 'User not found.')

            uploaded_file = request.files['profile_picture_input']
            filename = secure_filename(uploaded_file.filename)
            if filename != '':
                file_extension = filename.split('.')[-1]
                if file_extension in SUPPORTED_EXTENSIONS and file_extension == validate_image(uploaded_file.stream):
                    if uploaded_file.content_length < MAX_IMAGE_SIZE:
                        user.profile_picture = base64.b64encode(uploaded_file.read()).decode('utf-8')
                        user.profile_picture_type = file_extension
                        user.update(profile_picture=user.profile_picture, profile_picture_type=user.profile_picture_type, refresh='wait_for')
                        return {'message': 'Profile picture updated.'}, 200
                    else:
                        api.abort(400, 'File too large.')
                else:
                    print(f'Invalid file type. {file_extension} is not {validate_image(uploaded_file.stream)}')
                    api.abort(400, 'Invalid file type.')
        else:
            api.abort(404, 'User not found.')

    @api.doc(security="Bearer")
    @token_required
    def delete(self, uuid, current_user):
        ''' Removes the users current profile picture '''

        user = User.get_by_uuid(uuid)

        if user:
            if user != current_user:
                api.abort(403, 'User not found.')

            user.update(profile_picture=None, profile_picture_type=None, refresh='wait_for')

            return {'message': 'Profile picture removed.'}, 200
        
        api.abort(404, 'User not found.')

user_parser = api.parser()
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


@api.route("")
class UserList(Resource):

    @api.doc(security="Bearer")
    @api.marshal_with(mod_user_list_paged, as_list=True)
    @api.expect(user_parser)
    @token_required
    @user_has('view_users')
    @check_org
    def get(self, current_user):
        ''' Returns a list of users '''

        args = user_parser.parse_args()

        users = User.search()

        if args['username']:
            users = users.filter(
                'wildcard', username__keyword=args.username+"*")

        if args['organization']:
            users = users.filter('term', organization=args.organization)

        if args.deleted:
            users = users.filter('match', deleted=True)
        else:
            users = users.filter('match', deleted=False)

        users, total_results, pages = page_results(
            users, args.page, args.page_size)

        sort_by = args.sort_by

        # These fields are default Text but can only sort by Keyword so force them to keyword fields
        if sort_by in ['username', 'first_name', 'last_name', 'email']:
            sort_by = f"{sort_by}.keyword"

        if args.sort_direction == 'desc':
            sort_by = f"-{sort_by}"

        users = users.sort(sort_by)

        users = [r for r in users.scan()]
        [user.load_roles() for user in users]


        response = {
            'users': users,
            'pagination': {
                'total_results': total_results,
                'pages': pages,
                'page': args['page'],
                'page_size': args['page_size']
            }
        }

        return response

    @api.doc(security="Bearer")
    @api.expect(mod_user_create, validate=True)
    @api.marshal_with(mod_user_create_success)
    @api.response('409', 'User already exists.')
    @api.response('200', "Successfully created the user.")
    @token_required
    @user_has('add_user')
    def post(self, current_user):
        ''' Creates a new user '''

        # Check to see if the user already exists
        user = User.get_by_email(api.payload['email'])
        if user:
            api.abort(409, "User with this e-mail already exists.")
        else:
            

            if api.payload.get('organization') == None and hasattr(current_user, 'default_org') and current_user.default_org:
                api.abort(400, "Organization is required.")

            # Strip the organization field if the user is not a member of the default
            # organization
            # TODO: replace with @check_org wrapper
            if 'organization' in api.payload and hasattr(current_user, 'default_org') and not current_user.default_org:
                api.payload.pop('organization')

            roles_to_modify = []
            if 'role_uuid' in api.payload:
                user_role = api.payload.pop('role_uuid')
                role = Role.get_by_uuid(uuid=user_role)

                # Check that the target role is part of the target organization
                for r in role:
                    if r.organization == api.payload.get('organization'):
                        roles_to_modify.append(r)

            user_password = api.payload.pop('password')
            user = User(**api.payload)
            user.set_password(user_password)
            user.deleted = False

            if roles_to_modify:
                for role in roles_to_modify:
                    role.add_user_to_role(user.uuid)
                #user.role = roles_to_modify
            
            user.save()

            # Load the users roles
            user.load_roles()

            return {'message': 'Successfully created the user.', 'user': user}


@api.route("/set_password")
class UserSetPassword(Resource):

    @api.doc(security="Bearer")
    @api.expect(mod_password_update)
    @api.marshal_with(mod_user_full)
    @token_required
    def put(self, current_user):
        '''
        Allows the current_user to set their password, the current_user is targeted
        by the users access credentials
        '''

        if 'password' in api.payload:
            current_user.set_password(api.payload['password'])
            current_user.save()
        else:
            api.abort(400, 'Password required.')


@api.route('/notification_settings')
class UserNotificationSettings(Resource):

    @api.doc(security="Bearer")
    @api.marshal_with(mod_user_notification_settings)
    @token_required
    def get(self, current_user):
        ''' Returns the current users notification settings '''

        return current_user.notification_settings

    @api.doc(security="Bearer")
    @api.expect(mod_user_notification_settings)
    @api.marshal_with(mod_user_notification_settings)
    @token_required
    def put(self, current_user):
        ''' Updates the current users notification settings '''

        current_user.notification_settings = api.payload
        current_user.save()

        return current_user.notification_settings


@api.route("/<uuid>")
class UserDetails(Resource):

    @api.doc(security="Bearer")
    @api.marshal_with(mod_user_full)
    @token_required
    @user_has('view_users')
    def get(self, uuid, current_user):
        ''' Returns information about a user '''
        user = User.get_by_uuid(uuid)
        if user:
            return user
        else:
            api.abort(404, 'User not found.')

    @api.doc(security="Bearer")
    @api.expect(mod_user_update)
    @api.marshal_with(mod_user_full)
    @token_required
    @user_has('update_user')
    def put(self, uuid, current_user):
        ''' Updates information for a user '''

        user = User.get_by_uuid(uuid)
        if user:

            modified = False

            if 'username' in api.payload:
                target_user = User.get_by_username(api.payload['username'])
                if target_user:
                    if target_user.uuid == uuid:
                        del api.payload['username']
                    else:
                        api.abort(409, 'Username already taken.')

            if 'email' in api.payload:
                target_user = User.get_by_email(api.payload['email'])
                if target_user:

                    if target_user.uuid == uuid:
                        del api.payload['email']
                    else:
                        api.abort(409, 'Email already taken.')
                organization = Organization.get_by_uuid(user.organization)
                if organization:
                    if 'email' in api.payload:
                        email_domain = api.payload['email'].split('@')[1]
                        if email_domain not in organization.logon_domains:
                            api.abort(400, 'Invalid logon domain.')

            # Allow the user to save their own password regardless of their permissions
            if 'password' in api.payload and user.uuid == current_user.uuid:
                pw = api.payload.pop('password')
                user.set_password(pw)
                modified = True

            if 'password' in api.payload and not current_user.has_right('reset_user_password'):
                api.payload.pop('password')

            if 'password' in api.payload and current_user.has_right('reset_user_password'):
                pw = api.payload.pop('password')
                user.set_password(pw)
                modified = True

            # Update the users role if a role update is triggered
            if 'role_uuid' in api.payload and api.payload['role_uuid'] is not None:

                role_uuid = api.payload.pop('role_uuid')

                # Get the users current roles
                current_roles = user.roles
                new_roles = Role.get_by_uuid(role_uuid, all_results=True)

                appended_roles = []
                
                remove_from = [r for r in current_roles if r.uuid not in role_uuid]
                add_to = [r for r in new_roles if r not in current_roles]

                for role in add_to:
                    role.add_user_to_role(user_id=user.uuid)
                    appended_roles.append(role)

                for role in remove_from:
                    role.remove_user_from_role(user_id=user.uuid)

            if modified:
                user.save()

            if len(api.payload) > 0:
                user.update(**api.payload)

            user.load_roles()

            return user
        else:
            api.abort(404, 'User not found.')

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
        user = User.get_by_uuid(uuid)
        if user:
            if current_user.uuid == user.uuid:
                api.abort(403, 'User can not delete themself.')
            else:
                user.deleted = True
                random_identifier = ''.join(random.choice(
                    string.ascii_lowercase) for i in range(5))
                user.username = f"{user.username}-DELETED-{random_identifier}"
                user.email = None
                user.locked = True
                user.save()
                return {'message': 'User successfully deleted.'}
        else:
            api.abort(404, 'User not found.')
