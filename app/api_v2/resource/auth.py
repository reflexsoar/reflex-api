import datetime
from flask import make_response, request, current_app, session, redirect
from flask_restx import Resource, Namespace, fields

from app.api_v2.resource.utils import generate_random_password
from ..model import User, ExpiredToken, Settings, SSOProvider, RoleMappingPolicy, Role
from ..utils import log_event, token_required, check_password_reset_token, ip_approved

from onelogin.saml2.auth import OneLogin_Saml2_Auth
from onelogin.saml2.response import OneLogin_Saml2_Response
from onelogin.saml2.settings import OneLogin_Saml2_Settings
from onelogin.saml2.utils import OneLogin_Saml2_Utils

api = Namespace('Auth', description='Authentication operations', path='/auth')

mod_mfa_challenge = api.model('MFAChallenge', {
    'mfa_challenge_token': fields.String,
    'token': fields.String
})

mod_auth_success_token = api.model('AuthSuccessToken', {
    'access_token': fields.String
})

mod_auth = api.model('AuthModel', {
    'email': fields.String(default='admin@reflexsoar.com'),
    'password': fields.String(default='reflex')
})


@api.route('/mfa')
class MultiFactor(Resource):

    @api.expect(mod_mfa_challenge)
    @api.response(200, 'Success', mod_auth_success_token)
    @api.response(401, 'Incorrect token')
    def post(self):
        '''Check the users challenge against their TOTP'''

        user = check_password_reset_token(api.payload['mfa_challenge_token'])
        if user:
            if user.verify_totp(api.payload['token']):
                # Generate an access token
                _access_token = user.create_access_token()

                # Generate a refresh tokenn
                _refresh_token = user.create_refresh_token(
                    request.user_agent.string.encode('utf-8'))
                log_event(event_type="Authentication", source_user=user.username,
                          source_ip=request.remote_addr, message="Successful MFA Check.", status="Success")
                return {'access_token': _access_token, 'refresh_token': _refresh_token, 'user': user.uuid}, 200
            log_event(event_type="Authentication", source_user=user.username,
                      source_ip=request.remote_addr, message="Failed MFA Challenge", status="Failure")

        api.abort(401, 'Invalid TOTP token')


mod_user_email = api.model('UserEmail', {
    'email': fields.String
})


@api.route("/forgot_password")
class ForgotPassword(Resource):

    @api.expect(mod_user_email)
    def post(self):

        if current_app.config['PASSWORD_SSPR_DISABLED']:
            api.abort(401, 'Self-service password reset is disabled.')

        # Get the user by email
        user = User.get_by_email(api.payload['email'])

        if user:
            user.send_sspr_email()
        
        return {'message': 'A password reset e-mail has been generated.'}, 200
    
mod_password_reset_confirmation = api.model('PasswordResetConfirmation', {
    'password': fields.String(required=True),
    'confirm_password': fields.String(required=True)
}, validate=True)

@api.route('/reset_password/<string:token>')
class ResetPassword(Resource):

    def get(self, token):

        if current_app.config['PASSWORD_SSPR_DISABLED']:
            api.abort(401, 'Self-service password reset is disabled.')

        user = check_password_reset_token(token)

        if user:
            return {'message': 'Valid token.'}, 200

        api.abort(401, 'Invalid token.')

    @api.expect(mod_password_reset_confirmation)
    def post(self, token):

        if current_app.config['PASSWORD_SSPR_DISABLED']:
            api.abort(400, 'Self-service password reset is disabled.')

        user = check_password_reset_token(token)

        if 'password' not in api.payload or 'confirm_password' not in api.payload:
            api.abort(400, 'Passwords do not match.')

        if user:
            if api.payload['password'] != api.payload['confirm_password']:
                api.abort(400, 'Passwords do not match.')

            user.set_password(api.payload['password'])
            user.save()
            expired = ExpiredToken(token=token)
            expired.save()
            return {'message': 'Password updated.'}, 200

        api.abort(400, 'Invalid reset token.')


@api.route("/login")
class Login(Resource):

    @api.expect(mod_auth)
    @api.response(200, 'Success', mod_auth_success_token)
    @api.response(401, 'Incorrect username or password')
    @ip_approved
    def post(self):
        '''
        Log a user in to the platform and provide them with an access_token a refresh_token
        '''

        # Find the user based on their username, if their account is locked don't return a user
        # object to prevent processing any more failed logons
        if 'email' not in api.payload:
            api.abort(401, 'Incorrect username or password')

        user = User.get_by_email(api.payload['email'])

        if not user:
            api.abort(401, 'Incorrect username or password')

        if not user.roles:
            log_event(organization=user.organization, event_type="Authentication", source_user=user.username,
                      source_ip=request.remote_addr, message="User is not assigned any roles.", status="Failed")
            api.abort(401, 'User has not been assigned a role.')

        if user.check_password(api.payload['password']):

            # Generate an access token
            _access_token = user.create_access_token()

            # Generate a refresh tokenn
            _refresh_token = user.create_refresh_token(
                request.user_agent.string.encode('utf-8'))

            # Update the users failed_logons and last_logon entries
            user.update(failed_logons=0,
                        last_logon=datetime.datetime.utcnow(), refresh=True)

            log_event(organization=user.organization, event_type="Authentication", source_user=user.username,
                      source_ip=request.remote_addr, message="Successful Authentication.", status="Success")

            if user.mfa_enabled:
                return {'mfa_challenge_token': user.create_mfa_challenge_token()}
            else:
                return {'access_token': _access_token, 'refresh_token': _refresh_token, 'user': user.uuid}, 200

        if user.failed_logons == None:
            user.update(failed_logons=0, refresh=True)

        if user.failed_logons >= Settings.load().logon_password_attempts:
            user.update(locked=True, refresh=True)
            log_event(organization=user.organization, event_type="Authentication", source_user=user.username,
                      source_ip=request.remote_addr, message="Account Locked.", status="Failed")
        else:
            user.update(failed_logons=user.failed_logons+1, refresh=True)
            log_event(organization=user.organization, event_type="Authentication", source_user=user.username,
                      source_ip=request.remote_addr, message="Bad username or password.", status="Failed")

        api.abort(401, 'Incorrect username or password')


@api.route('/logout')
class Logout(Resource):

    @api.doc(security="Bearer")
    @api.response(200, 'Successfully logged out.')
    @api.response(401, 'Not logged in.')
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


def init_saml_auth(req, settings):
    auth = OneLogin_Saml2_Auth(req, old_settings=settings)
    return auth


def prepare_flask_request(request):

    https_on = 'on' if request.scheme == 'https' else 'off'

    if current_app.config['SSO_FORCE_HTTPS']:
        https_on = 'on'

    return {
        'https': https_on,
        'http_host': request.host,
        'script_name': request.path,
        'get_data': request.args.copy(),
        'post_data': request.form.copy()
    }

@api.route('/sso/<provider_uuid>/acs')
class SSOACS(Resource):

    def post(self, provider_uuid):

        provider = SSOProvider.get_by_uuid(provider_uuid)

        if not provider:
            api.abort(401, 'Unauthorized.')

        settings = provider.get_sso_settings()

        req = prepare_flask_request(request)

        auth = init_saml_auth(req, settings)
        
        request_id = None
        if 'AuthNRequestID' in session:
            request_id = session['AuthNRequestID']

        if request_id:
            auth.process_response(request_id=request_id)
        else:
            auth.process_response()

        errors = auth.get_errors()
        not_auth_warn = not auth.is_authenticated()

        if len(errors) == 0:  # TURN THIS BACK TO 0 AFTER TESTING THIS WHOLE THING
            if 'AuthNRequestID' in session:
                del session['AuthNRequestID']

            user = User.get_by_email(auth.get_nameid())

            if not user:
                if provider.auto_provision_users:
                    # Get the 
                    # Print all the attributes provided by the IdP
                    attributes = auth.get_attributes()
                    attribute_errors = []
                    wanted_attributes = {
                        'first_name': None,
                        'last_name': None,
                        'email': None,
                        'username': None
                    }
                    for wanted_attribute in wanted_attributes:
                        if wanted_attribute in attributes:
                            wanted_attributes[wanted_attribute] = attributes[wanted_attribute][0]
                        else:
                            attribute_errors.append(wanted_attribute)

                    if attribute_errors:
                        log_event(organization=provider.organization, event_type="SSO Authentication", source_user=auth.get_nameid(),
                            source_ip=request.remote_addr, message=f"User does not exist. Auto provisioning failed, missing attributes: {attribute_errors}", status="Failed")
                        return redirect(f"{current_app.config['SSO_BASE_URL']}/#/login", 401)
                    
                    # Check to see if the username is already in use
                    if User.get_by_username(wanted_attributes['username']):
                        log_event(organization=provider.organization, event_type="SSO Authentication", source_user=wanted_attributes['username'],
                            source_ip=request.remote_addr, message=f"User does not exist. Auto provisioning failed, username already in use.", status="Failed")
                        return redirect(f"{current_app.config['SSO_BASE_URL']}/#/login", 401)
                    
                    # Check to see if the email is already in use
                    if User.get_by_email(wanted_attributes['email']):
                        log_event(organization=provider.organization, event_type="SSO Authentication", source_user=wanted_attributes['username'],
                            source_ip=request.remote_addr, message=f"User does not exist. Auto provisioning failed, email already in use.", status="Failed")
                        return redirect(f"{current_app.config['SSO_BASE_URL']}/#/login", 401)
                    
                    # Create the user
                    user = User(
                        username=wanted_attributes['username'],
                        first_name=wanted_attributes['first_name'],
                        last_name=wanted_attributes['last_name'],
                        email=wanted_attributes['email'],
                        organization=provider.organization,
                        mfa_enabled=False,
                        from_sso_auto_provision=True,
                        locked=False
                    )
                    user.set_password(generate_random_password())
                    user.deleted = False
                    user.save(refresh="wait_for")

                    role = Role.get_by_uuid(provider.default_role)
                    if role:
                        role.add_user_to_role(user.uuid)
                    
                else:
                    log_event(organization=provider.organization, event_type="SSO Authentication", source_user=user.username,
                      source_ip=request.remote_addr, message="User does not exist.", status="Failed")
                    return redirect(f"{current_app.config['SSO_BASE_URL']}/#/login", 401)

            # Fetch the users role mapping policies

            role_mapping = RoleMappingPolicy.search()
            role_mapping = role_mapping.filter('term', organization=user.organization)
            role_mapping = role_mapping.filter('term', active=True)
            role_mapping = [r for r in role_mapping.scan()]
            
            policy_match = False
            sso_asserted_roles = []
            if role_mapping:
                for policy in role_mapping:
                    if policy_match:
                        break
                    for mapping in policy.role_mappings:
                        attribute_value = auth.get_attribute(mapping.attribute)
                        role = mapping.check_match(attribute_value)
                        if role:
                            sso_asserted_roles.append(role)
                            policy_match = True
            
                # Load all the roles for the organization
                roles = Role.get_by_organization(user.organization)

                # If sso_asserted_roles contains a role that the user is not already a member of
                # add the user
                for role in roles:
                    if role.uuid in sso_asserted_roles and user.uuid not in role.members:
                        role.add_user_to_role(user.uuid)

                # If the user is a member of a role that is not in sso_asserted_roles remove them
                # from the role
                for role in roles:
                    if role.members:
                        if role.uuid not in sso_asserted_roles and user.uuid in role.members:
                            role.remove_user_from_role(user.uuid)

            # If the user now has no roles
            if not user.roles:
                log_event(organization=user.organization, event_type="SSO Authentication", source_user=user.username,
                      source_ip=request.remote_addr, message="User is not assigned any roles.", status="Failed")
                return redirect(f"{current_app.config['SSO_BASE_URL']}/#/login")
            
            # If the user is locked
            if user.locked:
                log_event(organization=user.organization, event_type="SSO Authentication", source_user=user.username,
                      source_ip=request.remote_addr, message="User account is locked.", status="Failed")
                return redirect(f"{current_app.config['SSO_BASE_URL']}/#/login")

            access_token = user.create_access_token()
            refresh_token = user.create_refresh_token(
                request.user_agent.string.encode('utf-8'))

            self_url = OneLogin_Saml2_Utils.get_self_url(req)
            if 'RelayState' in request.form and self_url != request.form['RelayState']:

                # TODO: Set this back to RelayState
                response = make_response(redirect(f"{current_app.config['SSO_BASE_URL']}/#/dashboard"))

                # TODO: SECURITY CHECK: This is probably not the best way to do this
                response.set_cookie('access_token', access_token)
                response.set_cookie('refresh_token', refresh_token)

                return response
        elif auth.get_settings().is_debug_active():
            error_reason = auth.get_last_error_reason()
            current_app.logger.error(error_reason)
            
        return redirect(f"{current_app.config['SSO_BASE_URL']}/#/login")

@api.route('/ssostart')
class SSOStart(Resource):

    def post(self):

        # TODO: Check the email address is valid and get the organization ID
        # Redirect the user to the SSO URL for the organization
        user = User.get_by_email(api.payload['email'])

        # Get the users logon domain
        if user:
            logon_domain = user.email.split('@')[1]
        else:
            logon_domain = api.payload['email'].split('@')[1]

        if not logon_domain:
            api.abort(401, 'Unauthorized.')

        provider = SSOProvider.get_by_logon_domain(logon_domain)

        if not provider:
            api.abort(401, 'Unauthorized.')
        
        if user or provider.auto_provision_users:

            settings = provider.get_sso_settings()

            req = prepare_flask_request(request)

            auth = init_saml_auth(req, settings)

            sso_built_url = auth.login()

            session['AuthNRequestID'] = auth.get_last_request_id()

            return sso_built_url

        api.abort(401, 'Unauthorized.')
