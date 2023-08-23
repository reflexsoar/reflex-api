import datetime
from flask import make_response, request, current_app, session, redirect
from flask_restx import Resource, Namespace, fields
from ..model import User, ExpiredToken, Settings, SSOProvider
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

        auth.process_response(request_id=request_id)
        errors = auth.get_errors()
        not_auth_warn = not auth.is_authenticated()

        if len(errors) == 0:  # TURN THIS BACK TO 0 AFTER TESTING THIS WHOLE THING
            if 'AuthNRequestID' in session:
                del session['AuthNRequestID']

            user = User.get_by_email(auth.get_nameid())
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
        if user:

            org_uuid = user.organization
            # Get the users logon domain
            logon_domain = user.email.split('@')[1]

            provider = SSOProvider.get_by_logon_domain(logon_domain)

            if not provider:
                api.abort(401, 'Unauthorized.')

            settings = provider.get_sso_settings()

            req = prepare_flask_request(request)

            auth = init_saml_auth(req, settings)

            sso_built_url = auth.login()

            session['AuthNRequestID'] = auth.get_last_request_id()

            return sso_built_url

        api.abort(401, 'Unauthorized.')
