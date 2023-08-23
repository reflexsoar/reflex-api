from ..utils import token_required, user_has, ip_approved
from flask_restx import Resource, Namespace, fields
from ..model import SSOProvider
from .shared import mod_pagination, ISO8601, mod_user_list

api = Namespace('SSO', description='Reflex SSO Management', path='/sso')



mod_sso_advanced_security_settings = api.model('SSOAdvancedSecuritySettings', {
    'name_id_encrypted': fields.Boolean,
    'authn_requests_signed': fields.Boolean,
    'logout_requests_signed': fields.Boolean,
    'logout_response_signed': fields.Boolean,
    'signin_metadata': fields.Boolean,
    'want_messages_signed': fields.Boolean,
    'want_assertions_signed': fields.Boolean,
    'want_name_id': fields.Boolean,
    'want_name_id_encrypted': fields.Boolean,
    'want_assertions_encrypted': fields.Boolean,
    'allow_single_label_domains': fields.Boolean,
    'signature_algorithm': fields.Boolean,
    'digest_algorithm': fields.String,
    'reject_deprecated_algorithms': fields.String,
    'want_attribute_statement': fields.Boolean
})

mod_create_sso_provider = api.model('CreateSSOProvider', {
    'uuid': fields.String,
    'name': fields.String,
    'description': fields.String,
    'enabled': fields.Boolean,
    'idp_cert': fields.String,
    'idp_entity_id': fields.String,
    'idp_signon_url': fields.String,
    'idp_signout_url': fields.String,
    'auto_provision_users': fields.Boolean,
    'default_role': fields.String,
    'logon_domains': fields.List(fields.String),
    'acs_url': fields.String,
    'slo_url': fields.String,
    'security': fields.Nested(mod_sso_advanced_security_settings)
})

mod_sso_provider = api.model('SSOProvider', {
    'uuid': fields.String,
    'name': fields.String,
    'description': fields.String,
    'enabled': fields.Boolean,
    'idp_cert': fields.String,
    'idp_entity_id': fields.String,
    'idp_signon_url': fields.String,
    'idp_signout_url': fields.String,
    'auto_provision_users': fields.Boolean,
    'default_role': fields.String,
    'logon_domains': fields.List(fields.String),
    'acs_url': fields.String,
    'slo_url': fields.String,
    'created_at': ISO8601,
    'updated_at': ISO8601,
    'created_by': fields.Nested(mod_user_list),
    'updated_by': fields.Nested(mod_user_list),
    'active': fields.Boolean,
    'security': fields.Nested(mod_sso_advanced_security_settings)
})

mod_sso_provider_list = api.model('SSOProviderList', {
    'providers': fields.List(fields.Nested(mod_sso_provider))
})

@api.route("/provider/<uuid>/activate")
class SSOProviderActivate(Resource):

    @api.doc(security="Bearer")
    @api.marshal_with(mod_sso_provider)
    @ip_approved
    @token_required
    @user_has('update_sso_provider')
    def put(self, current_user, uuid):
        ''' Activates a SSO provider'''

        provider = SSOProvider.get_by_uuid(uuid)
        if not provider:
            api.abort(404, "Could not find a SSO provider")

        provider.update(active=True)

        return provider
    
@api.route("/provider/<uuid>/deactivate")
class SSOProviderDeactivate(Resource):

    @api.doc(security="Bearer")
    @api.marshal_with(mod_sso_provider)
    @ip_approved
    @token_required
    @user_has('update_sso_provider')
    def put(self, current_user, uuid):
        ''' Activates a SSO provider'''

        provider = SSOProvider.get_by_uuid(uuid)
        
        if not provider:
            api.abort(404, "Could not find a SSO provider")

        provider.update(active=False)

        return provider

@api.route("/provider")
class SSOProviderList(Resource):

    @api.doc(security="Bearer")
    @api.marshal_with(mod_sso_provider_list)
    @ip_approved
    @token_required
    @user_has('view_sso_providers')
    def get(self, current_user):
        ''' Returns a list of SSO providers'''

        realms = SSOProvider.search()

        return {
            'providers': [r for r in realms.scan()]
        }
    
    @api.doc(security="Bearer")
    @api.expect(mod_create_sso_provider, validate=True)
    @api.marshal_with(mod_sso_provider)
    @ip_approved
    @token_required
    @user_has('create_sso_provider')
    def post(self, current_user):
        ''' Creates a new SSO provider'''

        # Check if the name is already in use
        if SSOProvider.name_exists(api.payload['name']):
            api.abort(400, "A SSO provider with that name already exists")

        # Check if the uuid is already in use
        if SSOProvider.uuid_exists(api.payload['uuid']):
            api.abort(400, "An unexpected error occurred")
        
        provider = SSOProvider(**api.payload, active=False)
        provider.save()

        return provider