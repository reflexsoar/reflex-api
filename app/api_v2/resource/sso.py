from ..utils import token_required, user_has, ip_approved
from flask_restx import Resource, Namespace, fields
from ..model import SSOProvider
from .shared import mod_pagination, ISO8601, mod_user_list

api = Namespace('SSO', description='Reflex SSO Management', path='/sso')

mod_create_sso_provider = api.model('CreateSSOProvider', {
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
    'slo_url': fields.String
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
        
        provider = SSOProvider(**api.payload, active=False)
        provider.save()

        return provider