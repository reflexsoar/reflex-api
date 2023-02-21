from flask_restx import Resource, Namespace, ValidationError, fields, inputs as xinputs

from app.api_v2.model.user import Organization

from ..model import ServiceAccount
from .shared import mod_permissions, DEFAULT_ORG_ONLY_PERMISSIONS
from ..utils import token_required, user_has

api = Namespace('ServiceAccount', description="Service Account operations", path="/service_account")

mod_create_service_account = api.model('CreateServiceAccount', {
    'name': fields.String(required=True, description="Name of the service account"),
    'description': fields.String(required=False, description="Description of the service account"),
    'organization_scope': fields.List(fields.String, required=False, description="List of organization IDs that the service account can access"),
    'active': fields.Boolean(required=False, description="Is the service account active"),
    'permissions': fields.Nested(mod_permissions, required=True, description="Permissions for the service account"),
}, strict=True)

mod_service_account_created = api.model('ServiceAccountCreated', {
    'uuid': fields.String(required=True, description="UUID of the service account"),
    'access_token': fields.String(required=True, description="Access token for the service account")
})

mod_service_account_list = api.model('ServiceAccountList', {
    'uuid': fields.String(required=True, description="UUID of the service account"),
    'name': fields.String(required=True, description="Name of the service account"),
    'description': fields.String(required=False, description="Description of the service account"),
    'organization_scope': fields.List(fields.String, required=False, description="List of organization IDs that the service account can access"),
    'active': fields.Boolean(required=False, description="Is the service account active"),
    'permissions': fields.Nested(mod_permissions, required=True, description="Permissions for the service account"),
    'last_used': fields.DateTime(required=False, description="Last time the service account was used"),
}, strict=True)

@api.route('/')
class ServiceAccountList(Resource):
    @api.doc(security='Bearer')
    @api.marshal_with(mod_service_account_list, as_list=True, envelope='service_accounts')
    @token_required
    @user_has('view_service_accounts')
    def get(self, current_user):
        '''
        List service accounts
        '''
        return [account for account in ServiceAccount.search().scan()]

    @api.doc(security='Bearer')
    @api.expect(mod_create_service_account)
    @api.marshal_with(mod_service_account_created)
    @token_required
    @user_has('create_service_account')
    def post(self, current_user):
        '''
        Create service account
        '''
        # Service accounts can't have the following permissions
        if any([api.payload['permissions'][permission] and permission in DEFAULT_ORG_ONLY_PERMISSIONS for permission in api.payload['permissions']]):
            api.abort(400, f"Service accounts can't have the following permissions: {', '.join(DEFAULT_ORG_ONLY_PERMISSIONS)}")

        # Only a user in the default organization can set the organization scope of a service account
        # by default, the organization scope will be the same as the user's organization
        if getattr(current_user, 'default_org', False) is not True:
            api.payload['organization_scope'] = []
            
        api.payload['organization_scope'].append(current_user.organization)
        
        if len(api.payload['organization_scope']) > 0:
            organizations = Organization.search().filter('terms', uuid=api.payload['organization_scope'])
            organizations = organizations.scan()
            found_org_uuids = [organization.uuid for organization in organizations]
            missing_orgs = list(set(api.payload['organization_scope']) - set(found_org_uuids))
            if len(missing_orgs) > 0:
                api.abort(400, f"Organization(s) [{', '.join(missing_orgs)}] not found")

        service_account = ServiceAccount(**api.payload)
        try:
            service_account.save()
        except ValidationError as e:
            api.abort(400, e)
        access_token = service_account.create_access_token()
        return {'uuid': str(service_account.uuid), 'access_token': access_token}, 201
            
    