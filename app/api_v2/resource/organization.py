import math
from ..utils import token_required, user_has, ip_approved, default_org, page_results
from flask_restx import Resource, Namespace, fields, inputs as xinputs
from ..model import (
    Organization,
    User,
    Role,
    CaseStatus,
    CaseTemplate,
    CloseReason,
    DataType,
    EventStatus,
    Settings
)
from .shared import ISO8601, ValueCount, AsNewLineDelimited, mod_pagination
from ..schemas import JSONField, mod_user_create
from ...defaults import (
    create_admin_role,
    create_agent_role,
    create_analyst_role,
    create_default_case_status,
    create_default_case_templates,
    create_default_closure_reasons,
    create_default_data_types,
    create_default_event_status,
    initial_settings
)
from ... import ep

api = Namespace('Organizations',
                description="Organization operations", path="/organization")

mod_organization_list = api.model('OrganizationList', {
    'uuid': fields.String,
    'name': fields.String,
    'description': fields.String,
    'url': fields.String,
    'logon_domains': AsNewLineDelimited(attribute='logon_domains'),
    'default_org': fields.Boolean()
})

mod_organization_list_paged = api.model('PagedOrganizationList', {
    'organizations': fields.List(fields.Nested(mod_organization_list)),
    'pagination': fields.Nested(mod_pagination)
})

mod_admin_user_create = api.model('AdminUserCreate', {
    'username': fields.String(required=True),
    'email': fields.String(required=True),
    'password': fields.String(required=True),
    'first_name': fields.String(required=True),
    'last_name': fields.String(required=True),
    'locked': fields.Boolean,
    'role_uuid': fields.String(required=False)
}, strict=True)

mod_organization_create = api.model('CreateOrganization', {
    'name': fields.String,
    'description': fields.String,
    'url': fields.String,
    'logon_domains': fields.List(fields.String),
    'admin_user': fields.Nested(mod_admin_user_create, required=True)
}, strict=True)


mod_organization_update = api.model('UpdateOrganization', {
    'name': fields.String,
    'description': fields.String,
    'url': fields.String,
    'logon_domains': fields.List(fields.String)
}, strict=True)


@api.route("/<uuid>")
class OrganizationDetails(Resource):
    '''
    Controls information about a specified Organization, retrieve details about
    the single organization, update the organization or delete it from the system
    '''

    @api.doc(security="Bearer")
    @api.marshal_with(mod_organization_list)
    @token_required
    @default_org
    @user_has('view_organizations')    
    def get(self, uuid, user_in_default_org, current_user):
        '''
        Returns the details about a single organization
        Members of the default organization can see the details of any organization
        '''

        organization = Organization.get_by_uuid(uuid=uuid)

        # If the user is the default organization allow them to view any organization
        if current_user.is_default_org():
            return organization
        
        # If the user is not the default organization and they try to access a different organization
        if not current_user.is_default_org() and organization.uuid != current_user.organization:
            api.abort(404, 'Organization not found.')

        return organization

    @api.doc(security="Bearer")
    @api.expect(mod_organization_update)
    @api.marshal_with(mod_organization_list)
    @token_required
    @default_org
    @user_has('update_organization')
    def put(self, uuid, user_in_default_org, current_user):
        '''
        Updates an organization
        Only members of the default organization with update_organization permissions
        can perform this action
        '''

        # If the user is not in the default organization reject them with 404
        if not user_in_default_org:
            api.abort(404, 'Organization not found.')

        organization = Organization.get_by_uuid(uuid=uuid)

        # Don't make updates to the default user
        if 'admin_user' in api.payload:
            api.payload.pop('admin_user')
        
        # Check to see if other organizations already use these logon domains
        if 'logon_domains' in api.payload:
            api.payload['logon_domains'] = api.payload['logon_domains'].split('\n')
            org = Organization.get_by_logon_domain(api.payload['logon_domains'])
            if org and org.uuid != organization.uuid:

                # Providing this feedback is probably a security issue but this action
                # can only be performed by the default tenants admin, an attacker would win
                # if they had this level of access anyway
                api.abort(400, 'Invalid logon domain provided.')

        organization.update(**api.payload, refresh=True)

        return organization

    @api.doc(security="Bearer")
    @token_required
    @default_org
    @user_has('delete_organization')
    def delete(self, uuid, user_in_default_org, current_user):
        '''
        Deletes the organization from the platform
        Only admins from the default organization with delete_organization 
        permissions can perform this action
        '''

        if not user_in_default_org:
            api.abort(404, 'Organization not found.')

        api.abort(501, 'Action not implemented yet.')


org_parser = api.parser()
org_parser.add_argument('page_size', location='args',
                        required=False, type=int, default=25)
org_parser.add_argument('page', location='args',
                        required=False, type=int, default=1)
org_parser.add_argument('sort_by', type=str, location='args',
                        default='created_at', required=False)
org_parser.add_argument('all', type=xinputs.boolean, default=False, location='args', required=False)
org_parser.add_argument(
    'sort_by', type=str, location='args', default='created_at', required=False
)
org_parser.add_argument(
    'sort_direction', type=str, location='args', default='desc', required=False
)

@api.route("")
class OrganizationList(Resource):
    '''
    Returns a list of organizations within the Reflex system'''

    @api.doc(security="Bearer")
    @api.marshal_with(mod_organization_list_paged)
    @api.expect(org_parser)
    @token_required
    @user_has('view_organizations')
    def get(self, current_user):

        args = org_parser.parse_args()

        search = Organization.search()

        search, total_results, pages = page_results(search, args.page, args.page_size)

        sort_by = args.sort_by

        # Only allow these fields to be sorted on
        if sort_by not in ['name','url','logon_domains']:
            sort_by = "created_at"

        if args.sort_direction == 'desc':
            sort_by = f"-{sort_by}"

        search = search.sort(sort_by)

        organizations = search.execute()
        
        return {
            'organizations': organizations,
            'pagination': {
                'total_results': total_results,
                'pages': pages,
                'page': args.page,
                'page_size': args.page_size
            }
        }

    @api.doc(security="Bearer")
    @api.expect(mod_organization_create, validate=True)
    @api.marshal_with(mod_organization_list)
    @token_required
    @user_has('add_organization')
    def post(self, current_user):
        '''
        Creates a new organization in the Reflex system
        Requires information about the first user (admin) for that
        organization/tenant
        '''

        org = Organization.get_by_name(name=api.payload['name'])

        if not org:

            admin_details = api.payload.pop('admin_user')
            admin_pass = admin_details.pop('password')

            org = Organization.get_by_logon_domain(api.payload['logon_domains'])

            if not org:

                organization = Organization(**api.payload)
                organization.default_org = False
                organization.save()

                admin_details['organization'] = organization.uuid

                admin_user = User(**admin_details)
                admin_user.set_password(admin_pass)
                admin_user.deleted = False
                admin_user.save()

                create_admin_role(Role, admin_user.uuid, org_id=organization.uuid)
                create_agent_role(Role, organization.uuid)
                create_analyst_role(Role, organization.uuid)
                create_default_case_status(CaseStatus, organization.uuid)
                create_default_case_templates(CaseTemplate, organization.uuid)
                create_default_closure_reasons(CloseReason, organization.uuid)
                create_default_data_types(DataType, organization.uuid)
                create_default_event_status(EventStatus, organization.uuid)
                initial_settings(Settings, organization.uuid)

                return organization
            else:
                api.abort(400, 'Organization already using one or more of the supplied logon domains.')

        else:
            api.abort(400, 'Organization with supplied name already exists.')


