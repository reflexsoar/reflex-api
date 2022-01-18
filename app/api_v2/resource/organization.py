import math
from ..utils import token_required, user_has, ip_approved
from flask_restx import Resource, Namespace, fields, inputs as xinputs
from ..model import (
    Organization,
    User,
    Role,
    CaseStatus,
    CaseTemplate,
    CloseReason,
    DataType,
    EventStatus
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
    create_default_event_status
)

api = Namespace('Organizations',
                description="Organization operations", path="/organization")

mod_organization_list = api.model('OrganizationList', {
    'uuid': fields.String,
    'name': fields.String,
    'description': fields.String,
    'url': fields.String,
    #'logon_domains': fields.List(fields.String),
    'default_org': fields.Boolean()
})

mod_organization_list_paged = api.model('PagedOrganizationList', {
    'organizations': fields.List(fields.Nested(mod_organization_list)),
    'pagination': fields.Nested(mod_pagination)
})

mod_organization_create = api.model('CreateOrganization', {
    'name': fields.String,
    'description': fields.String,
    'url': fields.String,
    'logon_domains': fields.List(fields.String),
    'admin_user': fields.Nested(mod_user_create)
})


org_parser = api.parser()
org_parser.add_argument('page_size', location='args',
                        required=False, type=int, default=25)
org_parser.add_argument('page', location='args',
                        required=False, type=int, default=1)
org_parser.add_argument('sort_by', type=str, location='args',
                        default='created_at', required=False)
org_parser.add_argument('all', type=xinputs.boolean, default=False, location='args', required=False)


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

        # PERFORM FILTERING HERE
        # TODO: Implement filtering

        # PERFORM PAGINATION HERE
        page = args.page - 1
        total_orgs = search.count()
        pages = math.ceil(float(total_orgs / args.page_size))

        start = page*args.page_size
        end = args.page*args.page_size

        # If the user is requesting all the organizations use the scan()
        # function to retrieve them all
        if not args['all']:
            search = search[start:end]

            # PERFORM FINAL DOC FETCH HERE
            organizations = search.execute()
        else:
            organizations = search.scan()

        return {
            'organizations': organizations,
            'pagination': {
                'total_results': total_orgs,
                'pages': pages,
                'page': page+1,
                'page_size': args.page_size
            }
        }

    @api.doc(security="Bearer")
    @api.expect(mod_organization_create)
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

                return organization
            else:
                api.abort(400, 'Organization already using one or more of the supplied logon domains.')

        else:
            api.abort(400, 'Organization with supplied name already exists.')
