import math
from ..utils import page_results, token_required, user_has, ip_approved, default_org, check_org
from flask_restx import Resource, Namespace, fields
from ..model import Role
from .shared import mod_pagination, mod_permissions, mod_user_list, ISO8601

api = Namespace('Roles',
                description="Role operations", path="/role")

mod_role_create = api.model('RoleCreate', {
    'name': fields.String,
    'organization': fields.String(optional=True),
    'description': fields.String,
    'permissions': fields.Nested(mod_permissions)
}, strict=True)

mod_role_list = api.model('Role', {
    'uuid': fields.String,
    'organization': fields.String,
    'name': fields.String,
    'description': fields.String,
    'members': fields.List(fields.String),
    'permissions': fields.Nested(mod_permissions),
    'created_by': fields.Nested(mod_user_list),
    'created_at': ISO8601(attribute='created_at')
})

mod_role_list_paged = api.model('RolesPaged', {
    'roles': fields.Nested(mod_role_list),
    'pagination': fields.Nested(mod_pagination)
})

role_list_parser = api.parser()
role_list_parser.add_argument('organization', location='args', required=False)
role_list_parser.add_argument(
    'page', type=int, location='args', default=1, required=False)
role_list_parser.add_argument(
    'page_size', type=int, location='args', default=10, required=False)
role_list_parser.add_argument(
    'sort_by', type=str, location='args', default='created_at', required=False
)
role_list_parser.add_argument(
    'sort_direction', type=str, location='args', default='desc', required=False
)

@api.route("")
class RoleList(Resource):

    @api.doc(security="Bearer")
    @api.expect(role_list_parser)
    @api.marshal_with(mod_role_list_paged)
    @token_required
    @ip_approved
    @default_org    
    @user_has('view_roles')
    def get(self, user_in_default_org, current_user):
        ''' Returns a list of Roles '''

        args = role_list_parser.parse_args()

        roles = Role.search()

        if user_in_default_org:
            if args.organization:
                roles = roles.filter('term', organization=args.organization)

        roles = roles.exclude('term', name='Agent')

        sort_by = args.sort_by
        # Only allow these fields to be sorted on
        if sort_by not in ['name']:
            sort_by = "created_at"

        if args.sort_direction == 'desc':
            sort_by = f"-{sort_by}"

        roles = roles.sort(sort_by)

        # Do the pagination stuff
        roles, total_results, pages = page_results(roles, args.page, args.page_size)        

        roles = roles.execute()

        response = {
            'roles': list(roles),
            'pagination': {
                'total_results': total_results,
                'pages': pages,
                'page': args['page'],
                'page_size': args['page_size']
            }
        }

        return response

    @api.doc(security="Bearer")
    @api.expect(mod_role_create)
    @api.marshal_with(mod_role_list)
    @api.response('409', 'Role already exists.')
    @api.response('200', "Successfully created the role.")
    @token_required
    @ip_approved
    @check_org
    @user_has('add_role')
    def post(self, current_user):
        ''' Creates a new Role '''

        organization = None
        if 'organization' in api.payload:
            organization = api.payload['organization']

        role = Role.get_by_name(name=api.payload['name'], organization=organization)
       
        if not role:
            role = Role(name=api.payload['name'],
                        description=api.payload['description'],
                        permissions=api.payload['permissions'],
                        organization=organization
                    )
            role.save()
            return role
        else:
            api.abort(409, "Role with that name already exists.")


@api.route("/<uuid>")
class RoleDetails(Resource):

    @api.doc(security="Bearer")
    @api.expect(mod_role_create)
    @api.marshal_with(mod_role_list)
    @token_required
    @ip_approved
    @check_org
    @user_has('update_role')
    def put(self, uuid, current_user):
        ''' Updates an Role '''
        role = Role.get_by_uuid(uuid=uuid)

        if role:
            exists = Role.get_by_name(name=api.payload['name'], organization=api.payload['organization'])

            if 'name' in api.payload and exists and exists.uuid != role.uuid:
                api.abort(409, 'Role with that name already exists.')

            if 'organization' in api.payload and api.payload['organization'] != role.organization and role.members and len(role.members) > 0:
                api.abort(400, 'A role must be empty before it can be moved between Organizations.')

            else:
                role.update(**api.payload)
                return role
        else:
            api.abort(404, 'Role not found.')

    @api.doc(security="Bearer")
    @token_required
    @ip_approved
    @user_has('delete_role')
    def delete(self, uuid, current_user):
        ''' Removes a Role '''
        role = Role.get_by_uuid(uuid=uuid)
        if role:

            # Don't allow for the deletion of System Generated Roles
            if hasattr(role, 'system_generated') and role.system_generated:
                api.abort(
                    400, 'Can not delete a system generated role.'
                )

            # Don't allow for a role to be deleted if it still has members
            if role.members and len(role.members) > 0:
                api.abort(
                    400, 'Can not delete a role with assigned users.  Assign the users to a new role first.')
            else:
                role.delete()
                return {'message': 'Role successfully delete.'}
        else:
            api.abort(404, 'Role not found.')

    @api.doc(security="Bearer")
    @api.marshal_with(mod_role_list)
    @token_required
    @ip_approved
    @user_has('view_roles')
    def get(self, uuid, current_user):
        ''' Gets the details of a Role '''
        role = Role.get_by_uuid(uuid=uuid)
        if role:
            return role
        else:
            api.abort(404, 'Role not found.')

