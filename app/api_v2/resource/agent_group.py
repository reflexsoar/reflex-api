
from flask_restx import Resource, Namespace, fields, inputs as xinputs
from ..model import (
    AgentGroup,
)
from .shared import FormatTags, mod_pagination, ISO8601, mod_user_list
from .utils import redistribute_detections
from ..utils import check_org, token_required, user_has, ip_approved, page_results, generate_token, default_org
from ..schemas import mod_input_list

api = Namespace(
    'AgentGroup', description='Agent Group operations', path='/agent_group', strict=True)


mod_agent_group_create = api.model('AgentGroupList', {
    'uuid': fields.String,
    'organization': fields.String,
    'name': fields.String,
    'description': fields.String,
    'inputs': fields.List(fields.String)
})

mod_agent_group_brief = api.model('AgentGroupBrief', {
    'uuid': fields.String,
    'name': fields.String
})

mod_agent_group_list = api.model('AgentGroupList', {
    'uuid': fields.String,
    'organization': fields.String,
    'name': fields.String,
    'inputs': fields.List(fields.Nested(mod_input_list), attribute="_inputs"),
    'description': fields.String,
})

mod_agent_group_list_paged = api.model('AgentGroupListPaged', {
    'groups': fields.Nested(mod_agent_group_list),
    'pagination': fields.Nested(mod_pagination)
})


@api.route("/<uuid>")
class AgentGroupDetails(Resource):

    @api.doc(security="Bearer")
    @api.marshal_with(mod_agent_group_list)
    @token_required
    @user_has('view_agent_groups')
    def get(self, uuid, current_user):

        group = AgentGroup.get_by_uuid(uuid)
        if group:
            return group
        else:
            api.abort(404, 'Agent Group not found.')

    @api.doc(security="Bearer")
    @api.expect(mod_agent_group_create)
    @api.marshal_with(mod_agent_group_list)
    @token_required
    @default_org
    @user_has('update_agent_group')
    def put(self, uuid, user_in_default_org, current_user):

        group = AgentGroup.get_by_uuid(uuid)

        exists = None
        if 'name' in api.payload:
            if user_in_default_org:
                if 'organization' in api.payload:
                    exists = AgentGroup.get_by_name(api.payload['name'], organization=api.payload['organization'])
                else:
                    exists = AgentGroup.get_by_name(api.payload['name'])
            else:
                exists = AgentGroup.get_by_name(api.payload['name'])
       
            if exists and exists.uuid != uuid:
                api.abort(409, "Group with this name already exists")

        if group:
            group.update(**api.payload, refresh=True)
        
        return group

    @api.doc(security="Bearer")
    @token_required
    @user_has('delete_agent_group')
    def delete(self, uuid, current_user):

        group = AgentGroup.get_by_uuid(uuid)

        # Do not allow for deleting groups with agents assigned
        if group:
            if group.agents and len(group.agents) > 0:
                api.abort(400, 'Can not delete a group with agents assigned')

            group.delete()
            return {'message': f'Successfully deleted Agent Group {group.name}'}, 200
        else:
            api.abort(404, 'Agent Group not found')