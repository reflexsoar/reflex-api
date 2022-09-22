
import datetime
from flask import request
from flask_restx import Resource, Namespace, fields, inputs as xinputs
from ..model import (
    Agent,
    Settings,
    Role,
    AgentGroup,
    ExpiredToken
)
from .shared import FormatTags, mod_pagination, ISO8601, mod_user_list
from .utils import redistribute_detections
from ..utils import check_org, token_required, user_has, ip_approved, page_results, generate_token, default_org
from .agent_group import mod_agent_group_list
from ..schemas import mod_input_list

api = Namespace(
    'Agent', description='Reflex Agent administration', path='/agent', strict=True)


mod_agent_list = api.model('AgentList', {
    'uuid': fields.String,
    'organization': fields.String,
    'name': fields.String,
    'inputs': fields.List(fields.Nested(mod_input_list), attribute="_inputs"),
    'roles': fields.List(fields.String),
    'groups': fields.List(fields.Nested(mod_agent_group_list), attribute="_groups"),
    'active': fields.Boolean,
    'ip_address': fields.String,
    'healthy': fields.Boolean,
    'health_issues': fields.List(fields.String),
    'last_heartbeat': ISO8601(attribute='last_heartbeat')
})

mod_agent_heartbeat = api.model('AgentHeartbeat', {
    'healthy': fields.Boolean,
    'health_issues': fields.List(fields.String),
    'recovered': fields.Boolean
})

mod_agent_list_paged = api.model('AgentListPaged', {
    'agents': fields.Nested(mod_agent_list),
    'pagination': fields.Nested(mod_pagination)
})

mod_paged_agent_group_list = api.model('PagedAgentGroupList', {
    'groups': fields.List(fields.Nested(mod_agent_group_list)),
    'pagination': fields.Nested(mod_pagination)
})

mod_agent_create = api.model('AgentCreate', {
    'name': fields.String,
    'roles': fields.List(fields.String),
    'groups': fields.List(fields.String),
    'ip_address': fields.String,
    'inputs': fields.List(fields.String)
})


@api.route("/pair_token")
class AgentPairToken(Resource):

    @api.doc(security="Bearer")
    @token_required
    @user_has('pair_agent')
    def get(self, current_user):
        ''' 
        Generates a short lived pairing token used by the agent to get a long running JWT
        '''

        settings = Settings.load()
        return generate_token(None, settings.agent_pairing_token_valid_minutes, current_user.organization, 'pairing')


agent_list_parser = api.parser()
agent_list_parser.add_argument('organization', location='args', required=False)
agent_list_parser.add_argument(
    'page', type=int, location='args', default=1, required=False)
agent_list_parser.add_argument(
    'page_size', type=int, location='args', default=10, required=False)
agent_list_parser.add_argument(
    'sort_by', type=str, location='args', default='created_at', required=False
)
agent_list_parser.add_argument(
    'sort_direction', type=str, location='args', default='desc', required=False
)


@api.route("")
class AgentList(Resource):

    @api.doc(security="Bearer")
    @api.marshal_with(mod_agent_list_paged, as_list=True)
    @api.expect(agent_list_parser)
    @token_required
    @default_org
    @user_has('view_agents')
    def get(self, user_in_default_org, current_user):
        ''' Returns a list of Agents '''

        args = agent_list_parser.parse_args()

        agents = Agent.search()

        if user_in_default_org:
            if args.organization:
                agents = agents.filter('term', organization=args.organization)

        sort_by = args.sort_by
        if args.sort_direction == 'desc':
            sort_by = f"-{sort_by}"

        agents = agents.sort(sort_by)

        agents, total_results, pages = page_results(
            agents, args.page, args.page_size)

        response = {
            'agents': list(agents),
            'pagination': {
                'total_results': total_results,
                'pages': pages,
                'page': args['page'],
                'page_size': args['page_size']
            }
        }

        return response

    @api.doc(security="Bearer")
    @api.expect(mod_agent_create)
    @api.response('409', 'Agent already exists.')
    @api.response('200', "Successfully created the agent.")
    @token_required
    @user_has('add_agent')
    def post(self, current_user):
        ''' Creates a new Agent '''

        agent = Agent.get_by_name(name=api.payload['name'])
        if not agent:

            groups = None
            if 'groups' in api.payload:
                groups = api.payload.pop('groups')
                groups = AgentGroup.get_by_name(
                    name=groups, organization=current_user['organization'])
                if groups:
                    if isinstance(groups, AgentGroup):
                        api.payload['groups'] = [groups.uuid]
                    else:
                        api.payload['groups'] = [g.uuid for g in groups]

            agent = Agent(**api.payload)
            agent.save(refresh=True)

            # Add the agent to the groups
            if groups:
                if isinstance(groups, list):
                    [group.add_agent(agent.uuid) for group in groups]
                else:
                    groups.add_agent(agent.uuid)

            # Add the agent to the agent role
            role = Role.get_by_name(
                name='Agent', organization=agent.organization)
            role.add_user_to_role(agent.uuid)

            token = generate_token(str(
                agent.uuid), 525600*5, token_type='agent', organization=current_user['organization'])

            redistribute_detections(agent.organization)

            return {'message': 'Successfully created the agent.', 'uuid': str(agent.uuid), 'token': token}
        else:

            api.abort(409, "Agent already exists.")


@api.route("/heartbeat/<uuid>")
class AgentHeartbeat(Resource):

    @api.doc(security="Bearer")
    @api.expect(mod_agent_heartbeat)
    @token_required
    def post(self, uuid, current_user):
        agent = Agent.get_by_uuid(uuid=uuid)

        if agent:
            if current_user.uuid == agent.uuid:
                agent.last_heartbeat = datetime.datetime.utcnow()

                last_agent_health = agent.healthy

                agent.update(last_heartbeat=datetime.datetime.utcnow(),
                             **api.payload, refresh=True)

                # If agent was previously healthy and is not now redistribute detections
                if api.payload['healthy'] == False and last_agent_health == True:
                    redistribute_detections(organization=agent.organization)

                # If agent was previously unhealthy and is now healthy redistribute detections
                if api.payload['healthy'] == True and last_agent_health in [False, None]:
                    redistribute_detections(organization=agent.organization)

                return {'message': 'Your heart still beats!'}
        else:
            '''
            If the agent can't be found, revoke the agent token
            '''

            auth_header = request.headers.get('Authorization')
            access_token = auth_header.split(' ')[1]
            expired = ExpiredToken(token=access_token)
            expired.save()

            api.abort(400, 'Your heart stopped.')

    @api.doc(security="Bearer")
    @token_required
    def get(self, uuid, current_user):
        agent = Agent.get_by_uuid(uuid=uuid)
        if agent:
            agent.last_heartbeat = datetime.datetime.utcnow()
            agent.save()
            return {'message': 'Your heart still beats!'}
        else:
            '''
            If the agent can't be found, revoke the agent token
            '''

            auth_header = request.headers.get('Authorization')
            access_token = auth_header.split(' ')[1]
            expired = ExpiredToken(token=access_token)
            expired.save()

            api.abort(400, 'Your heart stopped.')


@api.route("/<uuid>")
class AgentDetails(Resource):

    @api.doc(security="Bearer")
    @api.expect(mod_agent_create)
    @api.marshal_with(mod_agent_list)
    @token_required
    @user_has('update_agent')
    def put(self, uuid, current_user):
        ''' Updates an Agent '''
        agent = Agent.get_by_uuid(uuid=uuid)
        if agent:

            agent.update(**api.payload, refresh=True)

            if 'roles' in api.payload:
                redistribute_detections(organization=agent.organization)

            return agent
        else:

            api.abort(404, 'Agent not found.')

    @api.doc(security="Bearer")
    @token_required
    @user_has('delete_agent')
    def delete(self, uuid, current_user):
        ''' Removes a Agent '''
        agent = Agent.get_by_uuid(uuid=uuid)
        if agent:
            role = Role.get_by_name(
                name='Agent', organization=agent.organization)
            role.remove_user_from_role(uuid)
            agent.delete()
            return {'message': 'Agent successfully delete.'}
        else:

            api.abort(404, 'Agent not found.')

    @api.doc(security="Bearer")
    @api.marshal_with(mod_agent_list)
    @token_required
    @user_has('view_agents')
    def get(self, uuid, current_user):
        ''' Gets the details of a Agent '''
        agent = Agent.get_by_uuid(uuid=uuid)
        if agent:
            return agent
        else:

            api.abort(404, 'Agent not found.')
