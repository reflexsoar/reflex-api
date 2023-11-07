import datetime
from flask import request
from flask_restx import Resource, Namespace, fields, inputs as xinputs

from app.api_v2.model.integration import IntegrationConfiguration, Integration
from ..model import (
    Agent,
    AgentLogMessage,
    Settings,
    Role,
    AgentGroup,
    ExpiredToken
)

from app.api_v2.model.agent import PLUGGABLE_SUPPORTED_ROLES
from .shared import FormatTags, mod_pagination, ISO8601, mod_user_list
from .utils import redistribute_detections
from ..utils import check_org, token_required, user_has, ip_approved, page_results, generate_token, default_org
from .agent_group import mod_agent_group_list
from .agent_policy import mod_agent_policy_detailed, mod_agent_policy_v2
from ..schemas import mod_input_list

api = Namespace(
    'Agent', description='Reflex Agent administration', path='/agent', strict=True)


mod_agent_list = api.model('AgentList', {
    'uuid': fields.String,
    'organization': fields.String,
    'name': fields.String,
    'inputs': fields.List(fields.Nested(mod_input_list), attribute="_inputs"),
    'roles': fields.List(fields.String, default=[]),
    #'groups': fields.List(fields.Nested(mod_agent_group_list), attribute="_groups"),
    'active': fields.Boolean,
    'ip_address': fields.String,
    'healthy': fields.Boolean,
    'health_issues': fields.List(fields.String, default=[]),
    'last_heartbeat': ISO8601(attribute='last_heartbeat'),
    'policy': fields.Nested(mod_agent_policy_detailed, attribute="_policy"),
    'version': fields.String,
    'is_pluggable': fields.Boolean(default=False)
})

mod_agent_details = api.model('AgentList', {
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
    'last_heartbeat': ISO8601(attribute='last_heartbeat'),
    'policy': fields.Nested(mod_agent_policy_detailed, attribute="_policy"),
    'version': fields.String,
    'is_pluggable': fields.Boolean(default=False)
})

mod_agent_inputs = api.model('AgentInputs', {
    'inputs': fields.List(fields.Nested(mod_input_list)),
})

mod_agent_heartbeat = api.model('AgentHeartbeat', {
    'healthy': fields.Boolean,
    'health_issues': fields.List(fields.String),
    'recovered': fields.Boolean,
    'version': fields.String,
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

mod_create_log_message = api.model('AgentLogMessage', {
    'message': fields.String,
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
        if sort_by in ['health_issues','version']:
            sort_by = f"{sort_by}.keyword"
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

            if 'version' in api.payload:
                if 'plg' in api.payload['version']:
                    api.payload['is_pluggable'] = True

            # Pluggable agents can't be detectors as of 2023-11-06
            if 'roles' in api.payload and 'is_pluggable' in api.payload:
                for role in api.payload['roles']:
                    if role not in PLUGGABLE_SUPPORTED_ROLES:
                        api.abort(400, f"Role {role} is not supported by pluggable agents.")

            groups = None
            if 'groups' in api.payload and api.payload['groups']:
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

            #redistribute_detections(agent.organization)

            return {'message': 'Successfully created the agent.', 'uuid': str(agent.uuid), 'token': token}
        else:
            api.abort(409, "Agent already exists.")


@api.route("/heartbeat/<uuid>")
class AgentHeartbeat(Resource):

    @api.doc(security="Bearer")
    @api.expect(mod_agent_heartbeat)
    @token_required
    def post(self, uuid, current_user):
        '''Collects heartbeat and health check information from Agents'''
        agent = Agent.get_by_uuid(uuid=uuid)

        if agent:
            if current_user.uuid == agent.uuid:
                agent.last_heartbeat = datetime.datetime.utcnow()

                last_agent_health = agent.healthy

                agent.update(last_heartbeat=datetime.datetime.utcnow(),
                             **api.payload, refresh=True)
                
                #if 'detector' in agent.roles:
                    # If agent was previously healthy and is not now redistribute detections
                    #if api.payload['healthy'] == False and last_agent_health == True:
                    #    redistribute_detections(organization=agent.organization)

                    # If agent was previously unhealthy and is now healthy redistribute detections
                    #if api.payload['healthy'] == True and last_agent_health in [False, None]:
                    #    redistribute_detections(organization=agent.organization)

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
        '''DEPRECATED: Collects heartbeat and health check information from Agents.  
        Will be removed in the future for the POST version of this endpoint.
        '''
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

@api.route("/inputs")
class AgentInputs(Resource):

    @api.doc(security="Bearer")
    @api.marshal_with(mod_agent_inputs)
    @token_required
    @user_has('view_agents')
    def get(self, current_user):
        ''' Returns a list of Inputs for an Agent '''

        agent = Agent.get_by_uuid(uuid=current_user.uuid)
        if agent:
            _inputs = []
            [_inputs.append(_input) for _input in agent._inputs]
            for group in agent._groups:
                [_inputs.append(_input) for _input in group._inputs]
                
            return {'inputs': _inputs}
        else:
            api.abort(404, "Agent not found.")

@api.route("/<uuid>/policy")
class AgentPolicy(Resource):

    @api.doc(security="Bearer")
    @api.marshal_with(mod_agent_policy_v2)
    @token_required
    @user_has('view_agents')
    def get(self, uuid, current_user):
        ''' Returns the policy for an Agent '''
        agent = Agent.get_by_uuid(uuid=uuid)
        if agent:

            policy = {
                'uuid': agent._policy.uuid,
                'name': agent._policy.name,
                'description': agent._policy.description,
                'organization': agent._policy.organization,
                'roles': agent._policy.roles,
                'role_settings': {
                    'detector': agent._policy.detector_config,
                    'poller': agent._policy.poller_config,
                    'runner': agent._policy.runner_config,
                    'mitre': agent._policy.mitre_mapper_config,
                    'fim': agent._policy.fim_config
                },
                'settings': {
                    'health_check_interval': agent._policy.health_check_interval,
                    'logging_level': agent._policy.logging_level,
                    'max_intel_db_size': agent._policy.max_intel_db_size,
                    'disable_event_cache_check': agent._policy.disable_event_cache_check,
                    'event_realert_ttl': agent._policy.event_realert_ttl
                },
                'tags': agent._policy.tags,
                'priority': agent._policy.priority,
                'revision': agent._policy.revision,
                'created_at': agent._policy.created_at,
                'updated_at': agent._policy.updated_at,
                'created_by': agent._policy.created_by,
                'updated_by': agent._policy.updated_by
            }

            return policy
        else:
            api.abort(404, "Agent not found.")


@api.route("/policy/outputs")
class AgentPolicyOutputs(Resource):

    @api.doc(security="Bearer")
    @token_required
    @user_has('view_agents')
    def get(self, current_user):
        '''Returns configuration details about all the outputs that are configured
        for an Agent to use
        '''

        search = IntegrationConfiguration.search()
        search = search.filter('term', organization=current_user.organization)
        search = search.filter('term', enabled=True)
        results = [r for r in search.scan()]

        integrations = Integration.search()
        integrations = integrations.filter('terms', product_identifier=[r.integration_uuid for r in results])
        integrations = [i for i in integrations.scan()]

        outputs = []
        for result in results:
            integration = next((i for i in integrations if i.product_identifier == result.integration_uuid), None)
            if integration:
                for action in result.actions:
                    action_manifest = integration.get_action_manifest(action)
                    if action_manifest.type == 'output':
                        _action = result.actions[action].to_dict()
                        if _action['enabled']:
                            action_config = {
                                'integration': integration.product_identifier,
                                "integration_name": integration.name,
                                'configuration_name': result.name,
                                'configuration_uuid': result.uuid,
                                "value": f"{integration.product_identifier}|{result.uuid}|{action}",
                                'name': action,
                                'description': action_manifest.description,
                                'settings': _action
                            }
                            outputs.append(action_config)
        
        return {
            "outputs": outputs
        }
    
@api.route("/policy/inputs")
class AgentPolicyInputs(Resource):

    @api.doc(security="Bearer")
    @token_required
    @user_has('view_agents')
    def get(self, current_user):
        '''Returns configuration details about all the outputs that are configured
        for an Agent to use
        '''

        search = IntegrationConfiguration.search()
        search = search.filter('term', organization=current_user.organization)
        search = search.filter('term', enabled=True)
        results = [r for r in search.scan()]


        integrations = Integration.search()
        integrations = integrations.filter('terms', product_identifier=[r.integration_uuid for r in results])
        integrations = [i for i in integrations.scan()]

        inputs = []
        for result in results:
            integration = next((i for i in integrations if i.product_identifier == result.integration_uuid), None)
            if integration:
                for action in result.actions:
                    action_manifest = integration.get_action_manifest(action)
                    if action_manifest.type == 'input':
                        _action = result.actions[action].to_dict()
                        if _action['enabled']:
                            action_config = {
                                'integration': integration.product_identifier,
                                "integration_name": integration.name,
                                'configuration_name': result.name,
                                'configuration_uuid': result.uuid,
                                "value": f"{integration.product_identifier}|{result.uuid}|{action}",
                                'name': action,
                                'description': action_manifest.description,
                                'settings': _action
                            }
                            inputs.append(action_config)
        
        return {
            "inputs": inputs
        }

@api.route("/<uuid>")
class AgentDetails(Resource):

    @api.doc(security="Bearer")
    @api.expect(mod_agent_create)
    @api.marshal_with(mod_agent_details)
    @token_required
    @user_has('update_agent')
    def put(self, uuid, current_user):
        ''' Updates an Agent '''
        agent = Agent.get_by_uuid(uuid=uuid)
        if agent:

            # Pluggable agents can't be detectors as of 2023-11-06
            if 'roles' in api.payload and agent.is_pluggable:
                for role in api.payload['roles']:
                    if role not in PLUGGABLE_SUPPORTED_ROLES:
                        api.abort(400, f"Role {role} is not supported by pluggable agents.")

            agent.update(**api.payload, refresh=True)          

            #if 'roles' in api.payload:
            #    redistribute_detections(organization=agent.organization)

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
    @api.marshal_with(mod_agent_details)
    @token_required
    @user_has('view_agents')
    def get(self, uuid, current_user):
        ''' Gets the details of a Agent '''
        agent = Agent.get_by_uuid(uuid=uuid)
        if agent:
            return agent
        else:

            api.abort(404, 'Agent not found.')


@api.route("/log")
class AgentLog(Resource):

    @api.doc(security="Bearer")
    @api.expect(mod_create_log_message)
    @token_required
    @user_has('create_agent_log')
    def post(self, current_user):
        ''' Creates a log message for an Agent '''
        print(current_user.to_dict())
        agent = Agent.get_by_uuid(uuid=current_user.uuid)
        if agent:
            log = AgentLogMessage(agent_uuid=current_user.uuid,
                message=api.payload['message'])
            log.save()
            return {'message': 'Log message successfully created.'}
        else:

            api.abort(404, 'Agent not found.')

