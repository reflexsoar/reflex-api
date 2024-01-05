import io
import gzip
import json
import datetime

# Import geolite library for geoip lookups
from geolite2 import geolite2

from flask import request
from flask_restx import Resource, Namespace, fields, inputs as xinputs

from app.api_v2.model.integration import IntegrationConfiguration, Integration
from app.api_v2.resource.agent_tag import mod_agent_tag_short
from ..model import (
    Agent,
    AgentLogMessage,
    Settings,
    Role,
    AgentGroup,
    AgentTag,
    ExpiredToken,
    ApplicationInventory
)

from app.api_v2.model.benchmark import (
    archive_agent_results,
    BenchmarkResultHistory,
    BenchmarkResult
)

from app.api_v2.model.agent import PLUGGABLE_SUPPORTED_ROLES
from app.api_v2.rql.parser import QueryParser
from .shared import mod_pagination, ISO8601, JSONField
from ..utils import token_required, page_results, user_has, generate_token, default_org
from .agent_group import mod_agent_group_list
from .agent_policy import mod_agent_policy_detailed, mod_agent_policy_v2
from ..schemas import mod_input_list

api = Namespace(
    'Agent', description='Reflex Agent administration', path='/agent', strict=True)

mod_agent_network_interfaces = api.model('AgentNetworkInterfaces', {
    'name': fields.String,
    'mac': fields.String,
    'ip': fields.String,
    'netmask': fields.String,
    'broadcast': fields.String,
})

mod_agent_local_users = api.model('AgentLocalUsers', {
    'username': fields.String,
    'terminal': fields.String,
    'host': fields.String,
    'session_start': ISO8601,
    'groups': fields.List(fields.String)
})

mod_local_user_brief = api.model('LocalUserBrief', {
    'username': fields.String,
    'groups': fields.List(fields.String)
})

mod_agent_system_info = api.model('AgentSystemInfo', {
    'type': fields.String,
    'os_release': fields.String,
    'os_version': fields.String,
    'os_name': fields.String,
    'machine': fields.String,
    'hostname': fields.String,
    'processor': fields.String,
    'architecture': fields.String,
})

mod_agent_chassis_info = api.model('AgentChassisInfo', {
    'domain': fields.String,
    'domain_role': fields.Integer,
    'model': fields.String,
    'manufacturer': fields.String,
    'system_family': fields.String,
    'system_sku': fields.String,
    'workgroup': fields.String,
    'serial_number': fields.String,
    'chassis_type': fields.String,
})

mod_agent_listening_ports = api.model('AgentListeningPorts', {
    'pid': fields.Integer,
    'process_name': fields.String,
    'process_path': fields.String,
    'process_user': fields.String,
    'port': fields.Integer,
    'protocol': fields.String,
    'status': fields.String,
    'family': fields.String,
    'parent_pid': fields.Integer,
    'parent_process_name': fields.String,
    'parent_process_path': fields.String,
    'parent_process_user': fields.String,
})

mod_agent_services = api.model('AgentServices', {
    'display_name': fields.String,
    'binpath': fields.String,
    'username': fields.String,
    'start_type': fields.String,
    'status': fields.String,
    'pid': fields.Integer,
    'name': fields.String,
    'description': fields.String
})

mod_agent_software_package = api.model('AgentSoftwarePackage', {
    'name': fields.String,
    'version': fields.String,
    'vendor': fields.String,
    'identifying_number': fields.String,
    'install_date': fields.String,
    'install_source': fields.String,
    'local_package': fields.String,
    'package_cache': fields.String,
    'package_code': fields.String,
    'package_name': fields.String,
    'url_info_about': fields.String,
    'language': fields.String
})

mod_container_port_binding = api.model('ContainerPortBinding', {
    'HostIp': fields.String,
    'HostPort': fields.String
})

mod_container_port = api.model('ContainerPort', {
    'port': fields.String,
    'protocol': fields.String,
    'bindings': fields.List(fields.Nested(mod_container_port_binding))
})

mod_container_network_settings = api.model('ContainerNetworkSettings', {
    'Bridge': fields.String,
    'SandboxID': fields.String,
    'SandboxKey': fields.String,
    'HairpinMode': fields.Boolean,
    'LinkLocalIPv6Address': fields.String,
    'LinkLocalIPv6PrefixLen': fields.Integer,
    'GlobalIPv6Address': fields.String,
    'GlobalIPv6PrefixLen': fields.Integer,
    'Ports': fields.List(fields.Nested(mod_container_port)),
    'MacAddress': fields.String,
    'IPv6Gateway': fields.String,
    'IPAddress': fields.String,
    'IPPrefixLen': fields.Integer,
    'IPv6Gateway': fields.String,
    'Gateway': fields.String,
    'EndpointID': fields.String,
    'SecondaryIPAddresses': fields.List(fields.String),
    'SecondaryIPv6Addresses': fields.List(fields.String),
})

mod_exposed_port = api.model('ContainerExposedPort', {
    'port': fields.String,
    'protocol': fields.String
})

mod_container_volume = api.model('ContainerVolume', {
    'name': fields.String,
})

mod_container_config = api.model('ContainerConfig', {
    'Hostname': fields.String,
    'Domainname': fields.String,
    'User': fields.String,
    'AttachStdin': fields.Boolean,
    'AttachStdout': fields.Boolean,
    'AttachStderr': fields.Boolean,
    'ExposedPorts': fields.List(fields.Nested(mod_exposed_port)),
    'Tty': fields.Boolean,
    'OpenStdin': fields.Boolean,
    'StdinOnce': fields.Boolean,
    'Env': fields.List(fields.String),
    'Cmd': fields.List(fields.String),
    'Image': fields.String,
    'Volumes': fields.List(fields.Nested(mod_container_volume)),
    'WorkingDir': fields.String,
    'Entrypoint': fields.List(fields.String),
    'Labels': fields.List(fields.String)
})

mod_container_state = api.model('ContainerState', {
    'Status': fields.String,
    'Running': fields.Boolean,
    'Paused': fields.Boolean,
    'Restarting': fields.Boolean,
    'OOMKilled': fields.Boolean,
    'Dead': fields.Boolean,
    'Pid': fields.Integer,
    'ExitCode': fields.Integer,
    'Error': fields.String,
    'StartedAt': ISO8601,
    'FinishedAt': ISO8601
})

mod_container_info = api.model('ContainerInfo', {
    'id' : fields.String,
    'created' : ISO8601,
    'path' : fields.String,
    'state' : fields.Nested(mod_container_state),
    'image' : fields.String,
    'resolv_conf_path' : fields.String,
    'hostname_path' : fields.String,
    'hosts_path' : fields.String,
    'log_path' : fields.String,
    'name' : fields.String,
    'driver' : fields.String,
    'restart_count' : fields.Integer,
    'platform' : fields.String,
    'mount_label' : fields.String,
    'process_label' : fields.String,
    'app_armor_profile' : fields.String,
    'exec_ids' : fields.List(fields.String),
    'network_settings': fields.Nested(mod_container_network_settings),
    'config': fields.Nested(mod_container_config)
})


mod_agent_host_information = api.model('AgentHostInformation', {
    'timezone': fields.String,
    'network_adapters': fields.List(fields.Nested(mod_agent_network_interfaces)),
    'users': fields.List(fields.Nested(mod_agent_local_users)),
    'last_reboot': ISO8601,
    'system': fields.Nested(mod_agent_system_info),
    'chassis': fields.Nested(mod_agent_chassis_info),
    'listening_ports': fields.List(fields.Nested(mod_agent_listening_ports)),
    'services': fields.List(fields.Nested(mod_agent_services)),
    'installed_software': fields.List(fields.Nested(mod_agent_software_package)),
    'local_users': fields.List(fields.Nested(mod_local_user_brief)),
    'containers': fields.List(fields.Nested(mod_container_info))
})

mod_agent_geo_information = api.model('AgentGeoInformation', {
    'country': fields.String,
    'country_code': fields.String,
    'continent': fields.String,
    'continent_code': fields.String,
    'city': fields.String,
    'state': fields.String,
    'state_code': fields.String,
    'latitude': fields.Float,
    'longitude': fields.Float,
    'metro_code': fields.Integer,
    'time_zone': fields.String
})

mod_agent_list = api.model('AgentList', {
    'uuid': fields.String,
    'organization': fields.String,
    'name': fields.String,
    'identifier': fields.String,
    'inputs': fields.List(fields.Nested(mod_input_list), attribute="_inputs"),
    'roles': fields.List(fields.String, default=[]),
    #'groups': fields.List(fields.Nested(mod_agent_group_list), attribute="_groups"),
    'active': fields.Boolean,
    'ip_address': fields.String,
    'console_visible_ip': fields.String,
    'geo': fields.Nested(mod_agent_geo_information),
    'healthy': fields.Boolean,
    'health_issues': fields.List(fields.String, default=[]),
    'last_heartbeat': ISO8601(attribute='last_heartbeat'),
    'policy': fields.Nested(mod_agent_policy_detailed, attribute="_policy"),
    'version': fields.String,
    'is_pluggable': fields.Boolean(default=False),
    'tags': fields.List(fields.Nested(mod_agent_tag_short))
})


mod_agent_details = api.model('AgentList', {
    'uuid': fields.String,
    'organization': fields.String,
    'name': fields.String,
    'identifier': fields.String,
    'inputs': fields.List(fields.Nested(mod_input_list), attribute="_inputs"),
    'roles': fields.List(fields.String),
    'groups': fields.List(fields.Nested(mod_agent_group_list), attribute="_groups"),
    'active': fields.Boolean,
    'ip_address': fields.String,
    'console_visible_ip': fields.String,
    'geo': fields.Nested(mod_agent_geo_information),
    'healthy': fields.Boolean,
    'health_issues': fields.List(fields.String),
    'last_heartbeat': ISO8601(attribute='last_heartbeat'),
    'policy': fields.Nested(mod_agent_policy_detailed, attribute="_policy"),
    'version': fields.String,
    'is_pluggable': fields.Boolean(default=False),
    'host_information': fields.Nested(mod_agent_host_information),
    'tags': fields.List(fields.Nested(mod_agent_tag_short))
})

mod_agent_inputs = api.model('AgentInputs', {
    'inputs': fields.List(fields.Nested(mod_input_list)),
})

mod_agent_heartbeat = api.model('AgentHeartbeat', {
    'healthy': fields.Boolean,
    'health_issues': fields.List(fields.String),
    'recovered': fields.Boolean,
    'version': fields.String,
    'is_pluggable': fields.Boolean,
    'host_information': fields.Nested(mod_agent_host_information),
    'identifier': fields.String,
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

mod_agent_log_host_meta = api.model('AgentLogHostMeta', {
    'name': fields.String
})

mod_agent_log_level_meta = api.model('AgentLogLevelMeta', {
    'name': fields.String,
    'no': fields.Integer
})

mod_agent_log_file_meta = api.model('AgentLogFileMeta', {
    'name': fields.String,
    'path': fields.String
})

mod_agent_log_thread_meta = api.model('AgentLogThreadMeta', {
    'name': fields.String,
    'id': fields.Integer
})

mod_agent_log_process_meta = api.model('AgentLogProcessMeta', {
    'name': fields.String,
    'id': fields.Integer
})

mod_agent_log_message = api.model('AgentLogMessage', {
    'timestamp': ISO8601,
    'host': fields.Nested(mod_agent_log_host_meta),
    'level': fields.Nested(mod_agent_log_level_meta),
    'file': fields.Nested(mod_agent_log_file_meta),
    'thread': fields.Nested(mod_agent_log_thread_meta),
    'process': fields.Nested(mod_agent_log_process_meta),
    'line': fields.Integer,
    'message': fields.String,
    'module': fields.String,
    'formatted': fields.String(required=False)
})

mod_create_log_messages = api.model('AgentLogMessages', {
    'messages': fields.List(fields.Nested(mod_agent_log_message))
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
agent_list_parser.add_argument(
    'filter_query', type=str, location='args', default=None, required=False
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

        #agents = list(agents)

        #filter_error = None
        #if args.filter_query:
            #print(args.filter_query)
#
            #try:
                #qp = QueryParser()
                #parsed_query = qp.parser.parse(args.filter_query)
                #_agents = [{'agent': a.to_dict()} for a in agents]
                #results = [r for r in qp.run_search(_agents, parsed_query)]
                #agents = [a['agent'] for a in results]
            #except Exception as e:
                #filter_error = str(e)
                #parsed_query = None

        response = {
            'agents': list(agents),
            'pagination': {
                'total_results': total_results,
                'pages': pages,
                'page': args['page'],
                'page_size': args['page_size']
            },
            'filter_error': None
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


def parse_geo_info(geo_info):
    '''
    Returns geo_info if the proper fields are present
    '''

    data = {}

    if 'location' in geo_info:
        data['latitude'] = geo_info['location'].get('latitude', None)
        data['longitude'] = geo_info['location'].get('longitude', None)
        data['metro_code'] = geo_info['location'].get('metro_code', None)
        data['time_zone'] = geo_info['location'].get('time_zone', None)

    if 'city' in geo_info:
        data['city'] = geo_info['city']['names'].get('en', None)

    if 'registered_country' in geo_info:
        data['iso_code'] = geo_info['registered_country'].get('iso_code', None)

    if 'continent' in geo_info:
        data['continent'] = geo_info['continent']['names'].get('en', None)
        data['continent_code'] = geo_info['continent'].get('code', None)

    if 'country' in geo_info:
        data['country'] = geo_info['country']['names'].get('en', None)
        data['country_code'] = geo_info['country'].get('iso_code', None)

    if 'subdivisions' in geo_info:
        if len(geo_info['subdivisions']) > 0:
            data['state'] = geo_info['subdivisions'][0]['names'].get('en', None)
            data['state_code'] = geo_info['subdivisions'][0].get('iso_code', None)

    return data
    


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

                # Determine the agents console_visible_ip address from the request
                if 'X-Forwarded-For' in request.headers:
                    api.payload['console_visible_ip'] = request.headers['X-Forwarded-For']
                else:
                    api.payload['console_visible_ip'] = request.remote_addr

                if ',' in api.payload['console_visible_ip']:
                    api.payload['console_visible_ip'] = api.payload['console_visible_ip'].split(',')[0]

                if 'console_visible_ip' in api.payload:
                    
                    try:
                        geo = geolite2.reader()
                    
                        geo_info = geo.get(api.payload['console_visible_ip'])

                        if geo_info:
                            api.payload['geo'] = parse_geo_info(geo_info)
                        else:
                            api.payload['geo'] = None
                    except Exception:
                        api.payload['geo'] = None

                # Assign the agents tags if they have changed
                agent_tags = AgentTag.set_agent_tags(agent)
                if agent.tags != agent_tags:
                    api.payload['tags'] = agent_tags
                
                # Inventory the agents installed software
                host_information = api.payload.get('host_information', None)
                installed_software = []
                if host_information:
                    
                    installed_software = host_information.get('installed_software', [])

                if len(installed_software) > 0:
                    ApplicationInventory.bulk_add(agent, installed_software)

                # Update the agent
                agent.update(last_heartbeat=datetime.datetime.utcnow(),
                             **api.payload, refresh=True)

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

            # Only return pluggable roles if the agent is pluggable
            if agent.is_pluggable:
                policy['roles'] = [r for r in policy['roles'] if r in PLUGGABLE_SUPPORTED_ROLES]

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

agent_details_parser = api.parser()
agent_details_parser.add_argument('include_host_info', type=xinputs.boolean, location='args', default=False, required=False)

@api.route("/<uuid>")
class AgentDetails(Resource):

    @api.doc(security="Bearer")
    @api.expect(mod_agent_create, agent_details_parser)
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

            args = agent_details_parser.parse_args()

            if args.include_host_info is False:
                # Remove the host_information from the response
                agent.host_information = None

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

            archive_agent_results(BenchmarkResultHistory, agent.uuid)
            archive_agent_results(BenchmarkResult, agent.uuid)

            agent.delete()
            return {'message': 'Agent successfully delete.'}
        else:

            api.abort(404, 'Agent not found.')

    @api.doc(security="Bearer")
    @api.marshal_with(mod_agent_details)
    @api.expect(agent_details_parser)
    @token_required
    @user_has('view_agents')
    def get(self, uuid, current_user):
        ''' Gets the details of a Agent '''
        agent = Agent.get_by_uuid(uuid=uuid)
        if agent:

            args = agent_details_parser.parse_args()

            if args.include_host_info is False:
                # Remove the host_information from the response
                agent.host_information = None


            return agent
        else:

            api.abort(404, 'Agent not found.')

mod_formatted_log = api.model('FormattedLog', {
    'formatted': fields.String
})

mod_agent_logs = api.model('AgentLogs', {
    'logs': fields.List(fields.String)
})

agent_log_parser = api.parser()
agent_log_parser.add_argument('agent', action='split', default=[], location='args', required=False)
agent_log_parser.add_argument('module', action='split', default=[], location='args', required=False)
agent_log_parser.add_argument('level', action='split', default=[], location='args', required=False)
agent_log_parser.add_argument('organization', action='split', default=[], location='args', required=False)
agent_log_parser.add_argument('start_date', type=str, location='args', default='now-1d', required=False)
agent_log_parser.add_argument('end_date', type=str, location='args', default='now', required=False)

@api.route("/log")
class AgentLog(Resource):

    @api.doc(security="Bearer")
    @api.expect(agent_log_parser)
    @api.marshal_with(mod_agent_logs)
    @token_required
    @user_has('view_agent_logs')
    def get(self, current_user):

        args = agent_log_parser.parse_args()

        search = AgentLogMessage.search()

        if args.agent:
            search = search.filter('terms', agent_uuid=args.agent)

        if args.module:
            search = search.filter('terms', module=args.module)

        if args.level:
            search = search.filter('terms', level__name=args.level)

        if args.organization:
            if current_user.is_default_org():
                search = search.filter('terms', organization=args.organization)

        if args.start_date:
            search = search.filter('range', timestamp={'gte': args.start_date})

        if args.end_date:
            search = search.filter('range', timestamp={'lte': args.end_date})

        # Newest logs first
        search = search.sort('-timestamp')

        # Max 1000 logs
        search = search[:500]

        logs = [l.formatted for l in search.scan()]

        return {'logs': logs}


    @api.doc(security="Bearer")
    @api.expect(mod_create_log_messages)
    @token_required
    @user_has('create_agent_log_message')
    def post(self, current_user):
        ''' Creates a log message for an Agent '''

        agent = Agent.get_by_uuid(uuid=current_user.uuid)
        if agent:
            # If the content is gzip encoded, decode it
            if 'Content-Encoding' in request.headers:
                if request.headers['Content-Encoding'] == 'gzip':
                    try:
                        compress_data = io.BytesIO(request.data)
                        gzip_data = gzip.GzipFile(fileobj=compress_data, mode='r')
                        text_data = gzip_data.read()
                        request_data = json.loads(text_data.decode('utf-8'))
                    except Exception as e:
                        api.abort(400, f'Error decoding gzip content. {e}')
            else:
                request_data = api.payload
            
            for message in request_data['messages']:
                log = AgentLogMessage(agent_uuid=current_user.uuid,
                    **message)
                log.save()
            return {'message': 'Log message successfully created.'}
        else:

            api.abort(404, 'Agent not found.')

