"""app/api_v2/model/agent.py

Contains all the logic for Agent interaction with the API
"""

from . import (
    Keyword,
    Ip,
    Date,
    Boolean,
    Integer,
    Text,
    user,
    base,
    inout,
    InnerDoc,
    Nested,
    Object,
    Float
)

PLUGGABLE_SUPPORTED_ROLES = ['fim']


class RunnerRoleConfig(InnerDoc):
    '''
    Contains information about the Runner role configuration
    '''

    # How many actions can a single runner run concurrently
    concurrent_actions = Integer()
    # Should the runner attempt a graceful exit when the runner is asked to shut down?
    graceful_exit = Boolean()
    # How long should the runner wait to fetch new actions when no work is available?
    wait_interval = Integer()
    # How often should the runner poll for new plugins?
    plugin_poll_interval = Integer()
    logging_level = Keyword()  # What logging level should the role use for its logs?


class DetectorRoleConfig(InnerDoc):
    '''
    Contains information about the Detector role configuration
    '''

    concurrent_rules = Integer()  # How many rules can a single detector run concurrently
    # Should the detector attempt a graceful exit when the detector is asked to shut down?
    graceful_exit = Boolean()
    # How far back should a detection rule look if its interval was missed
    catchup_period = Integer()
    wait_interval = Integer()  # How often should the detector wait between detection runs
    # How many events should a detector send when a threshold rule is matched?
    max_threshold_events = Integer()
    logging_level = Keyword()  # What logging level should the role use for its logs?


class PollerRoleConfig(InnerDoc):
    '''
    Contains information about the Poller role configuration
    '''

    concurrent_inputs = Integer()  # How many inputs can a single poller run concurrently
    # Should the poller attempt a graceful exit when the poller is asked to shut down?
    graceful_exit = Boolean()
    logging_level = Keyword()  # What logging level should the role use for its logs?
    # How many times should the poller attempt to read an input before giving up?
    max_input_attempts = Integer()
    # How long should the poller keep a cached copy of the event signature
    signature_cache_ttl = Integer()


class MitreMapperConfig(InnerDoc):
    '''
    Contains information about the Mitre Mapper configuration
    '''

    concurrent_inputs = Integer()  # How many inputs can a single mapper run concurrently
    # How often should the mapper refresh its mapping
    mapping_refresh_interval = Integer()
    # Should the mapper attempt a graceful exit when the mapper is asked to shut down?
    graceful_exit = Boolean()
    logging_level = Keyword()  # What logging level should the mapper use for its logs?
    # How many days back should the mapper assess for new data
    assessment_days = Integer()
    timeout = Integer()  # How long should the mapper wait for a response from the API


class FIMConfig(InnerDoc):
    '''Contains information about the FIM role configuration
    '''

    max_parallel_rules = Integer()  # How many rules can a single FIM run concurrently
    max_cpu_time = Integer()  # How long can a single FIM rule run before it is killed
    max_memory = Integer()  # How much memory can a single FIM rule use before it is killed
    # How much space can the FIM cache use before it is cleared
    max_cache_db_size = Integer()
    max_cache_db_age = Integer()  # How old can the FIM cache be before it is cleared
    # Should the FIM alert when the cache is missing
    alert_on_cache_missing = Boolean()
    wait_interval = Integer()  # How long should the FIM wait between runs
    logging_level = Keyword()  # What logging level should the FIM use for its logs?
    # Should the FIM attempt a graceful exit when asked to shut down
    graceful_exit = Boolean()


class AgentPolicy(base.BaseDocument):
    '''
    A Reflex agent policy that controls all the configuration of an agent
    from the central management console.  Policy settings can be changed locally
    at the agent using agent parameters at run time or using environmental 
    variables
    '''

    class Index:  # pylint: disable=too-few-public-methods
        ''' Defines the index to use '''
        name = 'reflex-agent-policies'
        settings = {
            'refresh_interval': '1s'
        }

    name = Keyword()  # What is a friendly name for this agent policy
    # A description of the policy
    description = Text(fields={'keyword': Keyword()})
    roles = Keyword()  # What roles do agents assigned to this policy have
    # How often should the agent check in with the server?
    health_check_interval = Integer()
    logging_level = Keyword()  # What logging level should the agent use for its logs?
    # How much space should the agent use for its intelligence database?
    max_intel_db_size = Integer()
    # Should the agent check the event cache for duplicate events?
    disable_event_cache_check = Boolean()
    # How long should an event signature be kept in the cache before it is realerted?
    event_realert_ttl = Integer()
    # What is the configuration for the poller role?
    poller_config = Nested(PollerRoleConfig)
    # What is the configuration for the detector role?
    detector_config = Nested(DetectorRoleConfig)
    # What is the configuration for the runner role?
    runner_config = Nested(RunnerRoleConfig)
    mitre_mapper_config = Nested(MitreMapperConfig)
    fim_config = Nested(FIMConfig)
    tags = Keyword()  # Tags to categorize this policy
    priority = Integer()  # What is the priority of this policy?
    revision = Integer()  # What is the revision of this policy?

    @classmethod
    def get_by_name(cls, name, organization=None):
        '''
        Fetches a document by the name field
        Uses a term search on a keyword field for EXACT matching
        '''
        response = cls.search()

        if isinstance(name, list):
            response = response.filter('terms', name=name)
        else:
            response = response.filter('term', name=name)
        if organization:
            response = response.filter('term', organization=organization)

        response = response.execute()
        if response:
            usr = response[0]
            return usr
        return response


class AgentLogHostMeta(InnerDoc):

    name = Keyword()

class AgentLogFileMeta(InnerDoc):
    
    name = Keyword()
    path = Keyword()

class AgentLogThreadMeta(InnerDoc):
    
    name = Keyword()
    id = Integer()


class AgentLogProcessMeta(InnerDoc):

    name = Keyword()
    id = Integer()

class AgentLogLevelMeta(InnerDoc):

    name = Keyword()
    no = Integer()

class AgentLogMessage(base.BaseDocument):
    '''
    A Reflex Agent log message
    '''

    class Index:
        ''' Defines the index to use '''
        name = 'reflex-agent-logs'
        settings = {
            'refresh_interval': '1s'
        }

    agent_uuid = Keyword()  # The UUID of the agent that generated this log message
    message = Text(fields={'keyword': Keyword()})  # The log message
    timestamp = Date()  # The timestamp of the log message
    name = Keyword()  # The name of the agent that generated this log message
    module = Keyword()  # The module that generated this log message
    line = Integer()  # The line number that generated this log message
    host = Object(AgentLogHostMeta)
    level = Object(AgentLogLevelMeta)
    file = Object(AgentLogFileMeta)
    function = Keyword()  # The function that generated this log message
    thread = Object(AgentLogThreadMeta)
    process = Object(AgentLogProcessMeta)  # The process that generated the log message


class AgentNetworkInterface(InnerDoc):
    '''
    Contains information about a network interface on the host
    '''
    name = Keyword()  # The name of the interface
    mac = Keyword()  # The MAC address of the interface
    ip = Ip()  # The IP address of the interface
    netmask = Keyword()  # The netmask of the interface
    broadcast = Ip()  # The broadcast address of the interface


class AgentSystemInfo(InnerDoc):
    '''
    Contains information about the system that the agent is running on
    '''
    type = Keyword()  # The type of system
    os_release = Keyword()  # The OS release of the system
    os_version = Keyword()  # The OS version of the system
    os_name = Keyword()  # The OS name of the system
    machine = Keyword()  # The machine type of the system
    hostname = Keyword()  # The hostname of the system
    processor = Keyword()  # The processor type of the system
    architecture = Keyword()  # The architecture of the system


class AgentChassisInfo(InnerDoc):
    '''
    Contains information about the chassis that the agent is running on
    '''
    domain = Keyword()  # The domain of the chassis
    domain_role = Integer()  # The domain role of the chassis
    model = Keyword()  # The model of the chassis
    manufacturer = Keyword()  # The manufacturer of the chassis
    system_family = Keyword()  # The system family of the chassis
    system_sku = Keyword()  # The system SKU of the chassis
    workgroup = Keyword()  # The workgroup of the chassis
    serial_number = Keyword()  # The serial number of the chassis
    chassis_type = Keyword()  # The chassis type of the chassis


class AgentLocalUser(InnerDoc):
    '''
    Contains information about a local user on the host
    '''

    username = Keyword()  # The username of the local user
    terminal = Keyword()  # The terminal of the local user
    host = Keyword()  # The host of the local user
    session_start = Date()  # The start time of the local user session
    groups = Keyword()  # The groups the local user belongs to

class AgentServices(InnerDoc):
    display_name = Keyword()
    binpath = Keyword()
    username = Keyword()
    start_type = Keyword()
    status = Keyword()
    pid = Integer()
    name = Keyword()
    description = Keyword()

class AgentListeningPorts(InnerDoc):

    pid = Integer()
    process_name = Keyword()
    process_path = Keyword()
    process_user = Keyword()
    port = Integer()
    protocol = Keyword()
    status = Keyword()
    family = Keyword()
    parent_pid = Integer()
    parent_process_name = Keyword()
    parent_process_path = Keyword()
    parent_process_user = Keyword()


class AgentSoftwarePackage(InnerDoc):
    '''
    Contains information about a software package installed on the host
    '''
    name = Keyword()  # The name of the software package
    version = Keyword()  # The version of the software package
    vendor = Keyword()  # The vendor of the software package
    identifying_number = Keyword()  # The identifying number of the software package
    install_date = Keyword()  # The install date of the software package
    install_source = Keyword()  # The install source of the software package
    local_package = Keyword()  # The local package of the software package
    package_cache = Keyword()  # The package cache of the software package
    package_code = Keyword()  # The package code of the software package
    package_name = Keyword()  # The package name of the software package
    url_info_about = Keyword()  # The URL info about of the software package
    language = Keyword()  # The language of the software package

class AgentHostInformation(InnerDoc):
    '''
    Contains information about the host that the agent is running on
    '''
    timezone = Keyword()  # The timezone of the host
    network_adapters = Nested(AgentNetworkInterface)
    users = Nested(AgentLocalUser)
    last_reboot = Date()  # The last time the host was rebooted
    system = Nested(AgentSystemInfo)
    chassis = Nested(AgentChassisInfo)
    listening_ports = Nested(AgentListeningPorts)
    services = Nested(AgentServices)
    installed_software = Nested(AgentSoftwarePackage)


class AgentTag(InnerDoc):
    '''
    A brief agent tag
    '''
    namespace = Keyword()  # The namespace of the tag
    value = Keyword()  # The value of the tag
    color = Keyword()  # The color of the tag


class AgentGeo(InnerDoc):
    '''
    Contains geo information about the agent
    '''
    latitude = Float()  # The latitude of the agent
    longitude = Float()  # The longitude of the agent
    metro_code = Keyword()  # The metro code of the agent
    time_zone = Keyword()  # The timezone of the agent
    city = Keyword()  # The city of the agent
    iso_code = Keyword()  # The ISO code of the agent
    continent = Keyword()  # The continent of the agent
    continent_code = Keyword()  # The continent code of the agent
    country = Keyword()  # The country of the agent
    country_code = Keyword()  # The country code of the agent
    state = Keyword()  # The state of the agent
    state_code = Keyword()  # The state name of the agent

class Agent(base.BaseDocument):
    '''
    A Reflex agent performs plugin actions, polls external sources
    for input data, and performs some Reflex system tasks
    '''

    name = Keyword()
    identifier = Keyword() # A unique ID that is generated by the operating system
    # A friendly name to give this agent that isn't it's system name
    friendly_name = Keyword()
    inputs = Keyword()  # A list of UUIDs of which inputs to run
    roles = Keyword()  # A list of roles that the agent belongs to
    groups = Keyword()  # A list of UUIDs that the agent belongs to
    active = Boolean()  # Is this agent active?
    ip_address = Ip()  # The IP address of the agent
    console_visible_ip = Ip()  # The IP address of the agent as seen by the console
    geo = Nested(AgentGeo)  # Geo information about the agent
    last_heartbeat = Date()  # The last time this agent was heard from
    healthy = Boolean()  # Is the agent in a healthy state?
    health_issues = Keyword()  # A list of issues that have been found with the agent
    agent_policy = Keyword()  # The agent policy that controls this agent
    version = Keyword()  # What is the version of this policy?
    is_pluggable = Boolean()  # Is this agent pluggable?
    updated_required = Boolean()  # Does this agent need to be updated?
    host_information = Nested(AgentHostInformation)
    tags = Nested(AgentTag)  # Tags to categorize this agent

    class Index:  # pylint: disable=too-few-public-methods
        ''' Defines the index to use '''
        name = 'reflex-agents'
        settings = {
            'refresh_interval': '1s'
        }

    @property
    def all_input_ids(self):
        inputs = [input.uuid for input in self._inputs]
        groups = AgentGroup.get_by_uuid(uuid=self.groups)
        for group in groups:
            if group.inputs:
                inputs += group.inputs
        return list(inputs)

    @property
    def _input_count(self):
        inputs = self._inputs
        if self._groups:
            [inputs.append(g.inputs) for g in self._groups]
        return len(inputs)

    @property
    def _inputs(self):
        '''
        Fetches the details of the inputs assigned to this agent
        '''

        inputs = inout.Input.get_by_uuid(uuid=self.inputs)
        return list(inputs)

    @property
    def _groups(self):
        groups = AgentGroup.get_by_uuid(uuid=self.groups)
        return list(groups)

    @property
    def merged_roles(self):
        '''
        Returns a combined list of the roles assigned to this agent directly or by policy
        '''
        if self.roles and len(self.roles) > 0:
            roles = self.roles
        else:
            roles = []

        if self._policy:
            if self._policy.roles and len(self._policy.roles) > 0:
                [roles.append(r) for r in self._policy.roles]

        if self.is_pluggable:
            roles = [role for role in roles if role in PLUGGABLE_SUPPORTED_ROLES]

        return list(set(roles))

    @property
    def _policy(self):
        '''
        Fetches the agent policy assigned to this agent
        '''
        policies = []
        groups = AgentGroup.get_by_uuid(uuid=self.groups)
        if groups:
            for group in groups:
                if group.agent_policy:
                    [policies.append(ap) for ap in AgentPolicy.get_by_uuid(
                        uuid=group.agent_policy)]

        if policies:
            policies.sort(key=lambda x: x.priority)

            policy = policies[0]

            if self.is_pluggable:
                policy['roles'] = [
                    role for role in policy.roles if role in PLUGGABLE_SUPPORTED_ROLES]

            return policy
        else:
            return AgentPolicy(
                uuid='00000000-0000-0000-0000-000000000000',
                name='default',
                organization=self.organization,
                description='Default agent policy',
                roles=[],
                health_check_interval=30,
                logging_level='ERROR',
                max_intel_db_size=50,
                disable_event_cache_check=False,
                event_realert_ttl=3600,
                poller_config=PollerRoleConfig(
                    concurrent_inputs=5,
                    graceful_exit=True,
                    logging_level='ERROR',
                    max_input_attempts=3,
                    signature_cache_ttl=3600
                ),
                detector_config=DetectorRoleConfig(
                    graceful_exit=True,
                    catchup_period=3600,
                    wait_interval=60,
                    max_threshold_events=100,
                    logging_level='ERROR',
                    concurrent_rules=10
                ),
                runner_config=RunnerRoleConfig(
                    concurrent_actions=10,
                    wait_interval=30,
                    plugin_poll_interval=30,
                    graceful_exit=True,
                    logging_level='ERROR'
                ),
                mitre_mapper_config=MitreMapperConfig(
                    concurrent_inputs=10,
                    mapping_refresh_interval=60,
                    graceful_exit=True,
                    logging_level='ERROR',
                    assessment_days=14,
                    timeout=30
                ),
                fim_config=FIMConfig(
                    max_parallel_rules=10,
                    max_cpu_time=30,
                    max_memory=256,
                    max_cache_db_size=100,
                    max_cache_db_age=72,
                    alert_on_cache_missing=True,
                    wait_interval=30,
                    logging_level='ERROR',
                    graceful_exit=True
                ),
                tags=['default'],
                priority=0,
                revision=0
            )

    def is_default_org(self):
        ''' Checks to see if the user belongs to the default org'''
        return False

    def has_right(self, permission):
        '''
        Checks to see if the user has the proper
        permissions to perform an API action
        '''

        # role = user.Role.search().query('match', members=self.uuid).execute()
        # if role:
        # role = role[0]

        # return bool(getattr(role.permissions, permission))
        role = user.Role.search()
        role = role.filter('term', members=self.uuid)
        role = role.execute()
        if role:
            role = role[0]

            if hasattr(role.permissions, permission):
                return getattr(role.permissions, permission)
            else:
                return False
        else:
            return False

    @classmethod
    def get_by_name(cls, name, organization=None):
        '''
        Fetches a document by the name field
        Uses a term search on a keyword field for EXACT matching
        '''
        response = cls.search()

        if isinstance(name, list):
            response = response.filter('terms', name=name)
        else:
            response = response.filter('term', name=name)
        if organization:
            response = response.filter('term', organization=organization)

        response = response.execute()
        if response:
            usr = response[0]
            return usr
        return response

    @classmethod
    def get_by_organization(cls, organization):
        '''
        Fetches a document by the organization field
        '''
        response = cls.search()
        response = response.filter('term', organization=organization)
        response = list(response.scan())

        if len(response) > 0:
            return response
        return []


class AgentGroup(base.BaseDocument):
    '''
    Agent Groups allows the system configure many agents
    by applying configuration settings to the group after which
    the agents will inherit the group config
    '''

    name = Keyword()
    description = Text(fields={'keyword': Keyword()})
    agents = Keyword()
    inputs = Keyword()  # A list of UUIDs of which inputs to run
    agent_policy = Keyword()  # The agent policy that controls agents in this group

    class Index:  # pylint: disable=too-few-public-methods
        ''' Defines the index to use '''
        name = 'reflex-agent-groups'
        settings = {
            'refresh_interval': '1s'
        }

    @property
    def _inputs(self):
        inputs = []

        if self.inputs:
            inputs = inout.Input.get_by_uuid(
                uuid=self.inputs, all_results=True)

        return list(inputs)

    @property
    def _policies(self):
        policies = []

        if self.agent_policy:
            policies = AgentPolicy.get_by_uuid(
                uuid=self.agent_policy, all_results=True)

        return list(policies)

    def add_agent(self, uuid):
        '''
        Adds an agent to to the group
        '''
        if self.agents:
            self.agents.append(uuid)
        else:
            self.agents = [uuid]
        self.save()

    def remove_agent(self, uuid):
        '''
        Removes an agent from the group
        '''
        if self.agents:
            self.agents.remove(uuid)
        self.save()

    @classmethod
    def get_by_policy(cls, policy, organization=None):
        '''
        Fetches a document by the policy field
        '''
        response = cls.search()
        response = response.filter('term', agent_policy=policy)
        if organization:
            response = response.filter('term', organization=organization)
        response = list(response.scan())

        if len(response) > 0:
            return response
        return []

    @classmethod
    def get_by_member(cls, member):
        '''
        Fetches a document by the the member of the agents field
        '''
        response = cls.search()
        if isinstance(member, list):
            response = response.filter('terms', agents=member)
        else:
            response = response.filter('term', agents=member)

        response = response.execute()

        if len(response) > 1:
            return list(response)

        if response:
            return response[0]
        else:
            return None

    @classmethod
    def get_by_name(cls, name, organization=None):
        '''
        Fetches a document by the name field
        Uses a term search on a keyword field for EXACT matching
        '''
        response = cls.search()

        if isinstance(name, list):
            response = response.filter('terms', name=name)
        else:
            response = response.filter('term', name=name)

        if organization:
            response = response.filter('term', organization=organization)

        response = response.execute()
        if len(response) > 1:
            return list(response)

        if response:
            return response[0]
        else:
            return None
