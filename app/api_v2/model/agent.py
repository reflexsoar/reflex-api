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
    Nested
)


class RunnerRoleConfig(InnerDoc):
    '''
    Contains information about the Runner role configuration
    '''

    concurrent_actions = Integer() # How many actions can a single runner run concurrently
    graceful_exit = Boolean() # Should the runner attempt a graceful exit when the runner is asked to shut down?
    wait_interval = Integer() # How long should the runner wait to fetch new actions when no work is available?
    plugin_poll_interval = Integer() # How often should the runner poll for new plugins?
    logging_level = Keyword() # What logging level should the role use for its logs?


class DetectorRoleConfig(InnerDoc):
    '''
    Contains information about the Detector role configuration
    '''

    concurrent_rules = Integer() # How many rules can a single detector run concurrently
    graceful_exit = Boolean() # Should the detector attempt a graceful exit when the detector is asked to shut down?
    catchup_period = Integer() # How far back should a detection rule look if its interval was missed
    wait_interval = Integer() # How often should the detector wait between detection runs
    max_threshold_events = Integer() # How many events should a detector send when a threshold rule is matched?
    logging_level = Keyword() # What logging level should the role use for its logs?
    

class PollerRoleConfig(InnerDoc):
    '''
    Contains information about the Poller role configuration
    '''

    concurrent_inputs = Integer() # How many inputs can a single poller run concurrently
    graceful_exit = Boolean() # Should the poller attempt a graceful exit when the poller is asked to shut down?
    logging_level = Keyword() # What logging level should the role use for its logs?
    max_input_attempts = Integer() # How many times should the poller attempt to read an input before giving up?
    signature_cache_ttl = Integer() # How long should the poller keep a cached copy of the event signature


class AgentPolicy(base.BaseDocument):
    '''
    A Reflex agent policy that controls all the configuration of an agent
    from the central management console.  Policy settings can be changed locally
    at the agent using agent parameters at run time or using environmental 
    variables
    '''

    class Index: # pylint: disable=too-few-public-methods
        ''' Defines the index to use '''
        name = 'reflex-agent-policies'
        settings = {
            'refresh_interval': '1s'
        }

    name = Keyword() # What is a friendly name for this agent policy
    description = Text(fields={'keyword': Keyword()}) # A description of the policy
    roles = Keyword() # What roles do agents assigned to this policy have
    health_check_interval = Integer() # How often should the agent check in with the server?
    logging_level = Keyword() # What logging level should the agent use for its logs?
    max_intel_db_size = Integer() # How much space should the agent use for its intelligence database?
    disable_event_cache_check = Boolean() # Should the agent check the event cache for duplicate events?
    event_realert_ttl = Integer() # How long should an event signature be kept in the cache before it is realerted?
    poller_config = Nested(PollerRoleConfig) # What is the configuration for the poller role?
    detector_config = Nested(DetectorRoleConfig) # What is the configuration for the detector role?
    runner_config = Nested(RunnerRoleConfig) # What is the configuration for the runner role?
    tags = Keyword() # Tags to categorize this policy
    priority = Integer() # What is the priority of this policy?
    revision = Integer() # What is the revision of this policy?

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


class Agent(base.BaseDocument):
    '''
    A Reflex agent performs plugin actions, polls external sources
    for input data, and performs some Reflex system tasks
    '''

    name = Keyword()
    friendly_name = Keyword() # A friendly name to give this agent that isn't it's system name
    inputs = Keyword()  # A list of UUIDs of which inputs to run
    roles = Keyword()  # A list of roles that the agent belongs to
    groups = Keyword()  # A list of UUIDs that the agent belongs to
    active = Boolean() # Is this agent active?
    ip_address = Ip() # The IP address of the agent
    last_heartbeat = Date() # The last time this agent was heard from
    healthy = Boolean() # Is the agent in a healthy state?
    health_issues = Keyword() # A list of issues that have been found with the agent
    agent_policy = Keyword() # The agent policy that controls this agent

    class Index: # pylint: disable=too-few-public-methods
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
        [inputs.append(g.inputs) for g in self.groups]
        return 0

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


    def has_right(self, permission):
        '''
        Checks to see if the user has the proper
        permissions to perform an API action
        '''

        #role = user.Role.search().query('match', members=self.uuid).execute()
        #if role:
            #role = role[0]

        #return bool(getattr(role.permissions, permission))
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
    description = Text(fields={'keyword':Keyword()})
    agents = Keyword()
    inputs = Keyword() # A list of UUIDs of which inputs to run
    agent_policy = Keyword() # The agent policy that controls agents in this group

    class Index: # pylint: disable=too-few-public-methods
        ''' Defines the index to use '''
        name = 'reflex-agent-groups'
        settings = {
            'refresh_interval': '1s'
        }
    
    @property
    def _inputs(self):
        inputs = []

        if self.inputs:
            inputs = inout.Input.get_by_uuid(uuid=self.inputs, all_results=True)        

        return list(inputs)

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
