"""app/api_v2/model/agent.py

Contains all the logic for Agent interaction with the API
"""

from . import (
    Keyword,
    Ip,
    Date,
    Boolean,
    Text,
    user,
    base,
    inout,
)

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
    active = Boolean()
    ip_address = Ip()
    last_heartbeat = Date()

    class Index: # pylint: disable=too-few-public-methods
        ''' Defines the index to use '''
        name = 'reflex-agents'
        settings = {
            'refresh_interval': '1s'
        }

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
