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
    inputs = Keyword()  # A list of UUIDs of which inputs to run
    roles = Keyword()  # A list of roles that the agent belongs to
    groups = Keyword()  # A list of UUIDs that the agent belongs to
    active = Boolean()
    ip_address = Ip()
    last_heartbeat = Date()

    class Index: # pylint: disable=too-few-public-methods
        ''' Defines the index to use '''
        name = 'reflex-agents'

    @property
    def _inputs(self):
        inputs = inout.Input.get_by_uuid(uuid=self.inputs)
        return list(inputs)

    def has_right(self, permission):
        '''
        Checks to see if the user has the proper
        permissions to perform an API action
        '''

        role = user.Role.search().query('match', members=self.uuid).execute()
        if role:
            role = role[0]

        return bool(getattr(role.permissions, permission))

    @classmethod
    def get_by_name(cls, name):
        '''
        Fetches a document by the name field
        Uses a term search on a keyword field for EXACT matching
        '''
        response = cls.search().query('term', name=name).execute()
        if response:
            usr = response[0]
            return usr
        return response


class AgentGroup(base.BaseDocument):
    '''
    Agent Groups allows the system configure many agents
    by applying configuration settings to the group after which
    the agents will inherit the group config
    '''

    name = Keyword()
    description = Text()
    agents = Keyword()
    inputs = Keyword() # A list of UUIDs of which inputs to run

    class Index: # pylint: disable=too-few-public-methods
        ''' Defines the index to use '''
        name = 'reflex-agent-groups'

    @property
    def _inputs(self):
        inputs = inout.Input.get_by_uuid(uuid=self.inputs)
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
