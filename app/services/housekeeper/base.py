""" /app/services/housekeeper/base.py
HouseKeeper service runs system jobs that attempt to keep the system
in a healthy state, like pruning old jobs or disabling accounts that have
not been used in a long time
"""

import datetime
import logging
from app.api_v2.model import (
    Settings,
    Agent,
    Role,
    AgentGroup,
    Task
)

class HouseKeeper(object):
    """ HouseKeeper service runs system jobs that attempt to keep the system
    in a healthy state, like pruning old jobs or disabling accounts that have
    not been used in a long time
    """

    def __init__(self, app, log_level="DEBUG", *args, **kwargs):

        log_levels = {
            'DEBUG': logging.DEBUG,
            'ERROR': logging.ERROR,
            'INFO': logging.INFO
        }

        log_handler = logging.StreamHandler()
        log_handler.setFormatter(logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'))

        self.logger = logging.getLogger(self.__class__.__name__)
        self.logger.addHandler(log_handler)
        self.logger.setLevel(log_levels[log_level])
        
        self.app = app

        self.agent_prune_lifetime = self.app.config['AGENT_PRUNE_LIFETIME']
        self.task_prune_lifetime = self.app.config['TASK_PRUNE_LIFETIME']
        self.logger.info(f"Service started. Task Lifetime: {self.task_prune_lifetime} | Agent Lifetime: {self.agent_prune_lifetime}")

    def prune_old_agents(self):
        ''' Automatically removes any agents that have not actively
        talked to the system in a number of days
        
        Parameters:
            days_back (int): How long since the agent last communicated
        '''

        days_ago = datetime.datetime.utcnow() - datetime.timedelta(days=self.agent_prune_lifetime)

        search = Agent.search()
        search = search[0:search.count()]
        search = search.filter('range', last_heartbeat={
                            'lte': days_ago.isoformat()
                        })
        print(search.to_dict())
        agents = search.execute()

        for agent in agents:

            self.logger.info(f"Deleting agent {agent.name}, last heartbeat exceeds threshold of {self.agent_prune_lifetime} days")

            # Remove the agent from the Agent Role
            agent_role = Role.get_by_member(member=agent.uuid)
            if agent_role:
                agent_role.remove_user_from_role(agent.uuid)

            # Remove the agent from the Agent Groups
            agent_group = AgentGroup.get_by_member(member=agent.uuid)
            if agent_group:
                if isinstance(agent_group, list):
                    for group in agent_group:
                        group.remove_agent(agent.uuid)
                else:
                    agent_group.remove_agent(agent.uuid)

            # Remove the agent from the Agent Group
            agent.delete()

        return True

    def prune_old_tasks(self):
        ''' Automatically prunes tasks that have completed for failed to complete
        in the last N days

        Parameters:
            days_back (int): How long since the task was completed
        '''

        days_ago = datetime.datetime.utcnow() - datetime.timedelta(days=self.task_prune_lifetime)

        search = Task.search()
        search = search.filter('range', created_at={
                            'lte': days_ago.isoformat()
                        })
        search.delete()
        

    def lock_old_users(self, days_back=90):
        ''' Automatically locks users that have not used the system in
        the last N days
        
        Parameters:
            days_back (int): How long since the user last used the account
        '''
        raise NotImplementedError

    def force_password_change(self, days_since=90):
        ''' Sets the password reset required flag on a user in the system
        if the last time they set their password is greater than days_since

        Parameters:
            days_since (int): How long its been since they set their password
        '''
        raise NotImplementedError

    