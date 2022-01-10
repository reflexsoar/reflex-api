""" /app/services/housekeeper/base.py
HouseKeeper service runs system jobs that attempt to keep the system
in a healthy state, like pruning old jobs or disabling accounts that have
not been used in a long time
"""

import datetime
import logging
from app.api_v2.model import (
    Settings,
    Agent
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

        ch = logging.StreamHandler()
        ch.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
        
        self.logger = logging.getLogger(self.__class__.__name__)
        self.logger.addHandler(ch)
        self.logger.setLevel(log_levels[log_level])
        
        self.app = app

    def prune_old_agents(self, days_back=7):
        ''' Automatically removes any agents that have not actively
        talked to the system in a number of days
        
        Parameters:
            days_back (int): How long since the agent last communicated
        '''

        search = Agent.search()
        search = search[0:search.count()]
        agents = search.execute()

        threshold = days_back * 86400

        for agent in agents:
            delta = datetime.datetime.utcnow() - agent.last_heartbeat
            if delta.seconds > threshold:
                self.logger.info(f"Deleting agent {agent.name}, last heartbeat exceeds threshold of {threshold}")
                agent.delete()

        return True

    def lock_old_users(self, days_back=90):
        ''' Automatically locks users that have not used the system in
        the last N days
        
        Parameters:
            days_back (int): How long since the user last used the account
        '''
        raise NotImplementedError

    