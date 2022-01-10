'''app/services/playbook_broker/base.py

PlaybookBroker service
'''

import logging

class PlaybookBroker(object):
    '''PlaybookBroker
    
    The PlaybookBroker is responsible for coordinating playbook actions
    by placing the inputs, actions and outputs of playbook steps on to 
    a queue for runner agents to execute
    '''

    def __init__(self, app, log_level="DEBUG", *args, **kwargs):

        log_levels = {
            'DEBUG': logging.DEBUG,
            'ERROR': logging.ERROR,
            'INFO': logging.INFO
        }

        ch = logging.StreamHandler()
        ch.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
        
        self.logger = logging.getLogger(f"PlaybookBroker")
        self.logger.addHandler(ch)
        self.logger.setLevel(log_levels[log_level])
        
        self.app = app