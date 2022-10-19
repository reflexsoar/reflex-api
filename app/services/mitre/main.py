import requests
import logging
from app.api_v2.model import MITRETactic, MITRETechnique


class MITREAttack(object):
    """
    Creates a class for downloading and managing MITRE ATT&CK information
    within the platform
    """

    def __init__(self, app, log_level='INFO'):

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

        self.config = app.config['MITRE_CONFIG']

    def download_framework(self):

        techniques = []
        tactics = []

        session = requests.Session()
        self.logger.info('Downloading MITRE ATT&CK JSON Data')
        response = session.get(self.config['JSON_URL'])
        if response.status_code == 200:

            data = response.json()['objects']

            # Create a MITRETactic document for each tactic
            tactics = [MITRETactic(mitre_id=tactic['id'],
                                   name=tactic['name'],
                                   description=tactic['description'],
                                   shortname=tactic['x_mitre_shortname'],
                                   external_references=tactic['external_references']
                                   ) for tactic in data if len(data) > 0 and tactic['type'] == 'x-mitre-tactic']

            # Extract the external_id from external references e.g. TA0006
            [t.get_external_id() for t in tactics]

            # Save or update the tactic
            self.logger.info('Updating MITRE ATT&CK Tactics')
            for tactic in tactics:
                existing_tactic = MITRETactic.get_by_external_id(
                    tactic.external_id)
                if existing_tactic:
                    existing_tactic.update(**tactic.to_dict(), refresh=True)
                else:
                    tactic.save()

            # Create a MITRETechnique document for each attack-pattern
            _techniques = [tech for tech in data if len(
                data) > 0 and tech['type'] == 'attack-pattern']
            techniques = []
            for tech in _techniques:
                data_sources = None
                if 'x_mitre_data_sources' in tech:
                    data_sources = tech['x_mitre_data_sources']

                techniques.append(MITRETechnique(mitre_id=tech['id'],
                                                 name=tech['name'],
                                                 description=tech['description'],
                                                 external_references=tech['external_references'],
                                                 kill_chain_phases=tech['kill_chain_phases'],
                                                 data_sources=data_sources
                                                 ))
#
            # Extract the external_id and kill_chain_phases for each technique
            [t.get_external_id() for t in techniques]
            [t.get_kill_chain_phase_names() for t in techniques]
#
            # Save or update the technique
            self.logger.info('Updating MITRE ATT&CK Techniques')
            for tech in techniques:
                existing_tech = MITRETechnique.get_by_external_id(tech.external_id)
                if existing_tech:
                    existing_tech.update(**tech.to_dict(), refresh=True)
                else:
                    tech.save()
