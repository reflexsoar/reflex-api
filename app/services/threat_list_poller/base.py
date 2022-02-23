from app.api_v2.model.system import DataType
from ...api_v2.model import ThreatList
import logging
import requests
import datetime
import json
from pymemcache.client.base import Client

class ThreatListPoller(object):
    '''
    The ThreatListPoller takes any threatlist in the system
    that contains a URL and a polling interval and automatically
    consumes the feed and puts the values of said feed in to the 
    lists values
    '''

    def __init__(self, app, threat_lists: list = None, memcached_config=None, log_level="DEBUG", *args, **kwargs):

        log_levels = {
            'DEBUG': logging.DEBUG,
            'ERROR': logging.ERROR,
            'INFO': logging.INFO
        }
        
        ch = logging.StreamHandler()
        ch.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
        
        self.logger = logging.getLogger(f"ThreatPoller")
        self.logger.addHandler(ch)
        self.logger.setLevel(log_levels[log_level])
        
        self.app = app
        self.threat_lists = threat_lists

        self.session = requests.Session()

        self.memcached_config = memcached_config if memcached_config else None

    def refresh_lists(self):
        '''
        Refreshes list data from Elasticsearch
        '''
        lists = ThreatList.search()
        lists = lists.filter('exists', field='active')
        lists = lists.filter('match', active=True)
        lists = lists.execute()
        if lists:
            self.threat_lists = [l for l in lists]

    def parse_data(self, data, list_format: str = "ip"):
        if list_format == 'ip':
            ips = data.split('\n')
            return ips

    def to_memcached(self, data, data_type, list_name, list_url):
        '''
        Pushes a value to memcached using a namespace
        that matches the type of value
        TODO: Make this support multi-tenancy by providing a memcached config per organization
        '''

        try:
            client = Client(f"{self.memcached_config['host']}:{self.memcached_config['port']}")

            # Change a name from "Someone's super awesome list!" to "someones_super_awesome_list"
            strip_chars = ['!#$%^&*()"\'']
            for char in strip_chars:
                list_name = list_name.replace(char, '')
            list_name = list_name.replace(' ','_').lower()

            for value in data:

                key = f"{list_name}:{data_type}:{value}"
                client.set(
                    key,
                    json.dumps({
                        "value": value,
                        "list_name": list_name,
                        "list_url": list_url
                    }),
                    expire=self.memcached_config['ttl']
                )
        except Exception as e:
            print(e)
            self.logger.error("An error occurred while trying to push ThreatList values to memcached")


    def run(self):
        '''
        Fetches all available lists and for each list checks
        to see if the list is ready for polling, performs the polling
        and updates the values in the list with the most recent values
        old values are replaced, new values are NOT appended
        '''
        self.logger.info('Fetching threat lists')
        self.refresh_lists()
        for l in self.threat_lists:

            do_poll = False

            data_type = DataType.get_by_uuid(l.data_type_uuid)

            if l.last_polled is not None:
                time_since = datetime.datetime.utcnow() - l.last_polled
                minutes_since = time_since.total_seconds()/60

                # Default to 60 minutes if the list doesn't have a poll interval set
                interval = 60
                if l.poll_interval:
                    interval = l.poll_interval

                if minutes_since > interval:
                    do_poll = True
            else:
                do_poll = True

            if do_poll:
                data_from_url = False
                data = None
                if l.url:
                    response = self.session.get(l.url)
                    self.logger.info(f'Polling {l.url}')
                    if response.status_code == 200:

                        data = self.parse_data(response.text)
                        data_from_url = True

                        # Push the values from the URL to the list
                        l.set_values(data, from_poll=True)

                if self.memcached_config and l.to_memcached:
                    self.logger.info(f'Pushing data to memcached')
                    if data_from_url and data:                   
                        self.to_memcached(data, data_type.name, l.name, l.url)
                    else:
                        self.to_memcached(l.values, data_type.name, l.name, 'manual_list')
                        l.polled()
            