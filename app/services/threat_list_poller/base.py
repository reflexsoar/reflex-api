from ...api_v2.models import ThreatList
import logging
import requests
import datetime

class ThreatListPoller(object):
    '''
    The ThreatListPoller takes any threatlist in the system
    that contains a URL and a polling interval and automatically
    consumes the feed and puts the values of said feed in to the 
    lists values
    '''

    def __init__(self, app, threat_lists: list = [], log_level="DEBUG", *args, **kwargs):

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

    def refresh_lists(self):
        lists = ThreatList.search()
        lists = lists.filter('exists', field='url')
        lists = lists.filter('exists', field='active')
        lists = lists.filter('match', active=True)
        lists = lists.execute()
        if lists:
            self.threat_lists = [l for l in lists]

    def parse_data(self, data, list_format: str = "ip"):
        if list_format == 'ip':
            ips = data.split('\n')
            return ips

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

            if l.last_polled is not None:
                time_since = datetime.datetime.utcnow() - l.last_polled
                minutes_since = time_since.total_seconds()/60
                print(minutes_since, l.poll_interval)
                if minutes_since > l.poll_interval:
                    print("DO EET")
                    do_poll = True
            else:
                do_poll = True

            if do_poll:
                response = self.session.get(l.url)
                self.logger.info(f'Polling {l.url}')
                if response.status_code == 200:
                    l.set_values(self.parse_data(response.text), from_poll=True)
            