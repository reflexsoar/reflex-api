from app.api_v2.model.system import DataType
from ...api_v2.model import ThreatList, ThreatValue
import logging
import requests
import datetime
import json
import zipfile
import io
import hashlib
from pymemcache.client.base import Client
from elasticsearch.helpers import streaming_bulk as esb
from elasticsearch_dsl import connections as econn

from opensearchpy.helpers import streaming_bulk as osb
from opensearch_dsl import connections as oconn

class ThreatListPoller(object):
    '''
    The ThreatListPoller takes any threatlist in the system
    that contains a URL and a polling interval and automatically
    consumes the feed and puts the values of said feed in to the 
    lists values
    '''

    def __init__(self, app, threat_lists: list = [], memcached_config=None, log_level="DEBUG", *args, **kwargs):

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

        self.streaming_bulk = esb
        self.connections = oconn
        if app.config['ELASTIC_DISTRO'] == 'opensearch':
            self.streaming_bulk = osb
            self.connections = oconn
        
        self.app = app
        self.threat_lists = threat_lists

        self.session = requests.Session()

        self.memcached_config = memcached_config if memcached_config else None
        if self.memcached_config:
            self.memcached_client = Client(f"{self.memcached_config['host']}:{self.memcached_config['port']}")

        self.es_client = self.build_elastic_connection()

    def build_elastic_connection(self):
        elastic_connection = {
            'hosts': self.app.config['ELASTICSEARCH_URL'],
            'verify_certs': self.app.config['ELASTICSEARCH_CERT_VERIFY'],
            'use_ssl': self.app.config['ELASTICSEARCH_SCHEME'],
            'ssl_show_warn': self.app.config['ELASTICSEARCH_SHOW_SSL_WARN']
        }

        username = self.app.config['ELASTICSEARCH_USERNAME']
        password = self.app.config['ELASTICSEARCH_PASSWORD']
        if self.app.config['ELASTICSEARCH_AUTH_SCHEMA'] == 'http':
            elastic_connection['http_auth'] = (username,password)

        elif self.app.config['ELASTICSEARCH_AUTH_SCHEMA'] == 'api':
            elastic_connection['api_key'] = (username,password)

        if self.app.config['ELASTICSEARCH_CA']:
            elastic_connection['ca_certs'] = self.app.config['ELASTICSEARCH_CA']

        return self.connections.create_connection(**elastic_connection)

    def refresh_lists(self):
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

    def to_memcached(self, data, data_type, list_name, list_url, list_type, organization):
        '''
        Pushes a value to memcached using a namespace
        that matches the type of value
        TODO: Make this support multi-tenancy by providing a memcached config per organization
        '''

        try:
            # Change a name from "Someone's super awesome list!" to "someones_super_awesome_list"
            strip_chars = ['!#$%^&*()"\'']
            for char in strip_chars:
                list_name = list_name.replace(char, '')
            list_name = list_name.replace(' ','_').lower()

            for value in data:

                # TODO: Hash this for multitenancy to not expose observables to others if 
                # memcached is a shared instance
                key = f"{organization}:{list_name}:{data_type}:{value}"

                if list_type == 'csv':
                    entry_value = json.dumps(value)
                else:
                    entry_value = json.dumps({
                        "value": value,
                        "list_name": list_name,
                        "list_url": list_url
                    })

                self.memcached_client.set(
                    key,
                    entry_value,
                    expire=self.memcached_config['ttl']
                )
        except Exception as e:
            self.logger.error(f"An error occurred while trying to push ThreatList values to memcached. {e}")


    def generate_intel_value(self, values, data_type, list_uuid, list_name, poll_interval):
        for value in values:
            list_name = list_name.lower().replace(' ','_')
            if value in (None,''):
                continue
            yield ThreatValue(
                value=value,
                data_type=data_type,
                list_uuid=list_uuid,
                list_name=list_name,
                poll_interval=poll_interval,
                from_poll=True,
                created_at=datetime.datetime.utcnow(),
                expire_at=datetime.datetime.utcnow()+datetime.timedelta(minutes=poll_interval*1.5)
            ).to_dict(True)


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
            data_type_name = data_type.name

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
                data_type_name = l.data_type.name
                if l.url:
                    response = self.session.get(l.url)
                    self.logger.info(f'Polling {l.url}')
                    if response.status_code == 200:

                        content_type = response.headers['Content-Type']
                        data_from_url = True

                        if content_type == 'application/zip':
                            self.logger.info(f"Unzipping file from {l.url}")
                            zip_file = zipfile.ZipFile(io.BytesIO(response.content))
                            if len(zip_file.namelist()) > 1:
                                self.logger.warning(f"ZIP file from {l.url} contains more than 1 file")
                            else:
                                if l.list_type == "csv":
                                    data = zip_file.read(zip_file.namelist()[0]).splitlines()
                        else:
                            data = self.parse_data(response.text)
                      
                        if l.list_type == "csv":
                            data_type = 'multiple'
                            headers = [h.strip() for h in l.csv_headers.split(',')]
                            entries = []
                            for e in data:
                                if isinstance(e, bytes):
                                    e = e.decode().strip()

                                if not e.startswith('#'):
                                    entries.append(e)

                            data = []
                            for entry in entries:
                                entry = entry.split(',') #TODO: Replace this with l.csv_delimiter
                                _entry = {}
                                if entry == ['']:
                                    continue

                                for i in range(0,len(headers)-1):
                                    value = entry[i].strip()

                                    if not value:
                                        value = ''
                                    else:
                                        value = value.strip('"') #TODO: If l.remove_double_quotes

                                    _entry[headers[i]] = value 
                                data.append(json.dumps(_entry))

                        # Push the values from the URL to the list
                        if data:
                            for ok,action in self.streaming_bulk(client=self.es_client, actions=self.generate_intel_value(data, data_type_name, l.uuid, l.name, l.poll_interval)):
                                if not ok:
                                    self.logger.warning(f"Failed to push to index. {action}")
                                pass
                                
                        l.polled()
                    else:
                        print(response.__dict__)

                if self.memcached_config and l.to_memcached and data:
                    self.logger.info(f'Pushing data to memcached')
                    if data_from_url and data:
                        self.to_memcached(data, data_type.name, l.name, l.url, l.list_type, l.organization)
                    else:
                        self.to_memcached(l.values, data_type.name, l.name, 'manual_list', l.list_type, l.organization)
                        l.polled()
            