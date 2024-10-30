import os
import re
import sys
import json
import hashlib
import datetime
from flask import current_app

from .utils import build_elastic_connection, execution_timer
from . import (
    base,
    Keyword,
    Text,
    Boolean,
    Integer,
    Date,
    Nested,
    system
)

from opensearchpy.helpers import streaming_bulk as obulk
from elasticsearch.helpers import streaming_bulk as ebulk
from . import memcached_client


class ThreatValue(base.BaseDocument):
    '''
    A threat list value that can be matched on

    Example:
        {'value': '192.168.1.1', 'data_type': 'ip', 'list_uuid': 'xxxxx'}
    '''

    value = Keyword()
    hashed_value = Keyword()
    list_name = Keyword()
    list_uuid = Keyword()
    data_type = Keyword()
    from_poll = Boolean()
    poll_uuid = Keyword() # The UUID of the poll action that populated this list
    key_field = Keyword() # If the value came from a CSV or a JSON string which key was it under
    record_num = Integer() # If the value came from a CSV or JSON list which record number was it
    record_id = Keyword()
    poll_interval = Integer()
    expire_at = Date()
    ibytes = Integer()

    class Index: # pylint: disable=too-few-public-methods
        ''' Defines the index to use '''
        name = 'reflex-threat-values'
        settings = {
            'refresh_interval': '1s'
        }

    @classmethod
    def prepare_value(self, values, case_insensitive=False):
        '''
        Puts a value into the format the index expects it to be in
        Called as the action for streaming_bulk
        '''

        now = datetime.datetime.utcnow()

        for value in values:

            if case_insensitive:
                if isinstance(value['value'], str):
                    value['value'] = value['value'].lower()

            hasher = hashlib.md5()
            hasher.update(value['value'].encode())
            hashed_value = hasher.hexdigest()

            if value['value'] == '':
                continue
            doc = {
                'created_at': now,
                'value': value['value'],
                'hashed_value': hashed_value,
                'data_type': value['data_type'],
                'organization': value['organization'],
                'poll_interval': value['poll_interval'],
                'from_poll': value['from_poll'],
                'list_name': value['list_name'],
                'list_uuid': value['list_uuid']
            }

            doc['ibytes'] = sys.getsizeof(doc)

            if value['poll_interval']:
                doc['expire_at'] = datetime.datetime.utcnow()+datetime.timedelta(minutes=value.pop('poll_interval'))
            yield doc

    @classmethod
    def push_to_memcached(self, values):
        '''
        Pushes the intel to memcached if memcached is enabled and configured
        '''
        #client = Client(f"{current_app.config['THREAT_POLLER_MEMCACHED_HOST']}:{current_app.config['THREAT_POLLER_MEMCACHED_PORT']}")
        client = memcached_client.client

        for value in values:

            hasher = hashlib.md5()
            hasher.update(value['value'].encode())
            value['value'] = hasher.hexdigest()

            memcached_key = f"{value['organization']}:{value['list_uuid']}:{value['data_type']}:{value['value']}"
            client.set(memcached_key, value['value'])            
        
    @classmethod
    def bulk_add(self, values):
        '''
        Adds many IntelValue items to the intel index using streaming_bulk
        '''
        conn = build_elastic_connection()
        if current_app.config['ELASTIC_DISTRO'] == "opensearch":
            streaming_bulk = obulk
        else:
            streaming_bulk = ebulk

        for ok, action in streaming_bulk(client=conn, index=self.Index.name, actions=self.prepare_value(values)):
            pass
        
        if current_app.config['THREAT_POLLER_MEMCACHED_ENABLED']:
            self.push_to_memcached(values)

    @classmethod
    def find(self, list_uuid, values=None):
        '''
        Finds a value in Elasticsearch based on the lists UUID and the 
        desired intel value, responses are returned as a list of IntelValue
        objects
        '''

        # TODO: Update this to allow global searches by checking if 
        # the target list is global and if so, don't filter on the 
        # current_users organization
        _list = ThreatList.search(skip_org_check=True)
        _list = _list.filter('term', uuid=list_uuid)
        _list = _list.execute()
        if len(_list) > 0 and _list[0].global_list:
            search = self.search(skip_org_check=True)
        else:
            search = self.search()

        search = self.search(skip_org_check=True)
        search = search.filter('term', list_uuid=list_uuid)

        if values:
            search = search.filter('terms', value=values)
        
        # Limit the number of results to 10,000
        search = search[0:10000]
        
        return list(search.scan())


class ThreatList(base.BaseDocument):
    '''
    A threat list contains observable values that are used to
    tag tag observables on ingest.  Threat lists can contain
    values from external sources via URL polling
    '''

    name = Keyword()
    description = Text(fields={'keyword':Keyword()})
    list_type = Text(fields={'keyword':Keyword()})  # value, pattern, csv
    data_type_uuid = Keyword()
    data_type_name = Keyword() # The data type of the values in the list
    tag_on_match = Boolean()  # Default to False
    url = Text(fields={'keyword':Keyword()}) # A url to pull threat information from
    poll_interval = Integer() # How often to pull from this list
    last_polled = Date() # The time that the list was last fetched
    to_memcached = Boolean() # Push the contents of the list to memcached periodically
    active = Boolean() # Is the list active
    csv_headers = Keyword() # User has to supply the CSV headers in order
    csv_headers_data_types = Keyword() # User has to supply what data_type each column is
    csv_header_map = Nested()
    case_sensitive = Boolean() # Are the values on the list case sensitive
    import_time = Integer() # The time in seconds it took to import this list
    poll_uuid = Keyword() # The UUID of the last poll event that populated this lists values
    flag_safe = Boolean()
    flag_spotted = Boolean()
    flag_ioc = Boolean()
    change_tlp = Boolean()
    new_tlp = Integer()
    global_list = Boolean() # Is this a global list

    class Index: # pylint: disable=too-few-public-methods
        ''' Defines the index to use '''
        name = 'reflex-threat-lists'
        settings = {
            'refresh_interval': '1s'
        }

    @property
    def data_type(self):
        data_type = system.DataType.get_by_uuid(uuid=self.data_type_uuid)
        if data_type:
            return data_type
        return []


    @property
    def values(self):
        '''
        Fetches the lists values from the threat value index
        Limited to 10,000 records
        '''
        
        # Only return results for manual lists
        if not self.url:
            search = ThreatValue.search()
            search = search[0:10000]
            search = search.filter('term', list_uuid=self.uuid)
            return list(search.execute())
        else:
            return []

    @property
    def value_count(self):
        '''
        Fetches the number of items associated with this list
        '''
        search = ThreatValue.search()
        search = search.filter('term', list_uuid=self.uuid)
        return search.count()


    def check_value(self, value, *args, **kwargs):
        '''
        Checks to see if a value matches a value list or a regular expression
        based list and returns the number of hits on that list'
        '''

        if not isinstance(value, list):           

            found = False

            if self.list_type != 'patterns':
                hasher = hashlib.md5()
                if isinstance(value, int):
                    hasher.update(str(value).encode())
                else:
                    hasher.update(value.encode())
                value = hasher.hexdigest()

                if 'MEMCACHED_CONFIG' in kwargs and kwargs['MEMCACHED_CONFIG']:
                    memcached_host, memcached_port = kwargs['MEMCACHED_CONFIG']
                else:
                    memcached_host = os.getenv('REFLEX_THREAT_POLLER_MEMCACHED_HOST')
                    memcached_port = os.getenv('REFLEX_THREAT_POLLER_MEMCACHED_PORT')

                # Create the memcached client
                #client = Client(f"{memcached_host}:{memcached_port}")
                client = memcached_client.client
            
                # Check memcached first
                memcached_key = f"{self.organization}:{self.uuid}:{self.data_type_name}:{value}"

                if not found:
                    try:
                        result = client.get(memcached_key)
                        if result:
                            found = True
                    except Exception as e:
                        pass
                        #current_app.logger.error(f"Error checking memcached for {memcached_key}: {e}")
            
            else:
                patterns = list(self.values)
                for p in patterns:
                    pattern = re.compile(p.value)
                    if pattern.match(value):
                        found = True
            
            return found
        else:
            return False

    def remove_values(self, values:list):
        '''
        Removes multiple values from the list based on a list of values

        Param: The list of values to keep
        '''
        if len(values) > 0:
            to_delete = []

            [to_delete.append(v.value) for v in self.values if v['value'] not in values]
            threat_values = ThreatValue.search()
            threat_values = threat_values.filter('terms', value=to_delete)
            threat_values = threat_values.filter('term', list_uuid=self.uuid)
            threat_values.delete()


    def set_values(self, values: list, from_poll=False):
        '''
        Sets the values of the threat list from a list of values
        '''
        if len(values) > 0:
            poll_interval = None
            if self.poll_interval:
                poll_interval = self.poll_interval

            values = [{
                'value': v,
                'data_type': self.data_type_name,
                'organization': self.organization,
                'poll_interval': poll_interval,
                'from_poll': from_poll,
                'list_name': self.name.lower().replace(' ','_'),
                'list_uuid': self.uuid} for v in values if v not in (*[x['value'] for x in self.values],'')]
            ThreatValue.bulk_add(values)

        if from_poll:
            self.last_polled = datetime.datetime.utcnow()
            self.save()

    def polled(self, time_taken=0, poll_uuid=None):
        '''
        Sets the last_polled date to the current time
        '''

        self.last_polled = datetime.datetime.utcnow()
        self.poll_uuid = poll_uuid
        if time_taken > 0:
            self.import_time = time_taken
        self.save()

    @classmethod
    def get_by_name(self, name):
        '''
        Fetches a document by the name field
        Uses a term search on a keyword field for EXACT matching
        '''
        response = self.search().query('term', name=name).execute()
        if response:
            user = response[0]
            return user
        return response

    @classmethod
    def get_by_data_type(self, data_type, organization=None):
        '''
        Fetches the threat list by the data_type
        it should be associated with
        '''
        data_type = system.DataType.get_by_name(name=data_type, organization=organization)
        try:
            response = self.search()
            
            if organization:
                response = response.filter('term', organization=organization)

            response = response.query('term', data_type_uuid=data_type.uuid).execute()
        except AttributeError:
            return []
        if response:
            return list(response)
        return []