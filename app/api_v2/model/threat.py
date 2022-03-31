import re
import json
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
from pymemcache.client.base import Client

class ThreatValue(base.BaseDocument):
    '''
    A threat list value that can be matched on
    Example:
        {'value': '192.168.1.1', 'data_type': 'ip', 'list_uuid': 'xxxxx'}
    '''

    value = Keyword()
    list_name = Keyword()
    list_uuid = Keyword()
    data_type = Keyword()
    from_poll = Boolean()
    key_field = Keyword() # If the value came from a CSV or a JSON string which key was it under
    record_num = Integer() # If the value came from a CSV or JSON list which record number was it
    poll_interval = Integer()
    expire_at = Date()

    class Index: # pylint: disable=too-few-public-methods
        ''' Defines the index to use '''
        name = 'reflex-threat-values'
        refresh_interval = '1s'

    @classmethod
    @execution_timer
    def prepare_value(self, values):
        '''
        Puts a value into the format the index expects it to be in
        Called as the action for streaming_bulk
        '''

        now = datetime.datetime.utcnow()

        for value in values:
            if value['value'] == '':
                continue
            doc = {
                'created_at': now,
                'value': value['value'],
                'data_type': value['data_type'],
                'organization': value['organization'],
                'poll_interval': value['poll_interval'],
                'from_poll': value['from_poll'],
                'list_name': value['list_name'],
                'list_uuid': value['list_uuid']
            }

            if value['poll_interval']:
                doc['expire_at'] = datetime.datetime.utcnow()+datetime.timedelta(minutes=value.pop('poll_interval'))
            yield doc

    @classmethod
    @execution_timer
    def push_to_memcached(self, values):
        '''
        Pushes the intel to memcached if memcached is enabled and configured
        '''
        client = Client(f"{current_app.config['THREAT_POLLER_MEMCACHED_HOST']}:{current_app.config['THREAT_POLLER_MEMCACHED_PORT']}")
        for value in values:
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
        search = self.search()
        search = search.filter('term', list_uuid__keyword=list_uuid)
        if values:
            search = search.filter('terms', value=values)
        return list(search.scan())


class ThreatList(base.BaseDocument):
    '''
    A threat list contains observable values that are used to
    tag tag observables on ingest.  Threat lists can contain
    values from external sources via URL polling
    '''

    name = Keyword()
    description = Text()
    list_type = Text(fields={'keyword':Keyword()})  # value, pattern, csv
    data_type_uuid = Keyword()
    tag_on_match = Boolean()  # Default to False
    url = Text() # A url to pull threat information from
    poll_interval = Integer() # How often to pull from this list
    last_polled = Date() # The time that the list was last fetched
    to_memcached = Boolean() # Push the contents of the list to memcached periodically
    active = Boolean() # Is the list active
    csv_headers = Keyword() # User has to supply the CSV headers in order
    csv_headers_data_types = Keyword() # User has to supply what data_type each column is
    csv_header_map = Nested()
    case_sensitive = Boolean() # Are the values on the list case sensitive

    class Index: # pylint: disable=too-few-public-methods
        ''' Defines the index to use '''
        name = 'reflex-threat-lists'

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
        search = ThreatValue.search()
        search = search[0:10000]
        search = search.filter('term', list=self.uuid)
        return list(search.scan())


    @execution_timer
    def check_value(self, value, *args, **kwargs):
        '''
        Checks to see if a value matches a value list or a regular expression
        based list and returns the number of hits on that list'
        '''
        print(value)

        if 'MEMCACHED_CONFIG' in kwargs and kwargs['MEMCACHED_CONFIG']:
            memcached_host, memcached_port = kwargs['MEMCACHED_CONFIG']
        else:
            memcached_host = current_app.config['THREAT_POLLER_MEMCACHED_HOST']
            memcached_port = current_app.config['THREAT_POLLER_MEMCACHED_PORT']

        # Create the memcached client
        client = Client(f"{memcached_host}:{memcached_port}")
        
        found = False

        # Check memcached first
        memcached_key = f"{self.organization}:{self.name.lower().replace(' ','_')}:{self.data_type.name}:{value}"
        if not found:            
            if 'MEMCACHED_CONFIG' in kwargs and kwargs['MEMCACHED_CONFIG']:
                
                result = client.get(memcached_key)
                if result:
                    found = True

        # If the item was not found in memcached check Elasticsearch
        if not found:
            
            values = ThreatValue.find(self.uuid, values=[value])
            if values:
                found = True

                # We found it, we should probably rehydrate memcached with it
                client.set(memcached_key, values[0].value)

        return found


    def set_values(self, values: list, from_poll=False):
        '''
        Sets the values of the threat list from a list of values
        '''
        if len(values) > 0:
            print(self.uuid)
            poll_interval = None
            if self.poll_interval:
                poll_interval = self.poll_interval
            values = [{
                'value': v,
                'data_type': self.data_type.name,
                'organization': self.organization,
                'poll_interval': poll_interval,
                'from_poll': from_poll,
                'list_name': self.name.lower().replace(' ','_'),
                'list_uuid': self.uuid} for v in values if v not in ('')]
            ThreatValue.bulk_add(values)

        if from_poll:
            self.last_polled = datetime.datetime.utcnow()
            self.save()

    def polled(self):
        '''
        Sets the last_polled date to the current time
        '''
        self.last_polled = datetime.datetime.utcnow()
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