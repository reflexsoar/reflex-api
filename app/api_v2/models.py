import ssl
import json
import uuid
import datetime
import urllib3
import hashlib
from flask import current_app
from collections import namedtuple
from elasticsearch import Elasticsearch, helpers
from json import JSONEncoder

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class BaseField(object):

    def __init__(self, field_type, relates_to=None):
        self.field_type = field_type
        self.relates_to = relates_to

class CustomJsonEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, Base):
            return o.__dict__
        return json.JSONEncoder.default(self, o)


class Client(object):
    '''
    A client making it easy to interact with Elasticsearch as the backend database
    using Python objects intead of raw json
    '''

    def __init__(self, hosts, username, password, *args, **kwargs):
        '''
        Initializes a new Elasticsearch client
        '''

        self.hosts = []
        self.username = username
        self.password = password
        self.scheme = "https"
        self.auth_method = str()
        self.check_hostname = False
        self.certification_verification = "none"
        self.cafile = str()

        # Set the properties based on what is presented in kwargs
        if kwargs:
            for k in kwargs:
                if k in self.__dict__:
                    self.__dict__[k] = kwargs[k]

        self.conn = self.build_es_connection()
    

    def build_es_connection(self):
        '''
        Creates an Elasticsearch connection object that can
        be used to query Elasticsearch
        '''

        if self.cafile != "":
            # TODO: Make this work using base64 encoded certificate file
            raise NotImplementedError
        else:
            context = ssl.create_default_context()
        context.check_hostname = self.check_hostname

        CONTEXT_VERIFY_MODES = {
            "none": ssl.CERT_NONE,
            "optional": ssl.CERT_OPTIONAL,
            "required": ssl.CERT_REQUIRED
        }
        context.verify_mode = CONTEXT_VERIFY_MODES[self.certification_verification]

        es_config = {
            'scheme': self.scheme,
            'ssl_context': context
        }

        if self.auth_method == 'api_key':
            es_config['api_key'] = (self.username, self.password)
        else:
            es_config['http_auth'] = (self.username, self.password)

        return Elasticsearch(*self.hosts, **es_config)


    def add(self, documents=[]):
        '''
        Adds a document to an Elasticsearch index
        '''
        try:

            docs = [{
                "_index": doc._index,
                "_source": doc.jsonify()
            } for doc in documents]

            for doc in documents:
                self.conn.index(index=doc._index, body=doc.jsonify())
            return True
        except Exception as e:
            print(e)
            return False


class Base(JSONEncoder):

    def __init__(self, *args, **kwargs):
        '''
        Initializes a base document with all the properties that all
        documents should have 
        '''

        self._id = None
        self._index = '.reflex-'+self.__class__.__name__.lower()
        self.uuid = str(uuid.uuid4())
        self.created_at = datetime.datetime.utcnow().isoformat()
        self.modified_at = datetime.datetime.utcnow().isoformat()
        self.created_by = None
        self.update_by = None

        # Set the properties based on what is presented in kwargs
        if kwargs:
            for k in kwargs:
                if k in self.__dict__:
                    self.__dict__[k] = kwargs[k]
    
    @classmethod
    def query(self, client, size=100, *args, **kwargs):
        '''
        Queries the elasticsearch index for all the documents and returns
        a list of document objects
        client: an elasticsearch client object
        size: the number of documents to return
        '''

        document = self()

        body = {
            'size': size
        }

        if kwargs:
            body['query'] = {}
            body['query']['bool'] = {}
            body['query']['bool']['must'] = [{'match': {k: kwargs[k]}} for k in kwargs]

        response = client.conn.search(index=document._index, body=body)
        print('ES Query Time: {} ms'.format(response['took']))
        if response['hits']['total']['value'] > 0:
            _hits = []
            _hits = [self(**h['_source']) for h in response['hits']['hits']]
            return _hits
        else:
            return None


    @classmethod
    def get(self, client, key_value, key_field='uuid', *args, **kwargs):
        '''
        Queries the elasticsearch index for all the documents and returns
        the single document object
        '''

        document = self()

        body = {
            "query": {
                "query_string": {
                    "query": "{}:{}".format(key_field, key_value)
                }
            }
        }

        try:
            response = client.conn.search(index=document._index, body=body)
            if response['hits']['total']['value'] > 0:
                return [self(**h['_source'], _id=h['_id']) for h in response['hits']['hits']][0]
            else:
                return None
        except Exception as e:
            return None


    def update(self, client, *args, **kwargs):
        
        if kwargs:
            for k in kwargs:
                if k in self.__dict__:
                    self.__dict__[k] = kwargs[k]
        
        response = client.conn.index(index=self._index, id=self._id, body=self.jsonify(), op_type='index')
        if response:
            return True
        
    def jsonify(self, pretty=False):
        '''
        Converts the document into a JSON payload
        Fields that start with _ are treated as system fields and are ignored
        '''
        
        if pretty:
            return json.dumps({k: self.__dict__[k] for k in self.__dict__ if not k.startswith('_')}, sort_keys=True, indent=4, cls=CustomJsonEncoder)
        else:
            return json.dumps({k: self.__dict__[k] for k in self.__dict__ if not k.startswith('_')}, cls=CustomJsonEncoder)


class User(Base):

    def __init__(self, *args, **kwargs):
        self.email = None
        self.username = None
        self.first_name = None
        self.last_name = None
        self.password_hash = None
        self.last_logon = None
        self.failed_logons = 0
        self.locked = False
        self.organization = None
        self.role = None
        self.groups = []
        self.api_key = None

        super().__init__(*args, **kwargs)


class Tag(Base):

    def __init__(self, *args, **kwargs):

        self.name = None
        super().__init__(*args, **kwargs)


class RawLog(Base):

    def __init__(self, *args, **kwargs):

        self.source_log = None

        super().__init__(*args, **kwargs)


class Event(Base):

    def __init__(self, *args, **kwargs):
        
        self.title = None
        self.description = None
        self.reference = None
        self.source = None
        self.tlp = 0
        self.severity = 0
        self.tags = []
        self.observables = []
        self.status = 0
        self.case = None
        self.signature = None
        self.dismissed = False
        self.dismiss_reason = None
        self.dismiss_comment = str()
        self.raw_log = None

        super().__init__(*args, **kwargs)


    def add_observables(self, client, observables):

        # Create the observables in elasticsearch
        # replace the observables list with a list of the UUIDs
        self.observables = [o for o in observables]
        #client.add(observables)

    def hash_event(self, data_types=['host','user','ip']):
        '''
        Generates an md5 signature of the event by combining the Events title
        and the observables attached to the event.  The Event signature is used
        for correlating multiple instances of an event
        '''
        
        _observables = []
        obs = []

        hasher = hashlib.md5()
        hasher.update(self.title.encode())

        for observable in self.observables:
            o = Observable.get(current_app.elasticsearch, key_field=uuid, key_value=observable)
            if o:
                _observables += [o if o.data_type in data_types else None]

        for observable in _observables:
            if observable and observable.data_type in sorted(data_types):
                obs.append({'data_type': observable.data_type.lower(), 'value': observable.value.lower()})
        obs = [dict(t) for t in {tuple(d.items()) for d in obs}] # Deduplicate the observables
        obs = sorted(sorted(obs, key = lambda i: i['data_type']), key = lambda i: i['value'])
        hasher.update(str(obs).encode())
        self.signature = hasher.hexdigest()
        return


class Observable(Base):

    def __init__(self, *args, **kwargs):

        self.value = ""
        self.data_type = ""
        self.tlp = 2
        self.safe = False
        self.spotted = False
        self.ioc = False

        super().__init__(*args, **kwargs)


class DataType(Base):

    def __init__(self, *args, **kwargs):

        self.name = ""
        self.description = ""
        self.regex = ""

        super().__init__(*args, **kwargs)