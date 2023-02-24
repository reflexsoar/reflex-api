import jwt
import json
from time import time
from flask import request, current_app

from . import user as u

from elasticsearch_dsl import connections as econn
from opensearch_dsl import connections as oconn


class IndexedDict(dict):
    """A dictionary that maintains an index of the keys in a flattened
    dot notation format.  All destination values are stored in a list to
    support multiple values for a single key. This is useful for searching
    for a key in a dictionary using dot notation and getting all the values
    back without having to know the exact path to the key or iterating over
    the entire dictionary.
    """

    def __init__(self, *args, **kwargs):
        """Initializes the IndexedDict class."""
        super().__init__()
        root_key = kwargs.pop('root_key', None)
        target_dict = self.index_data(
            target_dict={}, root_key=root_key, *args, **kwargs)
        self.update(target_dict)

    def index_data(self, data=None, prefix=None, keys=None, target_dict=None, root_key=None):
        """Flattens all the keys and their values in to a new dictionary
        so that the entire path is searchable using dot notation.

        Args:
            data (dict): The dictionary to flatten.
            prefix (str): The prefix to use for the flattened keys.
            keys (list): The list of keys to flatten.
            target_dict (dict): The dictionary to store the flattened keys and values.
            root_key (str): The root key to use for the flattened keys.

        Return:
            dict: The flattened dictionary.
        """

        if keys is None:
            keys = []

        if root_key:
            data = data[root_key]

        if isinstance(data, dict):
            for key, value in data.items():
                if prefix:
                    key = f"{prefix}.{key}"
                self.index_data(value, key, keys, target_dict)
        elif isinstance(data, list):
            for value in data:
                self.index_data(value, prefix, keys, target_dict)
        else:
            if prefix in target_dict:
                if isinstance(target_dict[prefix], list):
                    target_dict[prefix].append(data)
                else:
                    target_dict[prefix] = [target_dict[prefix], data]
            else:
                target_dict[prefix] = data
        return target_dict

    def __getitem__(self, key):
        """Returns the value of the key if it exists, otherwise returns None."""
        if key in self:
            return super().__getitem__(key)


def execution_timer(f):
    '''
    Times the execution of a function
    '''
    def wrapper(*args, **kwargs):
        t1 = time()
        result = f(*args, **kwargs)
        t2 = time()
        print(f'Function {f.__name__!r} executed in {(t2-t1):.4f}s')
        return result
    return wrapper


def build_elastic_connection():
    elastic_connection = {
        'hosts': current_app.config['ELASTICSEARCH_URL'],
        'verify_certs': current_app.config['ELASTICSEARCH_CERT_VERIFY'],
        'use_ssl': current_app.config['ELASTICSEARCH_SCHEME'],
        'ssl_show_warn': current_app.config['ELASTICSEARCH_SHOW_SSL_WARN'],
        'timeout': current_app.config['ELASTICSEARCH_TIMEOUT']
    }

    username = current_app.config['ELASTICSEARCH_USERNAME']
    password = current_app.config['ELASTICSEARCH_PASSWORD']
    if current_app.config['ELASTICSEARCH_AUTH_SCHEMA'] == 'http':
        elastic_connection['http_auth'] = (username,password)

    elif current_app.config['ELASTICSEARCH_AUTH_SCHEMA'] == 'api':
        elastic_connection['api_key'] = (username,password)

    if current_app.config['ELASTICSEARCH_CA']:
        elastic_connection['ca_certs'] = current_app.config['ELASTICSEARCH_CA']

    if current_app.config['ELASTIC_DISTRO'] == "opensearch":
        return oconn.create_connection(**elastic_connection)
    return econn.create_connection(**elastic_connection)


def escape_special_characters(value):
    '''
    Escapes characters in Elasticsearch that might wedge a search
    and return false matches
    '''

    characters = ['.', ' ', ']', '[']
    if isinstance(value, list):
        new_list = []
        for _value in value:
            for character in characters:
                _value = _value.replace(character, '\\'+character)
            new_list.append(_value)
        return new_list
    else:
        for character in characters:
            value = value.replace(character, '\\'+character)
    return value
    


def _current_user_id_or_none(organization_only=False):
    try:
        auth_header = request.headers.get('Authorization')

        current_user = None
        user_type = 'user'
        if auth_header:
            access_token = auth_header.split(' ')[1]
            token = jwt.decode(
                access_token, current_app.config['SECRET_KEY'], algorithms=['HS256'])
            if 'type' in token and token['type'] == 'agent':
                current_user = None
            elif 'type' in token and token['type'] == 'pairing':
                current_user = None
            elif 'type' in token and token['type' == 'service_account']:
                current_user = token['uuid']
                user_type = 'service_account'
            else:
                current_user = token['uuid']

            if organization_only:
                org_dict = {}
               
                if 'organization' in token:

                    org_dict['organization'] = token['organization']

                    if 'default_org' in token:
                        org_dict['default_org'] = token['default_org']
                    
                    return org_dict
                  
                else:
                    return None
                    
        if current_user:
            if user_type == 'user':
                user = u.User.get_by_uuid(uuid=current_user)
            else:
                user = u.ServiceAccount.get_by_uuid(uuid=current_user)
                
            current_user = {
                'username': user.username,
                'uuid': user.uuid,
                'organization': user.organization
            }

        return current_user

    except Exception:
        return None
