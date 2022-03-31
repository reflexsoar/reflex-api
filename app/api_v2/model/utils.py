import jwt
import json
from flask import request, current_app

from . import user as u

from elasticsearch_dsl import connections as econn
from opensearch_dsl import connections as oconn


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
        'ssl_show_warn': current_app.config['ELASTICSEARCH_SHOW_SSL_WARN']
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
        if auth_header:
            access_token = auth_header.split(' ')[1]
            token = jwt.decode(
                access_token, current_app.config['SECRET_KEY'], algorithms=['HS256'])
            if 'type' in token and token['type'] == 'agent':
                current_user = None
            elif 'type' in token and token['type'] == 'pairing':
                current_user = None
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
            user = u.User.get_by_uuid(uuid=current_user)
            current_user = {
                'username': user.username,
                'uuid': user.uuid,
                'organization': user.organization
            }

        return current_user

    except Exception:
        return None
