import ssl
import json
import jwt
import uuid
import datetime
import urllib3
import hashlib
from flask import current_app
from collections import namedtuple
from elasticsearch import Elasticsearch
from elasticsearch_dsl import Document, InnerDoc, Date, Integer, Keyword, Text, Boolean, Nested, connections
from json import JSONEncoder
from app import FLASK_BCRYPT

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class User(Document):
    
    uuid = Text()
    email = Text()
    username = Text()
    first_name = Text()
    last_name = Text()
    last_logon = Date()
    password_hash = Text()
    failed_logons = Integer()
    deleted = Boolean()
    locked = Boolean()
    #groups = Nested(Group)
    api_key = Text()
    created_at = Date()
    updated_at = Date()
    
    class Index:
        name = 'reflex-users'

    def set_password(self, password):
        self.password_hash = FLASK_BCRYPT.generate_password_hash(
            password).decode('utf-8')


    """ TODO: TURN THIS BACK ON
    def generate_api_key(self):
        '''
        Generates a long living API key, which the user can use to make
        API calls without having to authenticate using username/password

        The API Key should only be presented once and will be added to the 
        expired token table 
        '''

        _api_key = jwt.encode({
            'uuid': self.uuid,
            'organization': self.organization_uuid,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(
                    days = GlobalSettings.query.filter_by(
                        organization_uuid = self.organization_uuid).first().api_key_valid_days),
            'iat': datetime.datetime.utcnow(),
            'type': 'api'
        }, current_app.config['SECRET_KEY']).decode('utf-8')

        if self.api_key != None:
            blacklist = AuthTokenBlacklist(auth_token = self.api_key)
            blacklist.create()
            self.api_key = _api_key
        else:
            self.api_key = _api_key
        self.save()
        return {'api_key': self.api_key}
    """

    def create_access_token(self):
        _access_token = jwt.encode({
            'uuid': self.uuid,
            #'organization': self.organization_uuid,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=360),
            'iat': datetime.datetime.utcnow(),
            'type': 'user'
        }, current_app.config['SECRET_KEY'])

        return _access_token

    @property
    def permissions(self):
        return [
            k for k in self.role.permissions.__dict__ 
            if k not in ['_sa_instance_state', 'created_at', 'modified_at', 'created_by', 'modified_by', 'uuid', 'id'] 
            and self.role.permissions.__dict__[k] == True
        ]

    def create_password_reset_token(self):
        _token = jwt.encode({
            'uuid': self.uuid,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30),
            'iat': datetime.datetime.utcnow(),
            'type': 'password_reset'
        }, current_app.config['SECRET_KEY'])

        return _token

    def create_refresh_token(self, user_agent_string):
        _refresh_token = jwt.encode({
            'uuid': self.uuid,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(days=30),
            'iat': datetime.datetime.utcnow(),
            'type': 'refresh'
        }, current_app.config['SECRET_KEY'])

        user_agent_hash = hashlib.md5(user_agent_string).hexdigest()

        #refresh_token = RefreshToken.query.filter_by(
        #    user_agent_hash=user_agent_hash).first()

        #if not refresh_token:
        #    refresh_token = RefreshToken(
        #        user_uuid=self.uuid, refresh_token=_refresh_token, user_agent_hash=user_agent_hash)
        #    refresh_token.create()
        #    _refresh_token = refresh_token.refresh_token
        #else:
        #    refresh_token.refresh_token = _refresh_token
        #    db.session.commit()

        return _refresh_token

    def check_password(self, password):
        '''
        Tries to validate the users password against the 
        local authentication database
        '''

        return FLASK_BCRYPT.check_password_hash(self.password_hash, password)

    def ldap_login(self, password):
        ''' 
        If configured in the organizations settings
        will attempt to log the user in via LDAP
        '''

        raise NotImplementedError

    def save(self, **kwargs):
        self.uuid = uuid.uuid4()
        self.created_at = datetime.datetime.utcnow()
        return super().save(**kwargs)

    """
    def has_right(self, permission):
        '''
        Checks to see if the user has the proper 
        permissions to perform an API action
        '''

        if getattr(self.role.permissions,permission):
            return True
        else:
            return False
    """



class Observable(InnerDoc):

    tags = Keyword()
    data_type = Text()
    value = Text()
    spotted = Boolean()
    ioc = Boolean()
    safe = Boolean()
    tlp = Integer()
    created_at = datetime.datetime.utcnow()

class Event(Document):

    title = Text(fields={'raw': Keyword()})
    description = Text(fields={'raw': Keyword()})
    reference = Text()
    source = Text()
    tlp = Integer()
    severity = Integer()
    tags = Keyword()
    observables = Nested(Observable)
    status = Integer()
    signature = Text()
    dismissed = Boolean()
    dismiss_reason = Text()
    dismiss_comment = Text()
    raw_log = Text()

    class Index:
        name = 'reflex-events'

    def add_observable(self, content):
        self.observables.append(Observable(**content))

    def save(self, **kwargs):
        self.created_at = datetime.datetime.utcnow()
        self.hash_event()
        return super().save(**kwargs)

    def hash_event(self, data_types=['host','user','ip','string']):
        '''
        Generates an md5 signature of the event by combining the Events title
        and the observables attached to the event.  The Event signature is used
        for correlating multiple instances of an event
        '''

        _observables = []
        obs = []

        hasher = hashlib.md5()
        print(self.title.encode())
        hasher.update(self.title.encode())

        for observable in self.observables:
            _observables += [observable if observable.data_type in data_types else None]

        for observable in _observables:
            if observable and observable.data_type in sorted(data_types):
                print({'data_type': observable.data_type.lower(), 'value': observable.value.lower()})
                obs.append({'data_type': observable.data_type.lower(), 'value': observable.value.lower()})
        obs = [dict(t) for t in {tuple(d.items()) for d in obs}] # Deduplicate the observables
        obs = sorted(sorted(obs, key = lambda i: i['data_type']), key = lambda i: i['value'])
        hasher.update(str(obs).encode())
        self.signature = hasher.hexdigest()
        return