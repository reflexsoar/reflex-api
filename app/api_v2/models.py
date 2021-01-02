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


class BaseDocument(Document):
    """
    Base class for Documents containing common fields
    """

    uuid = Text()
    created_at = Date()
    updated_at = Date()

    @classmethod
    def get_by_uuid(self, uuid):
        response = self.search().query('match', uuid=uuid).execute()
        if response:
            document = response[0]
            return document
        return response

    def save(self, **kwargs):
        if not self.created_at:
            self.created_at = datetime.datetime.utcnow()
        self.updated_at = datetime.datetime.utcnow()
        self.uuid = uuid.uuid4()
        return super(BaseDocument, self).save(**kwargs)

    def update(self, **kwargs):
        self.updated_at = datetime.datetime.utcnow()
        return super(BaseDocument, self).update(**kwargs)


class User(BaseDocument):
    
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
    
    class Index:
        name = 'reflex-users'

    def set_password(self, password):
        '''
        Encrypts the password for the user. The Document base class
        does not support @property setters/getters so a custom function
        is required to make this work
        '''

        self.password_hash = FLASK_BCRYPT.generate_password_hash(
            password).decode('utf-8')

    def generate_api_key(self):
        '''
        Generates a long living API key, which the user can use to make
        API calls without having to authenticate using username/password

        The API Key should only be presented once and will be added to the 
        expired token table 
        '''

        _api_key = jwt.encode({
            'uuid': self.uuid,
            #'organization': self.organization_uuid,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(days=365),
            'iat': datetime.datetime.utcnow(),
            'type': 'api'
        }, current_app.config['SECRET_KEY'])

        if self.api_key != None:
            expired_token = ExpiredToken(token=self.api_key)
            expired_token.save()
            self.api_key = _api_key
        else:
            self.api_key = _api_key
        self.save()
        return {'api_key': self.api_key}


    def create_access_token(self):
        '''
        Generates an access_token that is presented each time the
        user calls the API, valid for 6 hours by default
        '''

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

    def has_right(self, permission):
        '''
        Checks to see if the user has the proper 
        permissions to perform an API action
        '''

        role = Role.search().query('match', members=self.uuid).execute()
        if role:
            role = role[0]

        if getattr(role.permissions, permission):
            return True
        else:
            return False

    @classmethod
    def get_by_username(self, username):
        response = self.search().query('match', username=username).execute()
        if response:
            user = response[0]
            return user
        return response

    @classmethod
    def get_by_email(self, email):
        response = self.search().query('match', email=email).execute()
        if response:
            user = response[0]
            return user
        return response


class Permission(InnerDoc):

    # User Permissions
    add_user = Boolean()
    update_user = Boolean()
    delete_user = Boolean()
    add_user_to_role = Boolean()
    remove_user_from_role = Boolean()
    reset_user_password = Boolean()
    unlock_user = Boolean()
    view_users = Boolean()

    # Role Permissions
    add_role = Boolean()
    update_role = Boolean()
    delete_role = Boolean()
    set_role_permissions = Boolean()
    view_roles = Boolean()

    # User Group Permissions
    create_user_group = Boolean()
    view_user_groups = Boolean()
    update_user_groups = Boolean()
    delete_user_group = Boolean()

    # EVENTS
    add_event = Boolean()  # Allows a user to add an event
    view_events = Boolean() # Allows a user to view/list events
    update_event = Boolean() # Allows a user to update an events mutable properties
    delete_event = Boolean() # Allows a user to delete an event

    # EVENT RULES
    create_event_rule = Boolean()
    view_event_rules = Boolean()
    update_event_rule = Boolean()
    delete_event_rule = Boolean()

    # Observable Permissions
    add_observable = Boolean()
    update_observable = Boolean()
    delete_observable = Boolean()
    add_tag_to_observable = Boolean()
    remove_tag_from_observable = Boolean()

    # Playbook Permission
    add_playbook = Boolean()
    update_playbook = Boolean()
    delete_playbook = Boolean()
    view_playbooks = Boolean()
    add_tag_to_playbook = Boolean()
    remove_tag_from_playbook = Boolean()

    # Agent Permissions
    view_agents = Boolean()
    update_agent = Boolean()
    delete_agent = Boolean()
    pair_agent = Boolean()

    # Agent Group Permissions
    create_agent_group = Boolean()
    view_agent_groups = Boolean()
    update_agent_group = Boolean()
    delete_agent_group = Boolean()

    # Input Permissions
    add_input = Boolean()
    view_inputs = Boolean()
    update_input = Boolean()
    delete_input = Boolean()

    # Tag Permissions
    add_tag = Boolean()
    update_tag = Boolean()
    delete_tag = Boolean()
    view_tags = Boolean()

    # Case Permissions
    create_case = Boolean()
    view_cases = Boolean()
    update_case = Boolean()
    delete_case = Boolean()

    # Case File Permissions
    upload_case_files = Boolean()
    view_case_files = Boolean()
    delete_case_files = Boolean()

    # Case Template Task Permissions
    create_case_task = Boolean()
    view_case_tasks = Boolean()
    update_case_task = Boolean()
    delete_case_task = Boolean()

    # Case Template Permissions
    create_case_template = Boolean()
    view_case_templates = Boolean()
    update_case_template = Boolean()
    delete_case_template = Boolean()

    # Case Template Task Permissions
    create_case_template_task = Boolean()
    view_case_template_tasks = Boolean()
    update_case_template_task = Boolean()
    delete_case_template_task = Boolean()

    # Case Comment Permissions
    create_case_comment = Boolean()
    view_case_comments = Boolean()
    update_case_comment = Boolean()
    delete_case_comment = Boolean()

    # Case Status Permissions
    create_case_status = Boolean()
    update_case_status = Boolean()
    delete_case_status = Boolean()

    # Plugin Permissions
    view_plugins = Boolean()
    create_plugin = Boolean()
    delete_plugin = Boolean()
    update_plugin = Boolean()

    # Credential Permissions
    add_credential = Boolean()
    update_credential = Boolean()
    decrypt_credential = Boolean()
    delete_credential = Boolean()
    view_credentials = Boolean()

    # Organization Administration
    add_organization = Boolean()
    view_organizatons = Boolean()
    update_organization = Boolean()
    delete_organization = Boolean()

    # List Permissions
    add_list = Boolean()
    update_list = Boolean()
    view_lists = Boolean()
    delete_list = Boolean()

    # Data Type Permissions
    create_data_type = Boolean()
    update_data_type = Boolean()

    # Update Settings
    update_settings = Boolean()
    view_settings = Boolean()
    create_persistent_pairing_token = Boolean()

    # API Permissions
    use_api = Boolean()


class Role(Document):

    uuid = Text() # Unique identifier for the role
    name = Text() # The name of the role (should be unique)
    description = Text() # A brief description of the role
    members = Keyword()  # Contains a list of user IDs
    permissions = Nested(Permission)

    class Index:
        name = 'reflex-user-roles'

    def add_user_to_role(self, user_id):
        '''
        Adds users unique IDs to the members field
        '''
        if isinstance(user_id, list):
            self.members = self.members + user_id
        else:
            self.members = self.members.append(user_id)
        self.save()

    def remove_user_from_role(self, user_id):
        '''
        Removes members from the members field
        '''
        if isinstance(user_id, list):
            self.members = [m for m in self.members if m not in user_id]
        else:
            self.members.remove(user_id)
        self.save()

    @classmethod
    def get_by_member(self, uuid):
        response = self.search().query('match', members=uuid).execute()
        if response:
            print(response)
            role = response[0]
            return role
        return response

    def save(self, **kwargs):
        '''
        Saves the Role
        ''' 
        self.uuid = uuid.uuid4()
        return super().save(**kwargs)


class ExpiredToken(Document):

    token = Text()

    class Index:
        name = 'reflex-expired-tokens'


class Observable(InnerDoc):

    uuid = Text()
    tags = Keyword()
    data_type = Text()
    value = Text()
    spotted = Boolean()
    ioc = Boolean()
    safe = Boolean()
    tlp = Integer()
    created_at = datetime.datetime.utcnow()

    def save(self, **kwargs):
        self.uuid = uuid.uuid4()
        return super().save(**kwargs)


class Event(Document):

    uuid = Text()
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
        self.uuid = uuid.uuid4()
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

    @classmethod
    def get_by_reference(self, reference):
        response = self.search().query('match', reference=reference).execute()
        if response:
            document = response[0]
            return document
        return response