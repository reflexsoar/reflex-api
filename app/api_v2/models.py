import re
import jwt
import uuid
import datetime
import urllib3
import hashlib
import secrets
import base64
from flask import current_app, request
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import InvalidToken
from elasticsearch_dsl.utils import AttrList
from elasticsearch_dsl import (
    Document,
    InnerDoc,
    Date,
    Integer,
    Keyword,
    Text,
    Boolean,
    Nested,
    Ip,
    Object
)

from .constants import MS_SID_ENDS_WITH, MS_SID_EQUALS
from flask_bcrypt import Bcrypt

FLASK_BCRYPT = Bcrypt()

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def escape_special_characters(string):
    ''' 
    Escapes characters in Elasticsearch that might wedge a search
    and return false matches
    '''

    characters = ['.', ' ']
    for character in characters:
        string = string.replace(character, '\\'+character)
    return string

def _current_user_id_or_none():
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
        if current_user:
            user = User.get_by_uuid(uuid=current_user)
            current_user = {
                'username': user.username,
                'uuid': user.uuid
            }

        return current_user

    except Exception as e:
        return None


class BaseDocument(Document):
    """
    Base class for Documents containing common fields
    """

    uuid = Keyword()
    created_at = Date()
    updated_at = Date()
    updated_by = Nested()
    created_by = Nested()

    @classmethod
    def get_by_uuid(self, uuid, *args, **kwargs):
        '''
        Fetches a document by the uuid field
        '''

        documents = None
        if uuid is not None:
            if isinstance(uuid, list) or isinstance(uuid, AttrList):
                response = self.search().query('terms', uuid=uuid, **kwargs).execute()
                documents = [r for r in response]
            else:
                response = self.search().query('term', uuid=uuid, **kwargs).execute()
                if response:
                    documents = response[0]
                else:
                    documents = None
            return documents
        return []

    def save(self, **kwargs):
        '''
        Overrides the default Document save() function and adds
        audit fields created_at, updated_at and a default uuid field
        '''

        if not self.created_at:
            self.created_at = datetime.datetime.utcnow()

        if not self.created_by:
            self.created_by = _current_user_id_or_none()

        if not self.uuid:
            self.uuid = uuid.uuid4()

        self.updated_at = datetime.datetime.utcnow()
        self.updated_by = _current_user_id_or_none()
        return super(BaseDocument, self).save(**kwargs)

    def update(self, **kwargs):
        '''
        Overrides the default Document update() function and 
        adds an update to updated_at each time the document 
        is saved 
        '''

        self.updated_at = datetime.datetime.utcnow()
        self.updated_by = _current_user_id_or_none()
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
            # 'organization': self.organization_uuid,
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

        #user_agent_hash = hashlib.md5(user_agent_string).hexdigest()

        # refresh_token = RefreshToken.query.filter_by(
        #    user_agent_hash=user_agent_hash).first()

        # if not refresh_token:
        #    refresh_token = RefreshToken(
        #        user_uuid=self.uuid, refresh_token=_refresh_token, user_agent_hash=user_agent_hash)
        #    refresh_token.create()
        #    _refresh_token = refresh_token.refresh_token
        # else:
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

        if hasattr(role.permissions, permission) and getattr(role.permissions, permission):
            return True
        else:
            return False

    @classmethod
    def get_by_username(self, username):
        response = self.search().query(
            'match', username=escape_special_characters(username)).execute()
        if response:
            user = response[0]
            return user
        return response

    @classmethod
    def get_by_email(self, email):
        response = self.search().query(
            'match', email=escape_special_characters(email)).execute()
        if response:
            user = response[0]
            return user
        return response

    def unlock(self):
        '''
        Unlocks a user account and resets their failed_logons back to 0
        '''
        if self.locked:
            self.locked = False
            self.failed_logons = 0
            self.save()

    def load_role(self):
        self.role = Role.get_by_member(self.uuid)


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
    view_events = Boolean()  # Allows a user to view/list events
    update_event = Boolean()  # Allows a user to update an events mutable properties
    delete_event = Boolean()  # Allows a user to delete an event

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
    add_agent = Boolean()
    view_agents = Boolean()
    update_agent = Boolean()
    delete_agent = Boolean()
    pair_agent = Boolean()

    # Agent Group Permissions
    add_agent_group = Boolean()
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

    # Close Reason Permissions
    create_close_reason = Boolean()
    update_close_reason = Boolean()
    delete_close_reason = Boolean()

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


class Role(BaseDocument):

    name = Keyword()  # The name of the role (should be unique)
    description = Text()  # A brief description of the role
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
            if self.members and user_id not in self.members:
                self.members.append(user_id)
            else:
                self.members = [user_id]
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
            role = response[0]
            return role
        return response

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


class ExpiredToken(BaseDocument):

    token = Keyword()

    class Index:
        name = 'reflex-expired-tokens'


class Tag(BaseDocument):

    _name = Keyword()

    class Index():
        name = 'reflex-tags'

    @property
    def name(self):
        return self._name.lower()

    @name.setter
    def name(self, value):
        self._name = value.lower()
        self.save()

    @classmethod
    def get_by_name(self, name):
        '''
        Fetches a document by the name field
        Uses a term search on a keyword field for EXACT matching
        '''
        response = self.search().query('term', _name=name.lower()).execute()
        if response:
            document = response[0]
            return document
        return response


class EventObservable(InnerDoc):

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

    def __eq__(self, other):
        return self.data_type==other.data_type and self.value==other.value

    def __hash__(self):
        return hash(('data_type', self.data_type, 'value', self.value))


class Observable(BaseDocument):

    uuid = Text()
    tags = Keyword()
    data_type = Text()
    value = Keyword()
    spotted = Boolean()
    ioc = Boolean()
    safe = Boolean()
    tlp = Integer()
    events = Keyword() # A list of event UUIDs this Observable belongs to
    case = Keyword() # The case the observable belongs to
    rule = Keyword() # The rule the Observable belongs to

    class Index():
        name = 'reflex-observables-test'
        settings = {
            'refresh_interval': '1s'
        }

    def save(self, **kwargs):
        self.uuid = uuid.uuid4()
        return super().save(**kwargs)

    def set_case(self, uuid):
        self.case = uuid
        self.save()

    def set_rule(self, uuid):
        self.rule = uuid
        self.save()

    def toggle_ioc(self):
        if self.ioc:
            self.update(ioc=False, refresh=True)
        else:
            self.update(ioc=True, refresh=True)


    def enrich(self):
        '''
        Enriches the observable with some static information
        based on industry known information
        '''

        # Well known SIDs for Microsoft Domains
        if self.data_type == 'sid':
            for k in MS_SID_ENDS_WITH:
                if self.value.endswith(k):
                    self.add_tag(MS_SID_ENDS_WITH[k])

            for k in MS_SID_EQUALS:
                if self.value == k:
                    self.add_tag(MS_SID_EQUALS[k])

        self.save()

    def add_event_uuid(self, uuid):
        '''
        Adds an event UUID to an observable for future lookup
        '''
        if self.events:
            if uuid not in self.events:
                self.events.append(uuid)
        else:
            self.events = [uuid]

    def add_tag(self, tag):
        '''
        Adds a tag to the observable
        '''
        if self.tags:
            if tag not in self.tags:
                self.tags.append(tag)
        else:
            self.tags = [tag]

    def check_threat_list(self):
        '''
        Checks the value of the observable against all threat
        lists for this type
        '''
        theat_lists = ThreatList.get_by_data_type(self.data_type)
        for l in theat_lists:
            hits = l.check_value(self.value)           
            if hits > 0:
                if l.tag_on_match:
                    self.add_tag("list: {}".format(l.name))
        self.save()


    @classmethod
    def get_by_value(self, value, all_docs=True):
        '''
        Fetches a document by the value field
        '''
        documents = []
        if value is not None:
            if isinstance(value, list):
                response = self.search().query('terms', value=value)
                if all_docs:
                    response = response[0:response.count()]
                    response.execute()
                else:
                    response.execute()
                documents = [r for r in response]
            else:
                response = self.search().query('term', value=value)
                if all_docs:
                    response = response[0:response.count()]
                    response.execute()
                else:
                    response.execute()
                documents = response

        return documents

    @classmethod
    def get_by_event_uuid(self, uuid, all_docs=True):
        '''
        Fetches the observable based on the related event
        '''

        documents = []
        # TODO: Deduplicate this code
        if uuid is not None:
            if isinstance(uuid, list) or isinstance(uuid, AttrList):
                response = self.search().query('terms', events=uuid)
                if all_docs:
                    response = response[0:response.count()]
                    response.execute()
                else:
                    response.execute()
                documents = [r for r in response] if response else []
            else:
                response = self.search().query('term', events=uuid)
                if all_docs:
                    response = response[0:response.count()]
                    response.execute()
                else:
                    response.execute()
                documents = [r for r in response] if response else []

        return documents

    @classmethod
    def get_by_case_uuid(self, uuid):
        '''
        Fetches the observable based on the related case
        '''
        response = self.search().query('match', case=uuid).execute()
        if response:
            return response
        else:
            return None

    @classmethod
    def get_by_case_and_value(self, uuid, value):
        '''
        Fetches the observable based on the case and the value
        '''
        s = self.search()
        #if any(c in value for c in ['-','@']):        
        #    s = s.filter('term', value__keyword=value)
        #else:
        s = s.filter('match', value=value)
        s = s.filter('match', case=uuid)
        response = s.execute()
        if response:
            return response[0]
        else:
            return None

    def __eq__(self, other):
        return self.data_type==other.data_type and self.value==other.value

    def __hash__(self):
        return hash(('data_type', self.data_type, 'value', self.value))

"""
OLD OBSERVBALE CLASS
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
    case = Keyword()

    class Index():
        name = 'reflex-observables'

    def save(self, **kwargs):
        self.uuid = uuid.uuid4()
        return super().save(**kwargs)

    def set_case(self, uuid):
        self.case = uuid
        self.save()

    def __eq__(self, other):
        return self.data_type==other.data_type and self.value==other.value

    def __hash__(self):
        return hash(('data_type', self.data_type, 'value', self.value))
"""


class EventStatus(BaseDocument):

    name = Keyword()
    description = Text()
    closed = Boolean()

    class Index():
        name = 'reflex-event-statuses'

    @classmethod
    def get_by_name(self, name):
        '''
        Fetches a document by the name field
        Uses a term search on a keyword field for EXACT matching
        '''
        response = self.search().query('term', name=name).execute()
        if response:
            status = response[0]
            return status
        return response


class Event(BaseDocument):

    uuid = Keyword()
    title = Keyword()
    description = Text()
    reference = Keyword()
    case = Keyword()
    source = Text()
    tlp = Integer()
    severity = Integer()
    tags = Keyword()
    #event_observables = Nested(Observable)
    status = Object()
    signature = Keyword()
    dismissed = Boolean()
    dismiss_reason = Text()
    dismiss_comment = Text()
    dismissed_by = Object()
    raw_log = Text()

    class Index:
        name = 'reflex-events'

    @property
    def observables(self):
        observables = Observable.get_by_event_uuid(self.uuid)
        return [r for r in observables]

    @observables.setter
    def observables(self, value):
        self.event_observables = value
        self.save

    def add_observable(self, content):
        '''
        Adds an observable to the event and also checks it
        against threatlists that are defined in the system
        '''

        added_observables = []
        for o in content:

            observable = Observable(**o)

            observable.add_event_uuid(self.uuid)
            observable.check_threat_list()
            observable.enrich()
            observable.save()
            added_observables.append(observable)

        return added_observables

    def set_open(self):
        self.status = EventStatus.get_by_name(name='Open')
        self.save()

    def set_new(self):
        self.status = EventStatus.get_by_name(name='New')
        self.save()

    def set_dismissed(self, reason, comment=None):
        self.status = EventStatus.get_by_name(name='Dismissed')
        if comment:
            self.dismiss_comment = comment
            self.dismiss_reason = reason.title
            self.dismissed_by = _current_user_id_or_none()
        self.save()

    def set_closed(self):
        self.status = EventStatus.get_by_name(name='Closed')
        self.save()

    def set_case(self, uuid):
        self.case = uuid
        self.save()

    def hash_event(self, data_types=['host', 'user', 'ip', 'string'], observables=[]):
        '''
        Generates an md5 signature of the event by combining the Events title
        and the observables attached to the event.  The Event signature is used
        for correlating multiple instances of an event
        '''

        _observables = []
        obs = []

        hasher = hashlib.md5()
        hasher.update(self.title.encode())

        for observable in observables:
            _observables += [observable if observable.data_type in data_types else None]

        for observable in _observables:
            if observable and observable.data_type in sorted(data_types):
                obs.append({'data_type': observable.data_type.lower(),
                            'value': observable.value.lower()})
        obs = [dict(t) for t in {tuple(d.items())
                                 for d in obs}]  # Deduplicate the observables
        obs = sorted(
            sorted(obs, key=lambda i: i['data_type']), key=lambda i: i['value'])
        hasher.update(str(obs).encode())
        self.signature = hasher.hexdigest()
        return

    def check_event_rule_signature(self, signature, observables=[]):
        hasher = hashlib.md5()
        obs = []

        for observable in observables:
            obs.append({'data_type': observable.data_type.lower(),
                        'value': observable.value.lower()})
        obs = [dict(t) for t in {tuple(d.items())
                                 for d in obs}]  # Deduplicate the observables
        obs = sorted(
            sorted(obs, key=lambda i: i['data_type']), key=lambda i: i['value'])
        hasher.update(str(obs).encode())
        if signature == hasher.hexdigest():
            return True
        else:
            return False

    @classmethod
    def get_by_reference(self, reference):
        response = self.search().query('match', reference=reference).execute()
        if response:
            document = response[0]
            return document
        return response

    @classmethod
    def get_by_signature(self, signature):
        response = self.search().query('match', signature=signature).execute()
        if len(response) >= 1:
            return [d for d in response]
        else:
            return [response]

    @classmethod
    def get_by_case(self, case):
        """
        Returns any event that has a case uuid associated with it that
        matches the :case: variable
        """
        response = self.search().query('term', case=case).execute()
        if len(response) >= 1:
            return [d for d in response]
        else:
            return [response]


class EventRule(BaseDocument):
    '''
    An Event Rule is created so that when new events come in they can
    be automatically handled based on how the analyst sees fit without the
    analyst actually having to do anything.
    '''

    name = Keyword()
    description = Text()
    event_signature = Keyword()  # The title of the event that this was created from
    rule_signature = Keyword()  # A hash of the title + user customized observable values
    # The target case to merge this into if merge into case is selected
    target_case_uuid = Keyword()
    #observables = Nested(Observable)
    merge_into_case = Boolean()
    dismiss = Boolean()
    expire = Boolean()  # If not set the rule will never expire, Default: True
    expire_at = Date()  # Computed from the created_at date of the event + a timedelta in days
    active = Boolean()  # Users can override the alarm and disable it out-right
    hit_count = Integer()

    class Index:
        name = 'reflex-event-rules'

    def add_observable(self, content):
        '''
        Adds an observable to the event and also checks it
        against threatlists that are defined in the system
        '''

        added_observables = []
        for o in content:

            observable = Observable(**o)

            observable.set_rule(self.uuid)
            observable.save()
            added_observables.append(observable)

        return added_observables

    def hash_observables(self, observables=[]):
        hasher = hashlib.md5()
        obs = []
        for observable in observables:
            obs.append({'data_type': observable.data_type.lower(),
                        'value': observable.value.lower()})
        obs = [dict(t) for t in {tuple(d.items())
                                 for d in obs}]  # Deduplicate the observables
        obs = sorted(
            sorted(obs, key=lambda i: i['data_type']), key=lambda i: i['value'])
        hasher.update(str(obs).encode())
        self.rule_signature = hasher.hexdigest()
        self.save()
        return

    def hash_target_observables(self, target_observables):
        hasher = hashlib.md5()
        obs = []
        expected_observables = [{'data_type': obs.data_type.lower(
        ), 'value': obs.value.lower()} for obs in self.observables]
        for observable in target_observables:
            obs_dict = {'data_type': observable.data_type.name.lower(
            ), 'value': observable.value.lower()}
            if obs_dict in expected_observables:
                obs.append(obs_dict)
        obs = [dict(t) for t in {tuple(d.items())
                                 for d in obs}]  # Deduplicate the observables
        obs = sorted(
            sorted(obs, key=lambda i: i['data_type']), key=lambda i: i['value'])
        hasher.update(str(obs).encode())
        return hasher.hexdigest()

    def process(self, event) -> bool:
        """
        Process the event based on the settings in the rule
        """
        # Check if the should be expired, disable the rule if it expired
        if self.expire and self.expire_at < datetime.datetime.utcnow():
            self.active = False
            self.save()
            return False
            
        else:

            # Increment the hit count
            if self.hit_count:
                self.hit_count += 1
            else:
                self.hit_count = 1
            self.save()

            if self.dismiss:
                event.set_dismissed()
                return True
            elif self.merge_into_case:

                # Set the event open and link it to the case
                event.set_open()
                event.set_case(self.target_case_uuid)

                # Fetch the case and add the observables
                # from the event
                case = Case.get_by_uuid(self.target_case_uuid)
                event_observables = Observable.get_by_event_uuid(event.uuid)
                print("Event:",event.uuid, event_observables)
                case_observables = Observable.get_by_case_uuid(self.target_case_uuid)
                print("Case:", case_observables)
                new_observables = None
                if case_observables:
                    new_observables = [o for o in event_observables if o.value not in [o.value for o in case_observables]]
                    print(new_observables)
                else:
                    new_observables = [o for o in event_observables]
                    print(new_observables)

                new_observables =[Observable(
                    tags=o.tags, value=o.value, data_type=o.data_type, ioc=o.ioc, spotted=o.spotted, tlp=o.tlp, case=case.uuid) for o in new_observables]

                if new_observables:
                    [o.save() for o in new_observables]

                # Add the event to the case
                case.add_event(event)
                return True                

        return False


    @classmethod
    def get_by_title(self, title):
        """
        Returns an event rule by its event_signature (event title)
        By default only returns active rules
        """

        query = self.search()
        query = query.filter('term', event_signature=title)
        
        response = query.execute()
        if len(response) >= 1:
            rule = [r for r in response if hasattr(r, 'active') and r.active]
        else:
            if hasattr(response, 'active') and response.active:
                rule = [response]
            else:
                rule = None

        return rule

class CaseHistory(BaseDocument):
    ''' 
    A case history entry that shows what changed on the case
    the message should be stored in markdown format
    so that it can be processed by the UI
    '''

    message = Text()
    case_uuid = Keyword()  # The uuid of the case this history belongs to

    class Index:
        name = 'reflex-case-history'

    @classmethod
    def get_by_case(self, uuid):
        '''
        Fetches a document by the uuid field
        '''
        response = self.search().query('match', case=uuid).execute()
        if response:
            return [r for r in response]
        return []


class CaseComment(BaseDocument):
    '''
    A case comment that allows analysts to exchange information
    and notes on a case
    '''

    message = Text()
    case_uuid = Keyword()  # The uuid of the case this comment belongs to
    is_closure_comment = Boolean()  # Is this comment related to closing the case
    edited = Boolean()  # Should be True when the comment is edited, Default: False
    closure_reason = Object()

    class Index:
        name = 'reflex-case-comments'

    @classmethod
    def get_by_case(self, uuid):
        '''
        Fetches a document by the uuid field
        '''
        response = self.search().query('match', case_uuid=uuid).execute()
        if response:
            return [r for r in response]
        return []


class CaseStatus(BaseDocument):

    name = Keyword()
    description = Text()
    closed = Boolean()

    class Index:
        name = 'reflex-case-statuses'

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


class CloseReason(BaseDocument):
    '''
    A custom sub-status for why a case was closed
    e.g. False Positive, Not Enough Information
    '''

    title = Keyword()
    description = Text()

    class Index:
        name = 'reflex-close-reasons'

    @classmethod
    def get_by_name(self, title):
        '''
        Fetches a document by the name field
        Uses a term search on a keyword field for EXACT matching
        '''
        response = self.search().query('term', title=title).execute()
        if response:
            user = response[0]
            return user
        return response


class Owner(InnerDoc):

    uuid = Keyword()
    username = Keyword()


class CloseReasonNested(InnerDoc):

    uuid = Keyword()
    title = Keyword()
    description = Text()


class CaseStatusNested(InnerDoc):

    uuid = Keyword()
    name = Keyword()
    closed = Boolean()


class CaseTemplateNested(InnerDoc):

    uuid = Keyword()
    title = Keyword()


class Case(BaseDocument):
    '''
    A case contains all the investigative work related to a
    series of events that were observed in the system
    '''

    title = Keyword()
    description = Text()
    severity = Integer()
    owner = Object()
    tlp = Integer()
    tags = Keyword()
    status = Object()
    related_cases = Keyword()  # A list of UUIDs related to this case
    closed = Boolean()
    closed_at = Date()
    close_reason = Object()
    case_template = Object()
    files = Keyword()  # The UUIDs of case files
    events = Keyword()

    class Index:
        name = 'reflex-cases'

    @property
    def observables(self):
        observables = Observable.get_by_case_uuid(self.uuid)
        if observables:
            return [r for r in observables]
        else:
            return []

    @observables.setter
    def observables(self, value):
        self.case_observables = value
        self.save

    def add_observables(self, observable, case_uuid=None):
        '''
        Adds an observable to the case by adding it to the observables index
        and linking the case
        '''

        if isinstance(observable, list):
            for o in observable:
                _observable = Observable.get_by_case_and_value(self.uuid, o['value'])
                if not _observable:
                    _observable = Observable(tags=o['tags'], value=o['value'], data_type=o['data_type'], ioc=o['ioc'], spotted=o['spotted'], tlp=o['tlp'], safe=o['safe'], case=case_uuid)
                    _observable.check_threat_list()
                    _observable.enrich()
                    _observable.save()
        else:
            o = observable
            _observable = Observable.get_by_case_uuid(self.uuid, o['value'])
            if not _observable:
                _observable = Observable(tags=o['tags'], value=o['value'], data_type=o['data_type'], ioc=o['ioc'], spotted=o['spotted'], tlp=o['tlp'], safe=o['safe'], case=case_uuid)
                _observable.check_threat_list()
                _observable.enrich()
                _observable.save()

    def get_observable_by_value(self, value):
        ''' Returns an observable based on its value '''
        if obs := [o for o in self.observables if o.value == value]:
            return obs[0]
        else:
            return None

    def set_owner(self, uuid):
        '''
        Sets the bare minimum information about the
        owner of the case so the UI can render it
        '''

        owner = User.get_by_uuid(uuid=uuid)

        owner_data = {
            'username': owner.username,
            'uuid': owner.uuid
        }
        self.owner = owner_data
        self.save()

    def set_template(self, uuid):
        '''
        Sets the case template
        '''

        template = CaseTemplate.get_by_uuid(uuid=uuid)
        self.case_template = template
        self.save()

    def close(self, uuid):
        '''
        Closes a case and sets the time that it was closed
        '''
        self.close_reason = CloseReason.get_by_uuid(uuid=uuid)
        self.closed_at = datetime.datetime.utcnow()
        self.closed = True

        # Close all the related events
        for e in self.events:
            event = Event.get_by_uuid(e)
            event.set_closed()

        self.save()

    def reopen(self):
        '''
        Reopens a case
        '''
        self.closed = False
        self.close_at = None

        # Reopen all the related events
        for e in self.events:
            event = Event.get_by_uuid(e)
            event.set_open()

        self.save()

    @classmethod
    def get_related_cases(self, uuid):
        cases = self.search().query('term', related_cases=uuid).execute()
        if cases:
            return [c for c in cases]
        else:
            return []
        return

    def add_history(self, message):
        '''
        Creates a history message and associates it with
        this case
        '''
        history = CaseHistory(message=message, case=self.uuid)
        history.save()

    def add_task(self, **task):
        '''
        Adds a task to the cases tasks list and adds a history entry
        '''
        task = CaseTask(**task, case=self.uuid)
        task.status = 0
        task.save()
        self.add_history('Task **{}** added'.format(task.title))
        return task

    def add_event(self, event):
        '''
        Adds an event or list of events to the case
        '''
        if isinstance(event, list):
            self.events.append([e.uuid for e in event])
        else:
            if self.events:
                self.events.append(event.uuid)
            else:
                self.events = [event.uuid]
        self.save()
        return True
        

class TaskNote(BaseDocument):
    '''
    A note on a case task
    '''

    note = Text()
    task = Keyword() # The UUID of the associated task

    class Index:
        name = 'reflex-case-task-notes'

    @classmethod
    def get_by_task_uuid(self, uuid):
        '''
        Fetches a note by the associated task UUID
        '''
        response = self.search().query('match', task=uuid).execute()
        if response:
            return [r for r in response]
        else:
            return []        


class CaseTask(BaseDocument):
    '''
    An action that needs to occur on a Case
    '''

    title = Keyword()
    order = Integer()
    description = Text()
    owner = Nested()  # The user that is assigned to this task by default
    group = Nested()  # The group that is assigned to this task by default
    case = Keyword()  # The UUID of the case this task belongs to
    from_template = Boolean()  # Indicates if the task came from a template. Default: False
    status = Integer()  # 0 = Open, 1 = Started, 2 = Complete
    start_date = Date()
    finish_date = Date()
    notes = Keyword()

    class Index:
        name = 'reflex-case-tasks'

    @property
    def _notes(self):
        notes = TaskNote.get_by_task_uuid(self.uuid)
        return notes

    @_notes.setter
    def observables(self, value):
        self.notes.append(value)
        self.save()

    @classmethod
    def get_by_case(self, uuid):
        '''
        Fetches a document by the uuid field
        '''
        response = self.search().query('match', case=uuid).execute()
        if response:
            return [r for r in response]
        return []

    @classmethod
    def get_by_title(self, title, case_uuid):
        '''
        Fetches a task by the title and case uuid
        '''
        response = self.search().query('match', case=case_uuid).query(
            'term', title=title).execute()
        if response:
            document = response[0]
            return document
        return response

    def close_task(self):
        '''
        Closes the task and gives it a completion date
        '''
        self.status = 2
        self.finish_date = datetime.datetime.utcnow()
        case = Case.get_by_uuid(uuid=self.case)
        case.add_history('Task **{}** closed'.format(self.title))
        self.save()

    def start_task(self, owner_uuid=None):
        '''
        Starts the task and gives it a date
        '''
        self.status = 1
        self.start_date = datetime.datetime.utcnow()
        if owner_uuid:
            self.set_owner(owner_uuid)
        case = Case.get_by_uuid(uuid=self.case)
        case.add_history('Task **{}** started'.format(self.title))
        self.save()

    def reopen_task(self):
        '''
        Reopens the task and resets the finish_date
        '''
        self.status = 1
        self.finish_date = None
        case = Case.get_by_uuid(uuid=self.case)
        case.add_history('Task **{}** reopened'.format(self.title))
        self.save()

    def set_owner(self, owner_uuid):
        '''
        Sets the owner of the case by the users uuid
        '''
        if owner_uuid:
            owner = User.get_by_uuid(owner_uuid)
            if owner:
                self.owner = {k: owner[k]
                              for k in owner if k in ['uuid', 'username']}

    def add_note(self, note):
        '''
        Adds a note to this task
        '''
        if note:
            note = TaskNote(note=note, task=self.uuid)
            note.save()
            if self.notes:
                self.notes.append(note.uuid)
            else:
                self.notes = [note.uuid]
        self.save()
        return note

    def delete(self, **kwargs):
        '''
        Deletes a task and appends a history message
        to the associated parent case
        '''

        case = Case.get_by_uuid(uuid=self.case)
        case.add_history('Task **{}** deleted'.format(self.title))

        return super(CaseTask, self).delete(**kwargs)


class CaseTemplateTask(InnerDoc):
    '''
    An action that needs to occur on a Case
    '''

    uuid = Keyword()
    title = Keyword()
    order = Integer()
    description = Text()
    owner = Keyword()  # The user that is assigned to this task by default
    group = Keyword()  # The group that is assigned to this task by default
    case = Keyword()  # The UUID of the case this task belongs to
    from_template = Boolean()  # Indicates if the task came from a template. Default: False
    status = Integer()  # 0 = Open, 1 = Started, 2 = Complete
    start_date = Date()
    finish_date = Date()


class CaseTemplate(BaseDocument):
    '''
    A Case Template represents a static format that a case can
    be created from when the work path is clearly defined
    '''

    title = Keyword()
    description = Text()
    severity = Integer()  # The default severity of the case
    owner = Keyword()  # The default owner of the case
    tlp = Integer()  # The default TLP of the case
    tags = Keyword()
    tasks = Nested(CaseTemplateTask)

    class Index:
        name = 'reflex-case-templates'

    @classmethod
    def title_search(self, s):
        '''
        Searches for a title based on a wildcard
        '''
        s = self.search().query('wildcard', title=s+'*')
        results = s.execute()
        if results:
            return [r for r in results]
        else:
            return []

    @classmethod
    def get_by_title(self, title):
        '''
        Fetches a document by the name field
        Uses a term search on a keyword field for EXACT matching
        '''
        response = self.search().query('term', title=title).execute()
        if response:
            document = response[0]
            return document
        return response


class Credential(BaseDocument):

    name = Keyword()
    description = Text()
    username = Text()
    secret = Text()

    class Index:
        name = 'reflex-credentials'

    def _derive_key(self, secret: bytes, salt: bytes, iterations: int = 100_000) -> bytes:

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=iterations,
            backend=default_backend()
        )
        return base64.urlsafe_b64encode(kdf.derive(secret))

    def encrypt(self, message: bytes, secret: str, iterations: int = 100_000) -> bytes:
        iterations = 100_000
        salt = secrets.token_bytes(16)
        key = self._derive_key(secret.encode(), salt, iterations)
        self.secret = base64.urlsafe_b64encode(b'%b%b%b' % (salt, iterations.to_bytes(4, 'big'),
                                                            base64.urlsafe_b64encode(Fernet(key).encrypt(message)))).decode()
        self.save()

    def decrypt(self, secret: str) -> bytes:
        decoded = base64.urlsafe_b64decode(self.secret)
        salt, iter, token = decoded[:16], decoded[16:20], base64.urlsafe_b64decode(
            decoded[20:])
        iterations = int.from_bytes(iter, 'big')
        key = self._derive_key(secret.encode(), salt, iterations)
        try:
            return Fernet(key).decrypt(token).decode()
        except InvalidToken:
            return None

    @classmethod
    def get_by_name(self, name):
        '''
        Fetches a document by the name field
        Uses a term search on a keyword field for EXACT matching
        '''
        response = self.search().query('term', name=name).execute()
        if response:
            document = response[0]
            return document
        return response


class FieldMap(InnerDoc):

    field = Keyword()
    data_type = Text()
    tlp = Integer()
    tags = Keyword()


class Input(BaseDocument):

    name = Keyword()
    description = Text()

    # Renamed from 'plugin'.
    # The name of the ingestor being used e.g. 'elasticsearch' or 'ews'
    source = Text()
    enabled = Boolean()  # Default to False
    config = Object()
    credential = Text()  # The UUID of the credential in use
    tags = Keyword()
    field_mapping = Nested(FieldMap)

    class Index:
        name = 'reflex-inputs'

    @property
    def _config(self):
        ''' Returns the configuration as a dict '''
        if isinstance(self.config, AttrList):
            return self.config[0].to_dict()
        return self.config.to_dict()

    @property
    def _field_mapping(self):
        ''' Returns the field mapping as a dict '''
        if isinstance(self.field_mapping, AttrList):
            return self.field_mapping[0].to_dict()
        return self.field_mapping.to_dict()

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


class Agent(BaseDocument):

    name = Keyword()
    inputs = Keyword()  # A list of UUIDs of which inputs to run
    roles = Keyword()  # A list of roles that the agent belongs to
    groups = Keyword()  # A list of UUIDs that the agent belongs to
    active = Boolean()
    ip_address = Ip()
    last_heartbeat = Date()

    class Index:
        name = 'reflex-agents'

    @property
    def _inputs(self):
        inputs = Input.get_by_uuid(uuid=self.inputs)
        return [i for i in inputs]

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


class AgentGroup(BaseDocument):

    name = Keyword()
    description = Text()
    agents = Keyword()

    class Index:
        name = 'reflex-agent-groups'

    def add_agent(self, uuid):
        '''
        Adds an agent to to the group
        '''
        if self.agents:
            self.agents.append(uuid)
        else:
            self.agents = [uuid]
        self.save()


class DataType(BaseDocument):

    name = Keyword()
    description = Text()
    regex = Text()

    class Index:
        name = 'reflex-data-types'

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


class DataTypeBrief(InnerDoc):

    name = Keyword()


class ThreatList(BaseDocument):

    name = Keyword()
    description = Text()
    list_type = Text()  # value or pattern
    data_type_uuid = Keyword()
    tag_on_match = Boolean()  # Default to False
    values = Keyword()  # A list of values to match on
    url = Text() # A url to pull threat information from
    poll_interval = Integer() # How often to pull from this list
    last_polled = Date() # The time that the list was last fetched
    active = Boolean()

    class Index:
        name = 'reflex-threat-lists'

    @property
    def data_type(self):
        data_type = DataType.get_by_uuid(uuid=self.data_type_uuid)
        if data_type:
            return data_type
        else:
            return []

    def check_value(self, value):
        '''
        Checks to see if a value matches a value list or a regular expression
        based list and returns the number of hits on that list'
        '''
        hits = 0

        if self.list_type == 'values':
            hits = len([v for v in self.values if v.lower() == value.lower()])
        elif self.list_type == 'patterns':
            hits = len([v for v in self.values if re.match(v, value) != None])

        return hits

    def set_values(self, values: list = [], from_poll=False):
        '''
        Sets the values of the threat list from a list of values
        '''
        if len(values) > 0:
            self.values = values
        
        if from_poll:
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
    def get_by_data_type(self, data_type):
        '''
        Fetches the threat list by the data_type
        it should be associated with
        '''
        dt = DataType.get_by_name(name=data_type)
        response = self.search().query('term', data_type_uuid=dt.uuid).execute()
        if response:
            return [r for r in response]
        else:
            return []


class Plugin(BaseDocument):

    name = Text()
    description = Text()
    manifest = Object()
    config_template = Object()
    enabled = Boolean()
    filename = Text()
    file_hash = Text()
    configs = Keyword()

    class Index():
        name = 'reflex-plugins'

    @property
    def config_count(self):
        '''
        Returns how many configurations are associated
        with this plugin
        '''
        if self.configs:
            return len(self.configs)
        else:
            return 0
    
    def add_config(self, config):
        '''
        Adds a reference to a configuration item
        '''
        if self.configs:
            self.configs.append(config.uuid)
        else:
            self.configs = [uuid]
        self.save()


class PluginConfig(BaseDocument):

    name = Text()
    description = Text()
    config = Object()

    class Index():
        name = 'reflex-plugin-configs'


class EventLog(BaseDocument):

    event_type = Text()
    message = Text()

    class Index():
        name = 'reflex-audit-logs'


class Settings(BaseDocument):

    base_url = Text()
    require_case_templates = Boolean()  # Default True
    #email_from = Text()
    #email_server = db.Column(db.String(255))
    #email_secret_uuid = db.Column(db.String(255), db.ForeignKey("credential.uuid"))
    #email_secret = db.relationship('Credential')
    allow_comment_deletion = Boolean()  # Default False
    playbook_action_timeout = Integer()  # Default 300
    playbook_timeout = Integer()  # Default 3600
    logon_password_attempts = Integer()  # Default 5
    api_key_valid_days = Integer()  # Default 366 days
    agent_pairing_token_valid_minutes = Integer()  # Default 15
    peristent_pairing_token = Text()
    require_event_dismiss_comment = Boolean()  # Default False
    allow_event_deletion = Boolean()  # Default False
    require_case_close_comment = Boolean()  # Default False
    assign_case_on_create = Boolean()  # Default True
    assign_task_on_start = Boolean()  # Default True
    allow_comment_editing = Boolean()  # Default False
    events_page_refresh = Integer()  # Default 60
    events_per_page = Integer()  # Default 10
    # ip,user,host,fqdn,sha1,md5,sha256,imphash,ssdeep,vthash,network,domain,url,mail
    data_types = Keyword()
    require_approved_ips = Boolean()
    approved_ips = Keyword()

    class Index:
        name = 'reflex-settings'

    @classmethod
    def load(self):
        ''' 
        Loads the settings, there should only be one entry
        in the index so execute should only return one entry, if for some
        reason there are more than one settings documents, return the most recent
        '''
        settings = self.search().execute()
        if settings:
            return settings[0]
        else:
            return None

    def generate_persistent_pairing_token(self):
        '''
        Generates a long living pairing token which can be used in
        automated deployment of agents
        '''

        _api_key = jwt.encode({
            'iat': datetime.datetime.utcnow(),
            'type': 'pairing'
        }, current_app.config['SECRET_KEY'])

        if self.peristent_pairing_token != None:
            expired = ExpiredToken(token=self.peristent_pairing_token)
            expired.create()

        self.update(peristent_pairing_token=_api_key)

        return {'token': self.peristent_pairing_token}
