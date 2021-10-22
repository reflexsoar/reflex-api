import jwt
import uuid
import datetime
from flask import current_app
from ..constants import MS_SID_ENDS_WITH, MS_SID_EQUALS
from . import (
    base,
    Keyword,
    Text,
    Boolean,
    Integer,
    AttrList,
    Float,
    Ip,
    user,
    threat
)


class EventLog(base.BaseDocument):
    '''
    EventLog messages that are used for auditing system activity
    '''

    event_type = Keyword()
    source_user = Keyword()
    source_ip = Ip()
    status = Keyword()
    event_reference = Keyword()
    time_taken = Float()
    message = Text()

    class Index: # pylint: disable=too-few-public-methods
        ''' Defines the index to use '''
        name = 'reflex-audit-logs'


class Tag(base.BaseDocument):
    '''
    Tags make it easy for analysts to quickly identify
    actionable information without looking things up
    '''

    _name = Keyword()

    class Index: # pylint: disable=too-few-public-methods
        ''' Defines the index to use '''
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


class DataType(base.BaseDocument):
    '''
    A DataType is really the type of observable e.g. an IP address
    or a domain name, url, hostname, user, etc.
    '''

    name = Keyword()
    description = Text()
    regex = Text()

    class Index: # pylint: disable=too-few-public-methods
        ''' Defines the index to use '''
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


class Settings(base.BaseDocument):
    '''
    Master settings for the application and how certain areas of 
    the application behave
    '''

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

    class Index: # pylint: disable=too-few-public-methods
        ''' Defines the index to use '''
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

        if self.peristent_pairing_token is not None:
            expired = user.ExpiredToken(token=self.peristent_pairing_token)
            expired.create()

        self.update(peristent_pairing_token=_api_key)

        return {'token': self.peristent_pairing_token}


class Observable(base.BaseDocument):
    '''
    An observable is an artifact on an event that is of importance
    to an analyst. An observable could be an IP, domain, email, fqdn, etc.
    '''

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

    class Index: # pylint: disable=too-few-public-methods
        ''' Defines the index to use '''
        name = 'reflex-observables-test'
        settings = {
            'refresh_interval': '1s'
        }

    def save(self, **kwargs):
        '''
        Saves the observable and assigns it a UUID
        '''
        self.uuid = uuid.uuid4()
        return super().save(**kwargs)

    def set_case(self, uuid):
        '''
        Assigns the observable to a case
        '''
        self.case = uuid
        self.save()

    def set_rule(self, uuid):
        '''
        Assigns the event rule the observable belongs to
        '''
        self.rule = uuid
        self.save()

    def toggle_ioc(self):
        '''
        Toggles if the observables is an indicator of compromise
        '''
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
        theat_lists = threat.ThreatList.get_by_data_type(self.data_type)
        for l in theat_lists:
            if l.active:
                hits = l.check_value(self.value)
                if hits > 0:
                    if l.tag_on_match:
                        self.add_tag(f"list: {l.name}")
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
