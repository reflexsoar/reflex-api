import datetime
import hashlib
from elasticsearch_dsl import Document, InnerDoc, Nested, Keyword, Integer, Date, Text, Boolean, connections


ELASTICSEARCH_URL = ['localhost:9200']
ELASTICSEARCH_AUTH_SCHEMA = "http"
ELASTICSEARCH_USERNAME = 'elastic'
ELASTICSEARCH_PASSWORD = ''
ELASTICSEARCH_SCHEME = 'https'
ELASTICSEARCH_CA = ''
ELASTICSEARCH_CERT_VERIFY = "none"

connections.create_connection(hosts=ELASTICSEARCH_URL, http_auth=(ELASTICSEARCH_USERNAME, ELASTICSEARCH_PASSWORD), use_ssl=True, verify_certs=False)

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
        #self.hash_event()
        return super().save(**kwargs)

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
            o = self.o.get(uuid=observable)
            if o:
                _observables += [o if o['data_type'] in data_types else None]

        for observable in _observables:
            if observable and observable.data_type in sorted(data_types):
                obs.append({'data_type': observable['data_type'].lower(), 'value': observable['value'].lower()})
        obs = [dict(t) for t in {tuple(d.items()) for d in obs}] # Deduplicate the observables
        obs = sorted(sorted(obs, key = lambda i: i['data_type']), key = lambda i: i['value'])
        hasher.update(str(obs).encode())
        self.signature = hasher.hexdigest()
        return

Event.init()

event_content = {
    'meta': {
        'id': 'abcxyz2'
    },
    'title': 'Admin group addition',
    'description': 'Something new was added to an admin group',
    'tags': ['privilege','tactic','admin'],
    'observables': [
        {
            'value':'brian',
            'data_type': 'user',
            'tags': ['secops','manager']
        }
    ]
}

event = Event(**event_content)
event.save()

