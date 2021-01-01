import ssl
import json
import uuid
import datetime
import urllib3
import hashlib
from flask import current_app
from collections import namedtuple
from elasticsearch import Elasticsearch
from elasticsearch_dsl import Document, InnerDoc, Date, Integer, Keyword, Text, Boolean, Nested, connections
from json import JSONEncoder

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

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