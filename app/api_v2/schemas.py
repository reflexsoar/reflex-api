import json
from flask import current_app
from flask_restx import Model, fields

class ObservableCount(fields.Raw):
    ''' Returns the number of observables '''

    def format(self, value):
        return len(value)

class IOCCount(fields.Raw):
    ''' Returns the number of observables that are IOC '''

    def format(self, value):
        iocs = [o for o in value if 'ioc' in o and o['ioc'] == True]
        return len(iocs)

mod_tag_list = Model('TagList', {
    'uuid': fields.String,
    'name': fields.String
})

mod_observable_create = Model('ObservableCreate', {
    'value': fields.String(required=True),
    'ioc': fields.Boolean,
    'tlp': fields.Integer,
    'spotted': fields.Boolean,
    'safe': fields.Boolean,
    'dataType': fields.String(required=True),
    'tags': fields.List(fields.String)
})

mod_observable_list = Model('ObservableList', {
    'tags': fields.List(fields.Nested(mod_tag_list)),
    'value': fields.String,
    'ioc': fields.Boolean,
    'tlp': fields.Integer,
    'spotted': fields.Boolean,
    'safe': fields.Boolean,
    'data_type': fields.String,
    'uuid': fields.String
})

mod_observable_brief = Model('ShortObservableDetails', {
    'uuid': fields.String,
    'value': fields.String,
    'data_type': fields.String
})

mod_raw_log = Model('RawLog', {
    'source_log': fields.String
})

mod_event_create = Model('EventCreate', {
    'title': fields.String(required=True),
    'reference': fields.String(required=True),
    'description': fields.String(required=True),
    'tags': fields.List(fields.String),
    'tlp': fields.Integer,
    'severity': fields.Integer,
    'source': fields.String,
    'observables': fields.List(fields.Nested(mod_observable_create)),
    'raw_log': fields.String
})

mod_event_list = Model('EventList', {
    'uuid': fields.String,
    'title': fields.String(required=True),
    'reference': fields.String(required=True),
    'description': fields.String(required=True),
    'tlp': fields.Integer,
    'severity': fields.Integer,
    #'status': fields.Nested(mod_event_status),
    'source': fields.String,
    #'tags': fields.List(fields.Nested(mod_tag_list), attribute='_tags'),
    #'observables': fields.List(fields.Nested(mod_observable_brief), attribute='_observables'),
    'tags': fields.List(fields.String),
    'observables': fields.List(fields.Nested(mod_observable_brief)),
    'observable_count': ObservableCount(attribute='observables'),
    'ioc_count': IOCCount(attribute='observables'),
    'created_at': fields.String,#ISO8601(attribute='created_at'),
    'modified_at': fields.String, #ISO8601(attribute='modified_at'),
    'case_uuid': fields.String,
    'signature': fields.String,
    'related_events_count': fields.Integer,
    'related_events': fields.List(fields.String),
    #'dismiss_reason': fields.Nested(mod_close_reason_list)
    'raw_log': fields.Nested(mod_raw_log, attribute='_raw_log')
})


schema_models = [mod_event_list, mod_event_create, mod_observable_brief, mod_observable_create, mod_raw_log]