import json
from flask_restx import Model, fields

class ISO8601(fields.Raw):
    ''' Returns a Python DateTime object in ISO8601 format with the Zulu time indicator '''
    def format(self, value):
        return value.isoformat()+"Z"

class ValueCount(fields.Raw):
    ''' Returns the number of values in a list'''
    def format(self, value):
        return len(value)

class AsNewLineDelimited(fields.Raw):
    ''' Returns an array as a string delimited by new line characters '''
    def format(self, value):
        return '\n'.join(list(value))

class JSONField(fields.Raw):
    def format(self, value):
        return value

class ObservableCount(fields.Raw):
    ''' Returns the number of observables '''
    def format(self, value):
        return len(value)
        
class IOCCount(fields.Raw):
    ''' Returns the number of observables that are IOC '''

    def format(self, value):
        iocs = [o for o in value if 'ioc' in o and o['ioc'] is True]
        return len(iocs)

class FormatTags(fields.Raw):
    ''' Returns tags in a specific format for the API response'''

    def format(self, value):
        return [{'name': v} for v in value]

class AsDict(fields.Raw):
    def format(self, value):
        try:
            return json.loads(value)
        except:
            return value

mod_pagination = Model('Pagination', {
    'total_results': fields.Integer,
    'pages': fields.Integer,
    'page_size': fields.Integer,
    'page': fields.Integer
})

mod_data_type_list = Model('DataTypeList', {
    'uuid': fields.String,
    'name': fields.String,
    'description': fields.String,
    'regex': fields.String,
    'created_at': ISO8601(attribute='created_at'),
    'updated_at': ISO8601(attribute='updated_at')
})

mod_observable_list = Model('ObservableList', {
    'tags': fields.List(fields.String),
    'value': fields.String,
    'ioc': fields.Boolean,
    'tlp': fields.Integer,
    'spotted': fields.Boolean,
    'safe': fields.Boolean,
    'data_type': fields.String,
    'uuid': fields.String,
    'case': fields.String,
    'source_field': fields.String,
    'original_source_field': fields.String
})

mod_observable_brief = Model('ShortObservableDetails', {
    'uuid': fields.String,
    'value': fields.String,
    'data_type': fields.String,
    'tags': fields.List(fields.String),
    'source_field': fields.String,
    'original_source_field': fields.String
})