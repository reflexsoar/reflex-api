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