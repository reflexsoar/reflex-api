from flask_restx import Model, fields

class ISO8601(fields.Raw):
    ''' Returns a Python DateTime object in ISO8601 format with the Zulu time indicator '''
    def format(self, value):
        return value.isoformat()+"Z"

mod_pagination = Model('Pagination', {
    'total_results': fields.Integer,
    'pages': fields.Integer,
    'page_size': fields.Integer,
    'page': fields.Integer
})