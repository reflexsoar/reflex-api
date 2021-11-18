from ..utils import token_required, user_has
from flask_restx import Resource, Namespace, fields

api = Namespace('Playbook', description="Playbook operaitons", path="/playbook")

playbook_list = api.model('PlaybookList', {
    'name': fields.String
})

playbook_create = api.model('CreatePlaybook', {
    'name': fields.String(required=True, description='The name of the playbook'),
    'description': fields.String(description='An overview of what the playbook does'),
    'priority': fields.Integer(default=100, required=True, description='What order to run this playbook in'),
    'configuration': fields.String(required=True),
    'enabled': fields.Boolean(default=True, description='Is it enabled'),
    'item_types': fields.List(fields.String, default=['event'], description='What objects can this be run against'),
    'tags': fields.List(fields.String, default=['default'], description='Helpful tags')
})

@api.route('/')
#@api.doc(security="Bearer")
class PlaybookList(Resource):

    def get(self):
        return "OKAY"

    @api.expect(playbook_create)    
    def post(self):

        print(api.payload)
        return "K"

