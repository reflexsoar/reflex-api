from ..utils import page_results, token_required, user_has, ip_approved, default_org, check_org
from flask_restx import Resource, Namespace, fields, inputs as xinputs
from .shared import ISO8601, mod_user_list

from ..model import Task

api = Namespace('Task',
                description="Task operations", path="/task")


mod_task_details = api.model('TaskDetails', {
    'uuid': fields.String,
    'task_type': fields.String,
    'complete': fields.Boolean,
    'started': fields.Boolean,
    'start_date': ISO8601(),
    'end_date': ISO8601(),
    'elapsed_seconds': fields.Integer,
    'broadcast': fields.Boolean,
    'organization': fields.String,
    'message': fields.String,
    'created_by': fields.Nested(mod_user_list)
})

mod_task_list = api.model('TaskList', {
    'tasks': fields.List(fields.Nested(mod_task_details))
})

task_parser = api.parser()
task_parser.add_argument('uuid', location='args', type=str, required=False)
task_parser.add_argument(
    'complete', type=xinputs.boolean, default=None, location='args', required=False)
task_parser.add_argument(
    'broadcast', type=xinputs.boolean, default=None, location='args', required=False)

@api.route("")
class Tasklist(Resource):

    @api.doc(security="Bearer")
    @api.expect(task_parser)
    @api.marshal_with(mod_task_list)
    @token_required
    def get(self, current_user):
        search = Task.search()

        args = task_parser.parse_args()

        # Limit task toasts only to the users organization
        search = search.filter('term', organization=current_user.organization)
        search = search.filter('range', created_at={'gte': 'now-30s'})

        if args.uuid:
            search = search.filter('term', uuid=args.uuid)

        if args.complete is not None:
            search = search.filter('term', complete=args.complete)

        if args.broadcast is not None:
            search = search.filter('term', broadcast=args.broadcast)

        tasks = search.execute()
        return {'tasks': tasks}