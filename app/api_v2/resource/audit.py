from ..utils import token_required, user_has, ip_approved
from flask_restx import Resource, Namespace, fields
from ..model import EventLog
from .shared import mod_pagination, ISO8601

api = Namespace('AuditLog', description='Reflex audit logs', path='/audit_log')

mod_audit_log = api.model('AuditLog', {
    'created_at': ISO8601(),
    'organization': fields.String,
    'event_type': fields.String,
    'message': fields.String,
    'source_user': fields.String,
    'status': fields.String,
    'event_reference': fields.String,
    'time_taken': fields.String
})

mod_audit_log_paged_list = api.model('AuditLogPagedList', {
    'logs': fields.List(fields.Nested(mod_audit_log)),
    'pagination': fields.Nested(mod_pagination)
})

audit_list_parser = api.parser()
audit_list_parser.add_argument(
    'event_type', action='split', location='args', required=False)
audit_list_parser.add_argument(
    'status', action='split', location='args', required=False)
audit_list_parser.add_argument(
    'source_user', action='split', location='args', required=False)
audit_list_parser.add_argument(
    'page', type=int, location='args', default=1, required=False)
audit_list_parser.add_argument(
    'sort_by', type=str, location='args', default='created_at', required=False)


@api.route("")
class AuditLogsList(Resource):

    @api.doc(security="Bearer")
    @api.marshal_with(mod_audit_log_paged_list)
    @api.expect(audit_list_parser)
    @ip_approved
    @token_required    
    @user_has('view_settings')
    def get(self, current_user):
        ''' Returns a paginated collection of audit logs'''

        args = audit_list_parser.parse_args()

        page_size = 25
        page = args.page - 1
        logs = EventLog.search()

        if args.status:
            logs = logs.filter('terms', status=args.status)

        if args.event_type:
            logs = logs.filter('terms', event_type=args.event_type)

        if args.source_user:
            logs = logs.filter('terms', source_user=args.source_user)

        total_logs = logs.count()
        total_pages = total_logs/page_size

        start = page*page_size
        end = start+page_size
        
        logs = logs.sort('-created_at')
        logs = logs[start:end]
        logs = [l for l in logs]

        return {
            'logs': logs,
            'pagination': {
                'page': page+1,
                'page_size': page_size,
                'total_results': total_logs,
                'pages': total_pages
            }
        }

