from flask_restx import Namespace, Resource, fields

from app.api_v2.model import LogSource

from ..utils import token_required, user_has
from .shared import ISO8601, NullableString, mod_user_list

api = Namespace('Log Sources', description='Log Sources', path='log_source')

log_source_model = api.model('LogSource', {
    'name': fields.String(required=True, description='The name of the log source', example='Microsoft Windows Sysmon'),
    'dataset': NullableString(required=False, description='The dataset name for the log source', example='sysmon'),
    'description': NullableString(required=False, description='A description of the log source', example='Microsoft Windows Sysmon'),
    'enabled': fields.Boolean(required=False, default=True, description='Is the log source enabled', example=True),
    'log_type': fields.String(required=True, description='One of the options from the VALID_LOG_TYPES list', example='windows_eventlog'),
    'log_path': fields.String(required=True, description='Interchangeable path for file or channel for windows_eventlog', example='Microsoft-Windows-Sysmon/Operational'),
    'reverse': fields.Boolean(required=False, default=False, description='Should the log source be read in reverse', example=False),
    'max_age': fields.Integer(required=False, default=30, description='Maximum age of the log file in days', example=30),
    'lookback': fields.Integer(required=False, default=7, description='How many days to look back for log events', example=7),
    'include_patterns': fields.List(fields.String, required=False, default=[], description='List of regex patterns to filter in log events', example=['.*']),
    'exclude_patterns': fields.List(fields.String, required=False, default=[], description='List of regex patterns to filter out log events', example=['.*']),
    'included_event_ids': fields.List(fields.Integer, required=False, default=[], description='List of event IDs to include in windows_eventlog', example=[1, 2, 3]),
    'excluded_event_ids': fields.List(fields.Integer, required=False, default=[], description='List of event IDs to exclude in windows_eventlog', example=[25]),
    'include_host_meta': fields.Boolean(required=False, default=True, description='Include host meta data in log events', example=True),
    'include_original_event': fields.Boolean(required=False, default=True, description='Include the original log event in the log event', example=True),
    'ignore_bookmark': fields.Boolean(required=False, default=False, description='Ignore the bookmark for the log source', example=False),
    'resolve_sids': fields.Boolean(required=False, default=False, description='Resolve SIDs to usernames', example=False),
    'outputs': fields.List(fields.String, required=False, default=[], description='Contains the UUID of the LogOutput objects to send the log events to', example=['uuid1', 'uuid2']),
    'tags': fields.List(fields.String, required=False, default=[], description='Tags to apply to the log events', example=['tag1', 'tag2']),
    'is_global': fields.Boolean(required=False, default=False, description='Is this a global log source that can be used by any organization', example=False),
})

log_source_create_model = api.inherit('LogSourceCreate', log_source_model, {
    'organization': fields.String(required=False, description='The organization that owns the log source'),
    'log_collection_policy': fields.List(fields.String, required=False, default=[], description='The log collection policy to add the log source to')
})


log_source_model_extended = api.inherit('LogSourceExtended', log_source_model, {
    'uuid': fields.String(description='The UUID of the log source'),
    'organization': fields.String(description='The organization that owns the log source'),
    'created_at': ISO8601(description='When the log source was created'),
    'created_by': fields.Nested(mod_user_list),
    'updated_at': ISO8601(description='When the log source was updated'),
    'updated_by': fields.Nested(mod_user_list)
})

log_source_collection_model = api.model('LogSourceCollection', {
    'sources': fields.List(fields.Nested(log_source_model_extended)),
    'total': fields.Integer(description='The total number of log sources')
})

@api.route("")
class LogSourceList(Resource):

    @api.doc(security="Bearer")
    @api.marshal_with(log_source_collection_model)
    @token_required
    @user_has('view_log_sources')
    def get(self, current_user):
        ''' Returns a list of log sources '''

        search = LogSource.search()

        return {
            'sources': list(search),
            'total': search.count()
        }
    
    @api.doc(security="Bearer")
    @api.expect(log_source_create_model)
    @api.marshal_with(log_source_model_extended)
    @token_required
    @user_has('create_log_source')
    def post(self, current_user):
        ''' Adds a new log source '''

        log_source = LogSource(**api.payload)

        # TODO: Add guard to prevent non-global admins from creating items in other orgs

        # TODO: If the 'log_collection_policy' field is set, add the log source to the policy
        # and remove it from the creation payload

        log_source.save()

        return log_source
    

@api.route("/<string:uuid>")
class LogSourceDetail(Resource):

    @api.doc(security="Bearer")
    @api.marshal_with(log_source_model_extended)
    @token_required
    @user_has('view_log_sources')
    def get(self, current_user, uuid):
        ''' Returns a specific log source '''

        log_source = LogSource.get_by_uuid(uuid)

        # TODO: Add guard to prevent non-global admins from creating items in other orgs

        if log_source:
            return log_source
        else:
            api.abort(404, f"Log source {uuid} does not exist")

    @api.doc(security="Bearer")
    @api.expect(log_source_create_model)
    @api.marshal_with(log_source_model_extended)
    @token_required
    @user_has('update_log_source')
    def put(self, current_user, uuid):
        ''' Updates a log source '''

        log_source = LogSource.get_by_uuid(uuid)

        # TODO: Add guard to prevent non-global admins from creating items in other orgs

        # TODO: If the 'log_collection_policy' field is set, add the log source to the policy
        # and remove it from the update payload

        # TODO: Check for name already in use

        if log_source:
            log_source.update(**api.payload)
            return log_source
        else:
            api.abort(404, f"Log source {uuid} does not exist")

    @api.doc(security="Bearer")
    @token_required
    @user_has('delete_log_source')
    def delete(self, current_user, uuid):
        ''' Deletes a log source '''

        log_source = LogSource.get_by_uuid(uuid)

        # TODO: Add guard to prevent non-global admins from creating items in other orgs

        if log_source:
            log_source.delete()
            return {'message': f"Log source {uuid} deleted"}
        else:
            api.abort(404, f"Log source {uuid} does not exist")
