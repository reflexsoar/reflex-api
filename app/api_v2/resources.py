import re
import base64
import datetime
import os
import json
import hashlib

from app.api_v2.model.user import Organization
from zipfile import ZipFile
#import pyminizip
from flask import request, current_app, abort, make_response, send_from_directory, send_file, Blueprint, render_template
from flask_restx import Api, Resource, Namespace, fields, Model, inputs as xinputs, marshal
from werkzeug.datastructures import FileStorage
from werkzeug.utils import secure_filename
from .schemas import *
from .model import (
    Event,
    EventRule,
    Observable,
    Observable,
    User,
    Role,
    Settings,
    Credential,
    Input,
    Agent,
    ThreatList,
    ExpiredToken,
    DataType,
    CaseComment,
    CaseHistory,
    CaseTemplate,
    Case,
    CaseStatus,
    CloseReason,
    CaseTask,
    Tag,
    AgentGroup,
    PluginConfig,
    Plugin,
    EventLog,
    A,
    Search,
    EventStatus,
    TaskNote,
    ObservableHistory,
    Q
)

from .utils import (
    default_org,
    ip_approved,
    check_org,
    page_results,
    token_required,
    user_has,
    generate_token,
    log_event,
    check_password_reset_token,
    escape_special_characters_rql
)

from .resource.utils import redistribute_detections

from .resource import (
    ns_playbook_v2,
    ns_audit_log_v2,
    ns_list_v2,
    ns_organization_v2,
    ns_event_v2,
    ns_auth_v2,
    ns_event_rule_v2,
    ns_role_v2,
    ns_task_v2,
    ns_detection_v2,
    ns_mitre_v2,
    ns_event_view_v2,
    ns_notification_v2,
    ns_agent_v2,
    ns_agent_group_v2,
    ns_field_mapping_v2,
    ns_agent_policy_v2,
    ns_case_v2,
    ns_user_v2,
    ns_input_v2,
    ns_service_account_v2,
    ns_observable_v2,
    ns_asset_v2,
    ns_reporting_v2,
    ns_detection_repository_v2,
    ns_integration_v2,
    ns_sso_v2,
    ns_package_v2,
    ns_data_source_v2,
    ns_schedule_v2,
    ns_release_notes_v2
)

show_swagger_docs = (os.getenv('REFLEX_SHOW_SWAGGER_DOCS', 'False').lower() == 'true')

# Instantiate a new API object
api_v2 = Blueprint("api2", __name__, url_prefix="/api/v2.0")
api2 = Api(api_v2) if show_swagger_docs else Api(api_v2, doc=False)

# All the API namespaces
ns_settings_v2 = api2.namespace(
    'Settings', description='Settings operations', path='/settings')
ns_credential_v2 = api2.namespace(
    'Credential', description='Credential operations', path='/credential')
ns_data_type_v2 = api2.namespace(
    'DataType', description='DataType operations', path='/data_type')
ns_case_status_v2 = api2.namespace(
    'CaseStatus', description='Case Status operations', path='/case_status')
ns_case_comment_v2 = api2.namespace(
    'CaseComment', description='Case Comments', path='/case_comment')
ns_case_task_v2 = api2.namespace(
    'CaseTask', description='Case Tasks', path='/case_task')
ns_case_history_v2 = api2.namespace(
    'CaseHistory', description='Case history operations', path='/case_history')
ns_case_template_v2 = api2.namespace(
    'CaseTemplate', description='Case Template operations', path='/case_template')
ns_close_reason_v2 = api2.namespace(
    'CloseReason', description='Closure reason are used when closing a case and can be customized', path='/close_reason')
ns_tag_v2 = api2.namespace('Tag', description='Tag operations', path='/tag')
ns_dashboard_v2 = api2.namespace('Dashboard', description='API endpoints that drive dashboard display', path='/dashboard')
ns_plugins_v2 = api2.namespace('Plugin', description='Plugin operations', path='/plugin')
#ns_observable_v2 = api2.namespace('Observable', description="Observable operations", path='/observable')
ns_hunting_v2 = api2.namespace('Hunting', description="Threat hunting operaitons", path="/hunting")
api2.add_namespace(ns_playbook_v2)
api2.add_namespace(ns_audit_log_v2)
api2.add_namespace(ns_list_v2)
api2.add_namespace(ns_organization_v2)
api2.add_namespace(ns_event_v2)
api2.add_namespace(ns_auth_v2)
api2.add_namespace(ns_event_rule_v2)
api2.add_namespace(ns_role_v2)
api2.add_namespace(ns_task_v2)
api2.add_namespace(ns_detection_v2)
api2.add_namespace(ns_mitre_v2)
api2.add_namespace(ns_event_view_v2)
api2.add_namespace(ns_notification_v2)
api2.add_namespace(ns_agent_v2)
api2.add_namespace(ns_agent_group_v2)
api2.add_namespace(ns_field_mapping_v2)
api2.add_namespace(ns_agent_policy_v2)
api2.add_namespace(ns_case_v2)
api2.add_namespace(ns_user_v2)
api2.add_namespace(ns_input_v2)
api2.add_namespace(ns_service_account_v2)
api2.add_namespace(ns_observable_v2)
api2.add_namespace(ns_asset_v2)
api2.add_namespace(ns_reporting_v2)
api2.add_namespace(ns_detection_repository_v2)
api2.add_namespace(ns_integration_v2)
api2.add_namespace(ns_sso_v2)
api2.add_namespace(ns_package_v2)
api2.add_namespace(ns_data_source_v2)
api2.add_namespace(ns_schedule_v2)
api2.add_namespace(ns_release_notes_v2)

# Register the integration base 
from app.integrations.base import IntegrationApi as ns_integration_base_v2
api2.add_namespace(ns_integration_base_v2)

# Register all the schemas from flask-restx
for model in schema_models:
    api2.models[model.name] = model

# Generic parsers
pager_parser = api2.parser()
pager_parser.add_argument('page_size', location='args',
                          required=False, type=int, default=25)
pager_parser.add_argument('page', location='args',
                          required=False, type=int, default=1)

upload_parser = api2.parser()
upload_parser.add_argument('files', location='files',
                           type=FileStorage, required=True, action="append")

def save_tags(tags):
    '''
    Adds tags to a reference index that the UI uses for 
    suggesting reasonable tags to the user
    '''

    for tag in tags:
        _tag = Tag.get_by_name(name=tag)
        if not _tag:
            tag = Tag(name=tag)
            tag.save()



data_type_parser = api2.parser()
data_type_parser.add_argument('organization', location='args', required=False)

@ns_data_type_v2.route("")
class DataTypeList(Resource):

    @api2.doc(security="Bearer")
    @api2.marshal_with(mod_data_type_list)
    @token_required
    @check_org
    def get(self, current_user):
        ''' Gets a list of all the data types '''

        args = data_type_parser.parse_args()

        data_types = DataType.search()

        if args.organization and hasattr(current_user,'default_org') and current_user.default_org:
            data_types = data_types.filter('term', organization=args.organization)

        data_types = data_types[0:data_types.count()]
        data_types = data_types.execute()
        if data_types:
            return [d for d in data_types]
        else:
            return []

    @api2.doc(security="Bearer")
    @api2.expect(mod_data_type_create)
    @api2.response('200', 'Successfully created data type.')
    @token_required
    @user_has('create_data_type')
    def post(self, current_user):
        ''' Creates a new data_type set '''
        data_type = DataType(**api2.payload)
        data_type.save()
        return {'message': 'Successfully created data type.', 'uuid': str(data_type.uuid)}


@ns_data_type_v2.route("/<uuid>")
class DataTypeDetails(Resource):

    @api2.doc(security="Bearer")
    @api2.marshal_with(mod_data_type_list)
    @token_required
    def get(self, uuid, current_user):
        ''' Gets a data type '''
        data_type = DataType.get_by_uuid(uuid=uuid)
        if data_type:
            return data_type
        else:
            ns_data_type_v2.abort(404, 'Data type not found.')

    @api2.doc(security="Bearer")
    @api2.expect(mod_data_type_create)
    @api2.marshal_with(mod_data_type_list)
    @token_required
    @user_has('update_data_type')
    def put(self, uuid, current_user):
        ''' Updates the data type '''
        data_type = DataType.get_by_uuid(uuid=uuid)
        if data_type:
            data_type.update(**api2.payload)
            return data_type
        else:
            ns_data_type_v2.abort(404, 'Data type not found.')




case_status_parser = api2.parser()
case_status_parser.add_argument(
    'name', type=str, location='args', required=False)
case_status_parser.add_argument(
    'organization', type=str, location='args', required=False)

@ns_case_status_v2.route("")
class CaseStatusList(Resource):

    @api2.doc(security="Bearer")
    @api2.expect(case_status_parser)
    @api2.marshal_with(mod_case_status_list, as_list=True)
    @token_required
    @check_org
    def get(self, current_user):
        ''' Returns a list of case_statuss '''

        args = case_status_parser.parse_args()
        
        statuses = CaseStatus.search()

        if args.name is not None:
            statuses = statuses.filter('term', name=args.name)

        if hasattr(current_user,'default_org') and args.organization is not None:
            statuses = statuses.filter('term', organization=args.organization)

        statuses = statuses.execute()
        if statuses:
            return [s for s in statuses]
        else:
            return []

    @api2.doc(security="Bearer")
    @api2.expect(mod_case_status_create)
    @api2.response('409', 'Case Status already exists.')
    @api2.response('200', 'Successfully create the CaseStatus.')
    @token_required
    @user_has('create_case_status')
    def post(self, current_user):
        ''' Creates a new Case Status '''
        case_status = CaseStatus.get_by_name(name=api2.payload['name'])

        if not case_status:
            case_status = CaseStatus(**api2.payload)
            case_status.save()
        else:
            ns_case_status_v2.abort(409, 'Case Status already exists.')
        return {'message': 'Successfully created the Case Status.'}


@ns_case_status_v2.route("/<uuid>")
class CaseStatusDetails(Resource):

    @api2.doc(security="Bearer")
    @api2.marshal_with(mod_case_status_list)
    @token_required
    def get(self, uuid, current_user):
        ''' Returns information about an CaseStatus '''
        case_status = CaseStatus.get_by_uuid(uuid=uuid)
        if case_status:
            return case_status
        else:
            ns_case_status_v2.abort(404, 'Case Status not found.')

    @api2.doc(security="Bearer")
    @api2.expect(mod_case_status_create)
    @api2.marshal_with(mod_case_status_list)
    @token_required
    @user_has('update_case_status')
    def put(self, uuid, current_user):
        ''' Updates information for an Case Status '''
        case_status = CaseStatus.get_by_uuid(uuid=uuid)
        if case_status:
            exists = CaseStatus.get_by_name(name=api2.payload['name'])
            if 'name' in api2.payload and exists and exists.uuid != case_status.uuid:
                ns_case_status_v2.abort(
                    409, 'Case Status name already exists.')
            else:
                case_status.update(**api2.payload)
                return case_status
        else:
            ns_case_status_v2.abort(404, 'Case Status not found.')

    @api2.doc(security="Bearer")
    @token_required
    @user_has('delete_case_status')
    def delete(self, uuid, current_user):
        ''' Deletes an CaseStatus '''
        case_status = CaseStatus.get_by_uuid(uuid=uuid)
        if case_status:
            case_status.delete()
            return {'message': 'Sucessfully deleted Case Status.'}

close_reason_parser = api2.parser()
close_reason_parser.add_argument(
    'title', type=str, location='args', required=False)
close_reason_parser.add_argument(
    'organization', type=str, location='args', required=False
)

@ns_close_reason_v2.route("")
class CloseReasonList(Resource):

    @api2.doc(security="Bearer")
    @api2.expect(close_reason_parser)
    @api2.marshal_with(mod_close_reason_list, as_list=True)
    @token_required
    def get(self, current_user):
        ''' Returns a list of close_reasons '''

        args = close_reason_parser.parse_args()

        close_reasons = CloseReason.search()
        close_reasons = close_reasons.exclude('term', enabled=False)

        if args.organization and current_user.is_default_org:
            close_reasons = close_reasons.filter('term', organization=args.organization)
        else:
            close_reasons = close_reasons.filter('term', organization=current_user.organization)
        
        if args.title:
            close_reasons = close_reasons.filter('match', title=args.title)
        
        close_reasons = close_reasons.execute()
        if close_reasons:
            return list(close_reasons)
        else:
            return []

    @api2.doc(security="Bearer")
    @api2.expect(mod_close_reason_create)
    @api2.response('409', 'Close Reason already exists.')
    @api2.response('200', 'Successfully create the CloseReason.')
    @token_required
    @user_has('create_close_reason')
    def post(self, current_user):
        ''' Creates a new Close Reason '''
        close_reason = CloseReason.get_by_name(title=api2.payload['title'])

        if not close_reason:
            close_reason = CloseReason(**api2.payload)
            close_reason.save()
        else:
            ns_close_reason_v2.abort(
                409, 'Close Reason with that name already exists.')
        return {'message': 'Successfully created the Close Reason.'}


@ns_close_reason_v2.route("/<uuid>")
class CloseReasonDetails(Resource):

    @api2.doc(security="Bearer")
    @api2.marshal_with(mod_close_reason_list)
    @token_required
    def get(self, uuid, current_user):
        ''' Returns information about an CloseReason '''
        close_reason = CloseReason.get_by_uuid(uuid=uuid)
        if close_reason:
            return close_reason
        else:
            ns_close_reason_v2.abort(404, 'Close Reason not found.')


    @api2.doc(security="Bearer")
    @api2.expect(mod_close_reason_create)
    @api2.marshal_with(mod_close_reason_list)
    @token_required
    @user_has('update_close_reason')
    def put(self, uuid, current_user):
        ''' Updates information for an Close Reason '''
        close_reason = CloseReason.get_by_uuid(uuid=uuid)
        if close_reason:
            exists = CloseReason.get_by_name(title=api2.payload['title'])
            if 'title' in api2.payload and exists and exists.uuid != close_reason.uuid:
                ns_close_reason_v2.abort(
                    409, 'Close Reason title already exists.')
            else:
                close_reason.update(**api2.payload)
                return close_reason
        else:
            ns_close_reason_v2.abort(404, 'Close Reason not found.')


    @api2.doc(security="Bearer")
    @token_required
    @user_has('delete_close_reason')
    def delete(self, uuid, current_user):
        ''' Soft deletes a CloseReason '''
        close_reason = CloseReason.get_by_uuid(uuid=uuid)
        if close_reason:
            close_reason.update(enabled = False)
            return {'message': 'Sucessfully deleted Close Reason.'}

case_history_parser = api2.parser()
case_history_parser.add_argument(
    'case_uuid', type=str, location='args', required=True)


@ns_case_history_v2.route("")
class CaseHistoryList(Resource):

    @api2.doc(security="Bearer")
    @api2.expect(case_history_parser)
    @api2.marshal_with(mod_case_history, as_list=True)
    @token_required
    @user_has('view_cases')
    def get(self, current_user):
        ''' Returns a list of case history events '''

        args = case_history_parser.parse_args()

        history = CaseHistory.get_by_case(uuid=args['case_uuid'], sort_by="-created_at")

        if history:
            return [h for h in history]
        else:
            return []


case_comment_parser = api2.parser()
case_comment_parser.add_argument(
    'case_uuid', type=str, location='args', required=True)


@ns_case_comment_v2.route("")
class CaseCommentList(Resource):

    @api2.doc(security="Bearer")
    @api2.expect(case_comment_parser)
    @api2.marshal_with(mod_comment, as_list=True)
    @token_required
    @user_has('view_case_comments')
    def get(self, current_user):
        ''' Returns a list of comments '''

        args = case_comment_parser.parse_args()

        if 'case_uuid' in args:
            comments = CaseComment.get_by_case(uuid=args['case_uuid'])

            for comment in comments:
                if comment.cross_organization:
                    organization = Organization.get_by_uuid(comment.other_organization)
                    comment.__dict__['other_organization_name'] = organization.name

            if comments:
                return list(comments)
            else:
                return []
        else:
            ns_case_comment_v2.abort(400, 'A case UUID is required.')

    @api2.doc(security="Bearer")
    @api2.expect(mod_comment_create, validate=True)
    @api2.response(200, 'AMAZING', mod_comment)
    @api2.marshal_with(mod_comment)
    @token_required
    @user_has('create_case_comment')
    def post(self, current_user):
        _tags = []
        ''' Creates a new comment '''
        if 'closure_reason_uuid' in api2.payload:
            api2.payload['closure_reason'] = CloseReason.get_by_uuid(
                api2.payload.pop('closure_reason_uuid'))

        case = Case.get_by_uuid(uuid=api2.payload['case_uuid'])
        if case:

            # Append the organization of the case to the comment
            api2.payload['organization'] = case.organization

            # Appends the commenters organization if commenting across organizations
            # useful when the default tenant comments on a sub-tenants cases
            if current_user.organization != case.organization:
                api2.payload['cross_organization'] = True
                api2.payload['other_organization'] = current_user.organization

            # Determine if the comment has any user mentions in it and 
            # notify any users that are mentioned if they have notifications enabled
            matches = re.findall(r'\B@(\w+)', api2.payload['message'])
            matches = list(set([m.lower() for m in matches]))
            mentioned_users = User.get_by_username(matches, as_text=True)
            # TODO - NOTIFICATIONS: Add notification for mentioned users if they have notifications enabled

            case_comment = CaseComment(**api2.payload)
            case_comment.save()
            case.add_history(message="Comment added to case")
        else:
            ns_case_comment_v2.abort(404, 'Case not found.')        
        return case_comment


@ns_case_comment_v2.route("/<uuid>")
class CaseCommentDetails(Resource):

    @api2.doc(security="Bearer")
    @api2.marshal_with(mod_comment)
    @api2.response('200', 'Success')
    @api2.response('404', 'Comment not found')
    @token_required
    @user_has('view_case_comments')
    def get(self, uuid, current_user):
        ''' Returns information about a comment '''
        case_comment = CaseComment.get_by_uuid(uuid=uuid)
        if case_comment:
            return case_comment
        else:
            ns_case_comment_v2.abort(404, 'Comment not found.')

    @api2.doc(security="Bearer")
    @api2.expect(mod_comment_create)
    @api2.marshal_with(mod_comment)
    @token_required
    @user_has('update_case_comment')
    def put(self, uuid, current_user):
        ''' Updates information for a comment '''
        case_comment = CaseComment.get_by_uuid(uuid=uuid)
        if case_comment:
            case_comment.edited = True
            case_comment.update(**api2.payload)
            return case_comment
        else:
            ns_case_comment_v2.abort(404, 'Comment not found.')

    @api2.doc(security="Bearer")
    @token_required
    @user_has('delete_case_comment')
    def delete(self, uuid, current_user):
        ''' Deletes a comment '''
        case_comment = CaseComment.get_by_uuid(uuid=uuid)
        if case_comment:
            case = Case.get_by_uuid(case_comment.case_uuid)
            case_comment.delete()
            case.add_history("Comment deleted")            
            return {'message': 'Sucessfully deleted comment.'}


case_template_parser = api2.parser()
case_template_parser.add_argument('title', location='args', required=False)
case_template_parser.add_argument('organization', location='args', required=False)


@ns_case_template_v2.route("")
class CaseTemplateList(Resource):

    @api2.doc(security="Bearer")
    @api2.marshal_with(mod_case_template_full, as_list=True)
    @api2.expect(case_template_parser)
    @token_required
    @user_has('view_case_templates')
    @check_org
    def get(self, current_user):
        ''' Returns a list of case_template '''

        args = case_template_parser.parse_args()

        case_templates = CaseTemplate.search()

        if args['title']:
            case_templates = case_templates.filter('wildcard', title=f"*{args.title}*")

        if args['organization']:
            case_templates = case_templates.filter('term', organization=args.organization)
        
        case_templates = list(case_templates.scan())
        if case_templates:
            return case_templates
        else:
            return []

    @api2.doc(security="Bearer")
    @api2.expect(mod_case_template_create)
    @api2.response('409', 'Case Template already exists.')
    @api2.response('200', "Successfully created the case_template.")
    @api2.marshal_with(mod_case_template_full)
    @token_required
    @user_has('create_case_template')
    def post(self, current_user):

        # Check to see if the case template already exists and
        # return an error indicating as such
        case_template = CaseTemplate.get_by_title(title=api2.payload['title'])
        if case_template:
            if 'organization' in api2.payload:
                if case_template.organization == api2.payload['organization']:
                    ns_case_template_v2.abort(409, 'Case Template with that name already exists.')

            elif case_template.organization == current_user.organization:
                ns_case_template_v2.abort(409, 'Case Template with that name already exists.')

        else:
            ''' Creates a new case_template template '''

            case_template = CaseTemplate(**api2.payload)
            case_template.save()

            # Set the default status to New
            # case_template_status = CaseStatus.query.filter_by(
            #   name="New").first()
            #case_template.status = case_template_status
            # case_template.save()

            return case_template


@ns_case_template_v2.route("/<uuid>")
class CaseTemplateDetails(Resource):

    @api2.doc(security="Bearer")
    @api2.marshal_with(mod_case_template_full)
    @api2.response('200', 'Success')
    @api2.response('404', 'Case Template not found')
    @token_required
    @user_has('view_case_templates')
    def get(self, uuid, current_user):
        ''' Returns information about a case_template '''
        case_template = CaseTemplate.get_by_uuid(uuid=uuid)
        if case_template:
            return case_template
        else:
            ns_case_template_v2.abort(404, 'Case Template not found.')

    @api2.doc(security="Bearer")
    @api2.expect(mod_case_template_create)
    @api2.marshal_with(mod_case_template_full)
    @token_required
    @user_has('update_case_template')
    @check_org
    def put(self, uuid, current_user):
        ''' Updates information for a case_template '''
        case_template = CaseTemplate.get_by_uuid(uuid=uuid)
        if case_template:
            if 'title' in api2.payload:
                exists = CaseTemplate.get_by_title(title=api2.payload['title'])
                if exists and exists.uuid != case_template.uuid:
                    ns_case_template_v2.abort(
                        409, 'A Case Template with that title already exists.')

            case_template.update(**api2.payload)
            return case_template
        else:
            ns_case_template_v2.abort(404, 'Case Template not found.')

    @api2.doc(security="Bearer")
    @token_required
    @user_has('delete_case_template')
    def delete(self, uuid, current_user):
        ''' Deletes a case_template '''
        case_template = CaseTemplate.get_by_uuid(uuid=uuid)
        if case_template:
            case_template.delete()
            return {'message': 'Sucessfully deleted case_template.'}


case_task_parser = api2.parser()
case_task_parser.add_argument(
    'case_uuid', type=str, location='args', required=False)


@ns_case_task_v2.route("")
class CaseTaskList(Resource):

    @api2.doc(security="Bearer")
    @api2.expect(case_task_parser)
    @api2.marshal_with(mod_case_task_full, as_list=True)
    @token_required
    @user_has('view_case_tasks')
    def get(self, current_user):
        ''' Returns a list of case_task '''
        args = case_task_parser.parse_args()

        if 'case_uuid' in args:
            tasks = CaseTask.get_by_case(uuid=args['case_uuid'], all_results=True)
            if tasks:
                
                #return [t for t in sorted(tasks, key = lambda t: t.order) if t is not None]
                return tasks
            else:
                return []
        else:
            ns_case_task_v2.abort(400, 'A case UUID is required.')

    @api2.doc(security="Bearer")
    @api2.expect(mod_case_task_create)
    @api2.marshal_with(mod_case_task_full)
    @api2.response('409', 'Case Task already exists.')
    @api2.response('200', "Successfully created the case task.")
    @token_required
    @user_has('create_case_task')
    def post(self, current_user):
        ''' Creates a new case_task '''

        task = CaseTask.get_by_title(
            title=api2.payload['title'], case_uuid=api2.payload['case_uuid'])

        if not task:
            case_uuid = api2.payload.pop('case_uuid')

            case = Case.get_by_uuid(uuid=case_uuid)
            task = case.add_task(**api2.payload)

            if 'owner_uuid' in api2.payload:
                owner = api2.payload.pop('owner_uuid')            
                task.set_owner(owner)

            task.save()

            return task

        else:
            ns_case_task_v2.abort(409, 'Case Task already exists')

@ns_case_task_v2.route("/<uuid>/add_note")
class CaseTaskNote(Resource):

    @api2.doc(security="Bearer")
    @api2.expect(mod_case_task_note_create)
    @api2.marshal_with(mod_case_task_note_details)
    @api2.response('200', 'Success')
    @token_required
    @user_has('update_case_task')
    def post(self, uuid, current_user):
        ''' Creates a new note on a specified task'''

        task = CaseTask.get_by_uuid(uuid)
        
        if task:
            note = task.add_note(note=api2.payload['note'])
            return note
        return {}


@ns_case_task_v2.route("/<uuid>")
class CaseTaskDetails(Resource):

    @api2.doc(security="Bearer")
    @api2.marshal_with(mod_case_task_full)
    @api2.response('200', 'Success')
    @api2.response('404', 'Case Task not found')
    @token_required
    @user_has('view_case_tasks')
    def get(self, uuid, current_user):
        ''' Returns information about a case task '''
        task = CaseTask.get_by_title(
            title=api2.payload['title'], case_uuid=api2.payload['case_uuid'])
        if task:
            return task
        else:
            ns_case_task_v2.abort(404, 'Case Task not found.')

    @api2.doc(security="Bearer")
    @api2.expect(mod_case_task_create)
    @api2.marshal_with(mod_case_task_full)
    @token_required
    @user_has('update_case_task')
    def put(self, uuid, current_user):
        ''' Updates information for a case_task '''

        
        task = CaseTask.get_by_uuid(uuid=uuid)

        settings = Settings.load(organization=task.organization)

        if task:
            if 'name' in api2.payload and CaseTask.get_by_title(title=api2.payload['title'], case_uuid=api2.payload['case_uuid']):
                ns_case_task_v2.abort(409, 'Case Task name already exists.')
            else:
                if 'status' in api2.payload:

                    # Start a task
                    if api2.payload['status'] == 1:

                        # If set, automatically assign the task to the user starting the task
                        if task.owner == [] and settings and settings.assign_task_on_start:
                            task.start_task(current_user.uuid)
                        else:
                            task.start_task()

                    # Close a task
                    if api2.payload['status'] == 2:
                        task.close_task()

                    # Reopen the task if the previous status was closed
                    if task.status == 2 and api2.payload['status'] == 1:
                        task.reopen_task()
            return task
        else:
            ns_case_task_v2.abort(404, 'Case Task not found.')

    @api2.doc(security="Bearer")
    @token_required
    @user_has('delete_case_task')
    def delete(self, uuid, current_user):
        ''' Deletes a case_task '''

        task = CaseTask.get_by_uuid(uuid=uuid)
        if task:
            task.delete()

            return {'message': 'Sucessfully deleted case task.'}


@ns_tag_v2.route("")
class TagList(Resource):

    @api2.doc(security="Bearer")
    @api2.marshal_with(mod_tag_list, as_list=True)
    @token_required
    def get(self, current_user):
        ''' Gets a list of tags '''
        tags = Tag.search().execute()
        if tags:
            return [t for t in tags]
        else:
            return []

    @api2.doc(security="Bearer")
    @api2.expect(mod_tag)
    @api2.response('409', 'Tag already exists.')
    @api2.response('200', "Successfully created the tag.")
    @token_required
    def post(self, current_user):
        ''' Creates a new tag '''
        tag = Tag.get_by_name(name=api2.payload['name'])
        if not tag:
            tag = Tag(**api2.payload)
            tag.create()
            return {'message': 'Successfully created the tag.'}
        else:
            ns_tag_v2.abort(409, 'Tag already exists.')






@ns_credential_v2.route('/encrypt')
class EncryptPassword(Resource):

    @api2.doc(security="Bearer")
    @api2.expect(mod_credential_create, validate=True)
    @api2.marshal_with(mod_credential_full)
    @api2.response('400', 'Successfully created credential.')
    @api2.response('409', 'Credential already exists.')
    @token_required
    @check_org
    @user_has('add_credential')
    def post(self, current_user):
        ''' Encrypts the password '''

        if 'organization' in api2.payload:
            credential = Credential.get_by_name(api2.payload['name'], organization=api2.payload['organization'])
        else:
            credential = Credential.get_by_name(api2.payload['name'])

        if not credential:
            pw = api2.payload.pop('secret')
            credential = Credential(**api2.payload)
            credential.save()
            credential.encrypt(pw.encode(
            ), current_app.config['MASTER_PASSWORD'])

            return credential
        else:
            ns_credential_v2.abort(409, 'Credential already exists.')


cred_parser = pager_parser.copy()
cred_parser.add_argument('name', location='args', required=False, type=str)
cred_parser.add_argument('organization', location='args', required=False, type=str)
cred_parser.add_argument('page', type=int, location='args', default=1, required=False)
cred_parser.add_argument('sort_by', type=str, location='args', default='-created_at', required=False)
cred_parser.add_argument('page_size', type=int, location='args', default=10, required=False)
cred_parser.add_argument(
    'sort_by', type=str, location='args', default='created_at', required=False
)
cred_parser.add_argument(
    'sort_direction', type=str, location='args', default='desc', required=False
)

@ns_credential_v2.route("")
class CredentialList(Resource):

    @api2.doc(security="Bearer")
    @api2.marshal_with(mod_credential_list_paged)
    @api2.expect(cred_parser)
    @token_required
    @user_has('view_credentials')
    def get(self, current_user):

        args = cred_parser.parse_args()

        credentials = Credential.search()

        if 'name' in args and args.name not in [None, '']:
            credentials = credentials.filter('match', name=args.name)

        if 'organization' in args and args.organization not in [None, '']:
            credentials = credentials.filter('term', organization=args.organization)

        credentials = credentials.sort(args.sort_by)

        sort_by = args.sort_by
        if args.sort_direction == 'desc':
            sort_by = f"-{sort_by}"

        credentials = credentials.sort(sort_by)

        credentials, total_results, pages = page_results(credentials, args.page, args.page_size)        

        credentials = credentials.execute()

        response = {
            'credentials': list(credentials),
            'pagination': {
                'total_results': total_results,
                'pages': pages,
                'page': args['page'],
                'page_size': args['page_size']
            }
        }

        return response


@ns_credential_v2.route('/decrypt/<uuid>')
class DecryptPassword(Resource):

    @api2.doc(security="Bearer")
    @api2.marshal_with(mod_credential_return)
    @api2.response('404', 'Credential not found.')
    @token_required
    @user_has('decrypt_credential')
    def get(self, uuid, current_user):
        ''' Decrypts the credential for use '''
        credential = Credential.get_by_uuid(uuid=uuid)
        if credential:
            value = credential.decrypt(current_app.config['MASTER_PASSWORD'])
            if value:
                return {'secret': value}
            else:
                ns_credential_v2.abort(401, 'Invalid master password.')
        else:
            ns_credential_v2.abort(404, 'Credential not found.')


@ns_credential_v2.route('/<uuid>')
class CredentialDetails(Resource):

    @api2.doc(security="Bearer")
    @api2.marshal_with(mod_credential_full)
    @api2.response('404', 'Credential not found.')
    @token_required
    @user_has('view_credentials')
    def get(self, uuid, current_user):
        ''' Gets the full details of a credential '''
        credential = Credential.get_by_uuid(uuid)
        if credential:
            return credential
        else:
            ns_credential_v2.abort(404, 'Credential not found.')

    @api2.doc(security="Bearer")
    @api2.expect(mod_credential_update, validate=True)
    @api2.marshal_with(mod_credential_full)
    @api2.response('404', 'Credential not found.')
    @api2.response('409', 'Credential name already exists.')
    @token_required
    @user_has('update_credential')
    def put(self, uuid, current_user):
        ''' Updates a credential '''
        credential = Credential.get_by_uuid(uuid=uuid)
        if credential:

            # Strip the organization field if the user is not a member of the default
            # organization
            # TODO: replace with @check_org wrapper
            if 'organization' in api2.payload and hasattr(current_user,'default_org') and not current_user.default_org:
                api2.payload.pop('organization')
                
            if 'name' in api2.payload:
                cred = Credential.get_by_name(api2.payload['name'])
                if cred:
                    if cred.uuid != uuid:
                        ns_credential_v2.abort(
                            409, 'Credential name already exists.')

            if 'secret' in api2.payload:
                credential.encrypt(api2.payload.pop('secret').encode(
                ), current_app.config['MASTER_PASSWORD'])

            if len(api2.payload) > 0:
                credential.update(**api2.payload)
            return credential
        else:
            ns_credential_v2.abort(404, 'Credential not found.')

    @api2.doc(security="Bearer")
    @api2.response('404', 'Credential not found.')
    @api2.response('200', "Credential sucessfully deleted.")
    @token_required
    @user_has('delete_credential')
    def delete(self, uuid, current_user):
        ''' Deletes a credential '''
        credential = Credential.get_by_uuid(uuid=uuid)
        if credential:

            # Prevent deletion from other organizations unless its from the default org
            if current_user.default_org or current_user.organization == credential.organization:
                credential.delete()
                return {'message': 'Credential successfully deleted.'}
            else:
                ns_credential_v2.abort(401, 'Unauthorized.')
        else:
            ns_credential_v2.abort(404, 'Credential not found.')


@ns_plugins_v2.route("")
class PluginList(Resource):

    @api2.doc(security="Bearer")
    @api2.marshal_with(mod_plugin_list)
    @token_required
    @user_has('view_plugins')
    def get(self, current_user):
        ''' Retrieves a list of plugins'''

        plugins = Plugin.search()
        plugins = plugins[0:plugins.count()]
        plugins = plugins.execute()

        return list(plugins)


@ns_plugins_v2.route("/<uuid>")
class PluginDetails(Resource):

    @api2.doc(security="Bearer")
    @api2.marshal_with(mod_plugin_list)
    @token_required
    @user_has('view_plugins')
    def get(self, uuid, current_user):
        ''' Retrieves the details of a specific plugin'''

        plugin = Plugin.get_by_uuid(uuid)
        if plugin:
            return plugin
        else:
            ns_plugins_v2.abort(404, 'Plugin not found.')


@ns_plugins_v2.route("/download/<path:path>")
class DownloadPlugin(Resource):

    # TODO: MAKE THIS ONLY ACCESSIBLE FROM AGENT TOKENS
    @api2.doc(security="Bearer")
    @token_required
    def get(self, path, current_user):
        plugin_dir = os.path.join(os.path.dirname(os.path.realpath(__file__)), current_app.config['PLUGIN_DIRECTORY'])
        return send_from_directory(plugin_dir, path, as_attachment=True)


@ns_plugins_v2.route("/upload")
class PluginUpload(Resource):

    @api2.doc(security="Bearer")
    @api2.expect(upload_parser)
    @api2.marshal_with(mod_plugin_list, as_list=True)
    @token_required
    @user_has('create_plugin')
    def post(self, current_user):
        ''' Adds a new plugin to the system'''

        plugins = []

        args = upload_parser.parse_args()

        def allowed_file(filename):
            return '.' in filename and filename.rsplit('.', 1)[1].lower() in current_app.config['PLUGIN_EXTENSIONS']

        if 'files' not in request.files:
            ns_plugins_v2.abort(400, 'No file selected.')

        uploaded_files = args['files']
        for uploaded_file in uploaded_files:

            if uploaded_file.filename == '':
                ns_plugins_v2.abort(400, 'No file selected.')

            if uploaded_file and allowed_file(uploaded_file.filename):

                # Make sure the file is one that can be uploaded
                # TODO: Add mime-type checking
                filename = secure_filename(uploaded_file.filename)
                
                # Check to see if the organizations plugin directory exists
                plugin_dir = os.path.join(os.path.dirname(os.path.realpath(__file__)), current_app.config['PLUGIN_DIRECTORY'])
                if not os.path.exists(plugin_dir):
                    os.makedirs(plugin_dir)

                # Save the file
                file_path = os.path.join(plugin_dir, filename)
                uploaded_file.save(file_path)
                uploaded_file.close()

                # Hash the file and update the checksum for the plugin
                hasher = hashlib.sha1()
                with open(file_path, 'rb') as f:
                    hasher.update(f.read())

                # Open the file and grab the manifest and the logo
                with ZipFile(file_path, 'r') as z:
                    # TODO: Add plugin structure checks
                    # if 'logo.png' not in z.namelist():
                    #    ns_plugin.abort(400, "Archive does not contain logo.png")
                    # if 'plugin.json' not in z.namelist():
                    #    ns_plugin.abort(400, "Archive does not contain plugin.json")

                    files = [{'name': name, 'data': z.read(
                        name)} for name in z.namelist()]
                    for f in files:
                        if 'logo.png' in f['name']:
                            logo_b64 = base64.b64encode(f['data']).decode()
                        if 'plugin.json' in f['name']:
                            manifest_data = json.loads(f['data'].decode())
                            description = manifest_data['description']
                            name = manifest_data['name']
                            if 'config_template' in manifest_data:
                                config_template = manifest_data['config_template']
                            else:
                                config_template = {}
                

                #plugin = Plugin.query.filter_by(filename=filename).first()
                plugin = Plugin.get_by_filename(filename=filename)
                if plugin:
                    plugin = plugin[0]
                    plugin.manifest = manifest_data
                    plugin.logo = logo_b64
                    plugin.description = description
                    plugin.config_template = config_template
                    plugin.name = name
                    plugin.file_hash = hasher.hexdigest()
                    plugin.save()
                else:
                    plugin = Plugin(name=name,
                                    filename=filename,
                                    description=description,
                                    manifest=manifest_data,
                                    logo=logo_b64,
                                    config_template=config_template,
                                    file_hash=hasher.hexdigest())
                    plugin.save()
                    
                plugins.append(plugin)
        return plugins

settings_parser = api2.parser()
settings_parser.add_argument('organization', location='args', required=False)

@ns_settings_v2.route("")
class GlobalSettings(Resource):

    @api2.doc(security="Bearer")
    @api2.marshal_with(mod_settings)
    @api2.expect(settings_parser)
    @token_required
    @default_org
    @user_has('view_settings')
    def get(self, user_in_default_org, current_user):
        ''' Retrieves the global settings for the system '''

        args = settings_parser.parse_args()

        print(args.organization, current_user.organization)

        if args.organization:
            if current_user.is_default_org():
                settings = Settings.load(organization=args.organization)
            elif current_user.organization == args.organization:
                settings = Settings.load(organization=current_user.organization)
            else:
                abort(404, 'Organization not found.')
        else:
            settings = Settings.load(organization=current_user.organization)
            
        return settings

    @api2.doc(security="Bearer")
    @api2.expect(mod_settings)
    @token_required
    @user_has('update_settings')
    @check_org
    def put(self, current_user):

        organization = None
        if 'organization' in api2.payload:
            organization = api2.payload.pop('organization')
        else:
            organization = current_user.organization

        if 'agent_pairing_token_valid_minutes' in api2.payload:
            if int(api2.payload['agent_pairing_token_valid_minutes']) > 525600:
                ns_settings_v2.abort(
                    400, 'agent_pairing_token_valid_minutes can not be greated than 365 days.')

        if 'approved_ips' in api2.payload and api2.payload['approved_ips'] is not None:
            api2.payload['approved_ips'] = api2.payload['approved_ips'].split('\n')

        if 'disallowed_password_keywords' in api2.payload and api2.payload['disallowed_password_keywords'] is not None:
            api2.payload['disallowed_password_keywords'] = api2.payload['disallowed_password_keywords'].split('\n')
             
        settings = Settings.load(organization=organization)
        settings.update(**api2.payload)

        return {'message': 'Succesfully updated settings'}


@ns_settings_v2.route("/backup")
class BackupData(Resource):

    @api2.doc(security="Bearer")
    @api2.expect(mod_create_backup)
    @token_required
    @user_has('view_settings')
    def post(self, current_user):
        '''
        Backs up all the data from the platform into a compressed archive
        containing a JSON file for each index
        '''

        if 'password' in api2.payload:

            models = [
                Event,Tag,ExpiredToken,Credential,Agent,ThreatList,EventStatus,EventRule,
                CaseComment,CaseHistory,Case,CaseTask,CaseTemplate,Observable,AgentGroup,
                TaskNote,Plugin,PluginConfig,EventLog,User,Role,DataType,CaseStatus,CloseReason,
                Settings,Input
            ]

            backup_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'backup/')
            lock_file = os.path.join(backup_path, 'backup.lock')

            # Check to see if a backup is already in progress
            if os.path.exists(lock_file):
                ns_settings_v2.abort(400, 'Backup already in progress.')

            for f in os.listdir(backup_path):
                os.remove(os.path.join(backup_path, f))

            # Create a lock file so other admins can't start a backup
            with open(lock_file, 'w') as f:
                f.write(f'BACKUP STARTED {datetime.datetime.utcnow()} by {current_user.username}')

            if not os.path.exists(backup_path):
                os.makedirs(backup_path)

            for model in models:

                filename = f'{model.Index.name}.json'
                file_path = os.path.join(backup_path, filename)
                search = model.search()
                search = search[0:search.count()]
                results = search.execute()
                results = [r.to_dict() for r in results]
                with open(file_path, 'w') as fout:
                    json.dump(results, fout, default=str)

                if not os.path.exists(file_path) or os.path.getsize(file_path) == 0:
                    ns_settings_v2.abort(400, f'Unable to backup to {filename}')

            archive_name = f'backup-{datetime.datetime.utcnow().strftime("%Y-%m-%d")}.zip'
            backup_archive = os.path.join(backup_path, archive_name)
            
            files_to_zip = []
            for folderName, subfolders, filenames in os.walk(backup_path):
                for filename in filenames:
                    if filename.endswith('.json'):
                        filepath = os.path.join(folderName,filename)
                        files_to_zip.append(filepath)

            #pyminizip.compress_multiple(files_to_zip, [], backup_archive, api2.payload['password'], 9)
            if os.path.exists(backup_archive):
                os.remove(os.path.join(lock_file))
                return send_from_directory(backup_path, archive_name, as_attachment=True)
            else:
                ns_settings_v2.abort(400, 'Backup failed.')
        else:
            ns_settings_v2.abort(400, 'Password missing.')

persistent_token_parser = api2.parser()
persistent_token_parser.add_argument('organization', location='args', required=False, type=str)

@ns_settings_v2.route("/generate_persistent_pairing_token")
class PersistentPairingToken(Resource):

    @api2.doc(security="Bearer")
    @api2.marshal_with(mod_persistent_pairing_token)
    @api2.expect(persistent_token_parser)
    @token_required
    @default_org
    @user_has('create_persistent_pairing_token')
    def get(self, user_in_default_org, current_user):
        ''' Returns a new API key for the user making the request '''

        args = persistent_token_parser.parse_args()

        
        settings = Settings.load(organization=current_user.organization)

        if user_in_default_org:
            if args.organization:
                settings = Settings.load(organization=args.organization)           
                
        return settings.generate_persistent_pairing_token()

@ns_dashboard_v2.route("")
class DashboardMetrics(Resource):
    
    @api2.doc(security="Bearer")
    @token_required
    def get(self, current_user):

        cases = Case.search()
        open_cases = cases.filter('match', status__name='New')
        closed_cases = cases.filter('match', status__closed='true')

        events = Event.search()
        new_events = events.filter('term', **{'status.name__keyword': 'New'})
        events_sorted = events.sort('-created_at')
        last_event = None
        if events_sorted.count() > 0:
            last_event = [e for e in events_sorted[0:1]][0]

        return {
            'total_cases': cases.count(),
            'open_cases': open_cases.count(),
            'closed_cases': closed_cases.count(),
            'total_events': events.count(),
            'new_events': new_events.count(),
            'time_since_last_event': last_event.created_at.isoformat()+"Z" if last_event else "Never"
        }

@ns_hunting_v2.route("/query")
class HuntingQuery(Resource):

    @token_required
    def post(self, current_user):

        search = Search(index='reflex-events-*')
        search = search.query('query_string', query=api2.payload['query'])
        results = search.execute()
        return results.to_dict()

