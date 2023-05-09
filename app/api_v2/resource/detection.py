import datetime
import json
import io

from uuid import uuid4
from app.api_v2.model.detection import DetectionException, DetectionRepository, VALID_DETECTION_STATUS
from app.api_v2.model.system import Settings
from app.api_v2.model.user import User
from app.api_v2.model.utils import _current_user_id_or_none
from ..utils import check_org, token_required, user_has, default_org
from flask import send_file
from flask_restx import Resource, Namespace, fields, inputs as xinputs
from ..model import (
    Detection,
    Organization,
    Event,
    Q,
    Agent,
    Input,
    MITRETactic,
    MITRETechnique,
    DetectionRepository
)
from .shared import mod_pagination, ISO8601, mod_user_list
from .utils import redistribute_detections
from ..utils import page_results
from .mitre import mod_tactic_brief, mod_technique_brief
from ..sigma_parsing.main import SigmaParser

api = Namespace(
    'Detection', description='Reflex detection rules', path='/detection', strict=True)

mod_bulk_detections = api.model('ExportDetections', {
    'detections': fields.List(fields.String, required=True)
})

mod_intel_list = api.model('DetectionIntelList', {
    'name': fields.String,
    'uuid': fields.String
})

mod_detection_exception = api.model('DetectionException', {
    'uuid': fields.String,
    'description': fields.String,
    'condition': fields.String(required=True),
    'values': fields.List(fields.String(required=True)),
    'field': fields.String(required=True),
    'list': fields.Nested(mod_intel_list, required=False),
    'is_global': fields.Boolean(required=False, default=False),
    'rule_bound': fields.Boolean(required=False, default=False)
}, strict=True)

mod_detection_exception_list = api.model('DetectionExceptionList', {
    'uuid': fields.String,
    'description': fields.String,
    'condition': fields.String,
    'values': fields.List(fields.String),
    'field': fields.String,
    'list': fields.Nested(mod_intel_list),
    'is_global': fields.Boolean(required=False, default=False),
    'rule_bound': fields.Boolean(required=False, default=False),
    'created_by': fields.Nested(mod_user_list)
}, strict=True)

mod_threshold_config = api.model('ThesholdConfig', {
    'threshold': fields.Integer,
    'key_field': fields.String,
    'operator': fields.String,
    'dynamic': fields.Boolean,
    'discovery_period': fields.Integer,
    'recalculation_period': fields.Integer,
    'per_field': fields.Boolean,
    'max_events': fields.Integer
}, strict=True)

mod_metric_change_config = api.model('MetricChangeConfig', {
    'avg_period': fields.Integer,
    'threshold': fields.Integer,
    'threshold_format': fields.Integer,
    'increase': fields.Boolean()
}, strict=True)

mod_indicator_match_config = api.model('IndicatorMatchConfig', {
    'list_uuid': fields.String,
    'source_field': fields.String,
}, strict=True)

mod_new_terms_config = api.model('NewTermsConfig', {
    'key_field': fields.String,
    'max_terms': fields.Integer,
    'window_size': fields.Integer
}, strict=True)

mod_field_mistmatch_config = api.model('FieldMismatchConfig', {
    'source_field': fields.String,
    'target_field': fields.String,
    'operator': fields.String
}, strict=True)

mod_query_config = api.model('DetectionQuery', {
    'language': fields.String,
    'query': fields.String
}, strict=True)

mod_source_config = api.model('SourceConfig', {
    'language': fields.String,
    'name': fields.String,
    'uuid': fields.String
})

mod_observable_field = api.model('ObservableField', {
    'field': fields.String,
    'alias': fields.String,
    'data_type': fields.String,
    'sigma_field': fields.String,
    'tlp': fields.Integer,
    'tags': fields.List(fields.String)
})

mod_detection_schedule_hour_range = api.model('DetectionScheduleHourRange', {
    'from': fields.String,
    'to': fields.String
})

mod_detection_schedule_day = api.model('DetectionScheduleDay', {
    'custom': fields.Boolean,
    'hours': fields.List(fields.Nested(mod_detection_schedule_hour_range))
})

mod_detection_schedule = api.model('DetectionSchedule', {
    'monday': fields.Nested(mod_detection_schedule_day),
    'tuesday': fields.Nested(mod_detection_schedule_day),
    'wednesday': fields.Nested(mod_detection_schedule_day),
    'thursday': fields.Nested(mod_detection_schedule_day),
    'friday': fields.Nested(mod_detection_schedule_day),
    'saturday': fields.Nested(mod_detection_schedule_day),
    'sunday': fields.Nested(mod_detection_schedule_day)
})

mod_detection_details = api.model('DetectionDetails', {
    'uuid': fields.String,
    'original_uuid': fields.String,
    'from_repo_sync': fields.Boolean,
    'name': fields.String,
    'query': fields.Nested(mod_query_config),
    'status': fields.String,
    'from_sigma': fields.Boolean,
    'sigma_rule': fields.String,
    'organization': fields.String,
    'detection_id': fields.String,
    'description': fields.String,
    'guide': fields.String,
    'setup_guide': fields.String,
    'testing_guide': fields.String,
    'tags': fields.List(fields.String),
    'tactics': fields.List(fields.Nested(mod_tactic_brief)),
    'techniques': fields.List(fields.Nested(mod_technique_brief)),
    'references': fields.List(fields.String),
    'false_positives': fields.List(fields.String),
    'kill_chain_phase': fields.String,
    'rule_type': fields.Integer,
    'version': fields.Integer,
    'active': fields.Boolean,
    'warnings': fields.List(fields.String),
    'source': fields.Nested(mod_source_config),
    'case_template': fields.String,
    'risk_score': fields.Integer,
    'severity': fields.Integer,
    'signature_fields': fields.List(fields.String),
    'field_templates': fields.List(fields.String),
    'observable_fields': fields.List(fields.Nested(mod_observable_field)),
    'time_taken': fields.Integer,
    'query_time_taken': fields.Integer,
    'interval': fields.Integer,
    'lookbehind': fields.Integer,
    'mute_period': fields.Integer,
    'skip_event_rules': fields.Boolean,
    'last_run': ISO8601,
    'last_hit': ISO8601,
    'total_hits': fields.Integer,
    'running': fields.Boolean,
    'assigned_agent': fields.String,
    'exceptions': fields.List(fields.Nested(mod_detection_exception_list)),
    'threshold_config': fields.Nested(mod_threshold_config, skip_none=True),
    'metric_change_config': fields.Nested(mod_metric_change_config, skip_none=True),
    'field_mismatch_config': fields.Nested(mod_field_mistmatch_config, skip_none=True),
    'new_terms_config': fields.Nested(mod_new_terms_config, skip_none=True),
    'indicator_match_config': fields.Nested(mod_indicator_match_config, skip_none=True),
    'include_source_meta_data': fields.Boolean(),
    'created_at': ISO8601,
    'created_by': fields.Nested(mod_user_list, skip_none=True),
    'updated_at': ISO8601,
    'updated_by': fields.Nested(mod_user_list, skip_none=True),
    'repository': fields.List(fields.String),
    'daily_schedule': fields.Boolean,
    'schedule': fields.Nested(mod_detection_schedule),
    'assess_rule': fields.Boolean,
    'hits_over_time': fields.String,
    'average_hits_per_day': fields.Integer,
    'last_assessed': fields.DateTime,
    'average_query_time': fields.Integer,
}, strict=True)

mod_create_detection = api.model('CreateDetection', {
    'name': fields.String(default='Sample Rule', required=True),
    'query': fields.Nested(mod_query_config, required=True),
    'from_sigma': fields.Boolean(default=False, required=False, skip_none=True),
    'sigma_rule': fields.String(required=False, skip_none=True),
    'sigma_rule_id': fields.String(required=False),
    'organization': fields.String,
    'status': fields.String(default='Draft', required=False, enum=VALID_DETECTION_STATUS),
    'description': fields.String(default="A detailed description.", required=True),
    'guide': fields.String(default="An investigation guide on how to triage this detection"),
    'setup_guide': fields.String,
    'testing_guide': fields.String,
    'tags': fields.List(fields.String),
    'tactics': fields.List(fields.Nested(mod_tactic_brief)),
    'techniques': fields.List(fields.Nested(mod_technique_brief)),
    'references': fields.List(fields.String),
    'false_positives': fields.List(fields.String),
    'kill_chain_phase': fields.String,
    'rule_type': fields.Integer(required=True),
    'active': fields.Boolean,
    'source': fields.Nested(mod_source_config, required=True),
    'case_template': fields.String,
    'risk_score': fields.Integer(default=10000, min=0, max=50000),
    'severity': fields.Integer(required=True, default=1, min=1, max=4),
    'signature_fields': fields.List(fields.String),
    'field_templates': fields.List(fields.String),
    'observable_fields': fields.List(fields.Nested(mod_observable_field)),
    'interval': fields.Integer(default=5, required=True, min=1),
    'lookbehind': fields.Integer(default=5, required=True, min=1),
    'mute_period': fields.Integer(default=5, required=True, min=0),
    'skip_event_rules': fields.Boolean(default=False),
    'exceptions': fields.List(fields.Nested(mod_detection_exception_list)),
    'threshold_config': fields.Nested(mod_threshold_config),
    'indicator_match_config': fields.Nested(mod_indicator_match_config),
    'metric_change_config': fields.Nested(mod_metric_change_config),
    'field_mismatch_config': fields.Nested(mod_field_mistmatch_config),
    'new_terms_config': fields.Nested(mod_new_terms_config),
    'include_source_meta_data': fields.Boolean(default=False),
    'daily_schedule': fields.Boolean(required=False),
    'schedule': fields.Nested(mod_detection_schedule, required=False)
}, strict=True)

mod_update_detection = api.model('UpdateDetection', {
    'name': fields.String,
    'organization': fields.String,
    'detection_id': fields.String,
    'description': fields.String,
    'guide': fields.String,
    'setup_guide': fields.String,
    'testing_guide': fields.String,
    'tags': fields.List(fields.String),
    'tactics': fields.List(fields.String),
    'techniques': fields.List(fields.String),
    'references': fields.List(fields.String),
    'false_positives': fields.List(fields.String),
    'kill_chain_phase': fields.String,
    'rule_type': fields.Integer,
    'active': fields.Boolean,
    'source': fields.String,
    'case_template': fields.String,
    'risk_score': fields.Integer(default=10000, min=0, max=50000),
    'severity': fields.Integer(required=True, default=1, min=1, max=4),
    'signature_fields': fields.List(fields.String),
    'field_templates': fields.List(fields.String),
    'observable_fields': fields.List(fields.String),
    'interval': fields.Integer(default=5, required=True, min=1),
    'lookbehind': fields.Integer(default=5, required=True, min=1),
    'mute_period': fields.Integer(default=5, required=True, min=0),
    'skip_event_rules': fields.Boolean,
    'exceptions': fields.List(fields.Nested(mod_detection_exception_list)),
    'threshold_config': fields.Nested(mod_threshold_config),
    'metric_change_config': fields.Nested(mod_metric_change_config),
    'field_mismatch_config': fields.Nested(mod_field_mistmatch_config),
    'new_terms_config': fields.Nested(mod_new_terms_config),
    'indicator_match_config': fields.Nested(mod_indicator_match_config),
    'include_source_meta_data': fields.Boolean(),
    'status': fields.String(default='Draft', required=False, enum=VALID_DETECTION_STATUS),
    'daily_schedule': fields.Boolean(required=False),
    'schedule': fields.Nested(mod_detection_schedule, required=False),
    'assess_rule': fields.Boolean,
    'hits_over_time': fields.String,
    'average_hits_per_day': fields.Integer,
    'last_assessed': fields.DateTime,
    'average_query_time': fields.Integer,
}, strict=True)

mod_detection_list_paged = api.model('DetectionListPaged', {
    'detections': fields.List(fields.Nested(mod_detection_details)),
    'pagination': fields.Nested(mod_pagination)
})

mod_detection_export = api.model('DetectionExport', {
    'original_uuid': fields.String(attribute='uuid'),
    'from_repo_sync': fields.Boolean,
    'name': fields.String,
    'query': fields.Nested(mod_query_config),
    'from_sigma': fields.Boolean,
    'sigma_rule': fields.String,
    'detection_id': fields.String,
    'description': fields.String,
    'guide': fields.String,
    'tags': fields.List(fields.String),
    'tactics': fields.List(fields.Nested(mod_tactic_brief)),
    'techniques': fields.List(fields.Nested(mod_technique_brief)),
    'references': fields.List(fields.String),
    'false_positives': fields.List(fields.String),
    'kill_chain_phase': fields.String,
    'rule_type': fields.Integer,
    'version': fields.Integer,
    'active': fields.Boolean,
    'warnings': fields.List(fields.String),
    'source': fields.Nested(mod_source_config),
    'risk_score': fields.Integer,
    'severity': fields.Integer,
    'signature_fields': fields.List(fields.String),
    'observable_fields': fields.List(fields.Nested(mod_observable_field)),
    'time_taken': fields.Integer,
    'query_time_taken': fields.Integer,
    'interval': fields.Integer,
    'lookbehind': fields.Integer,
    'mute_period': fields.Integer,
    'skip_event_rules': fields.Boolean,
    'exceptions': fields.List(fields.Nested(mod_detection_exception_list)),
    'threshold_config': fields.Nested(mod_threshold_config, skip_none=True),
    'metric_change_config': fields.Nested(mod_metric_change_config, skip_none=True),
    'field_mismatch_config': fields.Nested(mod_field_mistmatch_config, skip_none=True),
    'new_terms_config': fields.Nested(mod_new_terms_config, skip_none=True),
    'indicator_match_config': fields.Nested(mod_indicator_match_config, skip_none=True),
    'include_source_meta_data': fields.Boolean(),
    'status': fields.String,
    
})

mod_exported_detections = api.model('ExportedDetections', {
    'detections': fields.List(fields.Nested(mod_detection_export))
})

mod_detection_hits = api.model('DetectionHit', {
    'title': fields.String,
    'tags': fields.List(fields.String),
    'reference': fields.String(required=True),
    'severity': fields.Integer,
    'risk_score': fields.Integer,
    'created_at': ISO8601(attribute='created_at'),
    'updated_at': ISO8601(attribute='updated_at'),
    'original_date': ISO8601(attribute='original_date'),
})

mod_detection_hits_paged = api.model('DetectionHit', {
    'events': fields.List(fields.Nested(mod_detection_hits)),
    'pagination': fields.Nested(mod_pagination)
})

mod_sigma = api.model('Sigma', {
    'sigma_rule': fields.String,
    'source_input': fields.String,
    'organization': fields.String,
    'pipeline': fields.String(default='ecs_windows'),
    'backend': fields.String(default='opensearch')
})

mod_detection_field_settings = api.model('DetectionFieldSettings', {
    'fields': fields.List(fields.Nested(mod_observable_field)),
    'signature_fields': fields.List(fields.String)
})

mod_detection_import = api.model('ImportDetection', {
    'detections': fields.List(fields.Nested(mod_create_detection))
})

mod_deleted_detections = api.model('DeletedDetections', {
    'detections': fields.List(fields.String)
})

mod_detection_repo_filter = api.model('DetectionRepoFilter', {
    'value': fields.String,
    'name': fields.String,
    'count': fields.Integer
})

mod_detection_org_filter = api.model('DetectionOrgFilter', {
    'value': fields.String,
    'name': fields.String,
    'count': fields.Integer
})

mod_detection_warnings_filter = api.model('DetectionWarningsFilter', {
    'value': fields.String,
    'name': fields.String,
    'count': fields.Integer
})

mod_detection_status_filter = api.model('DetectionStatusFilter', {
    'value': fields.String,
    'name': fields.String,
    'count': fields.Integer
})

mod_detection_tactic_filter = api.model('DetectionTacticFilter', {
    'value': fields.String,
    'name': fields.String,
    'count': fields.Integer
})

mod_detection_technique_filter = api.model('DetectionTechniqueFilter', {
    'value': fields.String,
    'name': fields.String,
    'count': fields.Integer
})

mod_detection_tag_filter = api.model('DetectionTagFilter', {
    'value': fields.String,
    'name': fields.String,
    'count': fields.Integer
})

mod_detection_active_filter = api.model('DetectionActiveFilter', {
    'value': fields.Boolean,
    'name': fields.String,
    'count': fields.Integer
})

mod_detection_filters = api.model('DetectionFilters', {
    'tags': fields.List(fields.Nested(mod_detection_tag_filter)),
    'tactics': fields.List(fields.Nested(mod_detection_tactic_filter)),
    'techniques': fields.List(fields.Nested(mod_detection_technique_filter)),
    'status': fields.List(fields.Nested(mod_detection_status_filter)),
    'organization': fields.List(fields.Nested(mod_detection_org_filter)),
    'repository': fields.List(fields.Nested(mod_detection_repo_filter)),
    'warnings': fields.List(fields.Nested(mod_detection_warnings_filter)),
    'active': fields.List(fields.Nested(mod_detection_warnings_filter)),
    'rule_type': fields.List(fields.Nested(mod_detection_warnings_filter))
})

mod_detection_uuids = api.model('DetectionUUIDs', {
    'detections': fields.List(fields.String)
})

detection_list_parser = api.parser()
detection_list_parser.add_argument(
    'agent', location='args', type=str, required=False)
detection_list_parser.add_argument(
    'active', location='args', action="split", type=xinputs.boolean, required=False)
detection_list_parser.add_argument(
    'page', type=int, location='args', default=1, required=False)
detection_list_parser.add_argument(
    'sort_by', type=str, location='args', default='created_at', required=False)
detection_list_parser.add_argument(
    'sort_direction', type=str, location='args', default='asc', required=False)
detection_list_parser.add_argument(
    'page_size', type=int, location='args', default=10, required=False)
detection_list_parser.add_argument(
    'techniques', location='args',  action='split', type=str, required=False)
detection_list_parser.add_argument(
    'phase_names', location='args', action='split', type=str, required=False)
detection_list_parser.add_argument(
    'tactics', location='args', action='split', type=str, required=False)
detection_list_parser.add_argument(
    'organization', location='args', action='split', type=str, required=False)
detection_list_parser.add_argument(
    'repo_synced', location='args', type=xinputs.boolean, required=False, default=True)
detection_list_parser.add_argument(
    'tags', location='args', action='split', type=str, required=False)
detection_list_parser.add_argument(
    'repository', location='args', action='split', type=str, required=False)
detection_list_parser.add_argument(
    'status', location='args', action='split', type=str, required=False)
detection_list_parser.add_argument(
    'warnings', location='args', action='split', type=str, required=False)
detection_list_parser.add_argument(
    'name__like', location='args', type=str, required=False)
detection_list_parser.add_argument(
    'description__like', location='args', type=str, required=False)
detection_list_parser.add_argument(
    'query__like', location='args', type=str, required=False)
detection_list_parser.add_argument(
    'assess_rule', location='args', type=xinputs.boolean, required=False, default=False)
detection_list_parser.add_argument(
    'rule_type', location='args', type=int, action='split', required=False)
detection_list_parser.add_argument(
    'max_average_hits_per_day', location='args', type=int, required=False, default=0)
detection_list_parser.add_argument(
    'min_average_hits_per_day', location='args', type=int, required=False, default=0)

@api.route("")
class DetectionList(Resource):

    @api.doc(security="Bearer")
    @api.marshal_with(mod_detection_list_paged)
    @api.expect(detection_list_parser)
    @token_required
    @user_has('view_detections')
    def get(self, current_user):
        '''
        Returns a list of detections
        '''

        total_results = 0
        pages = 0

        args = detection_list_parser.parse_args()

        if isinstance(current_user, Agent) and not args.assess_rule:
            args.agent = current_user.uuid

        search = Detection.search()
        if args.sort_direction == 'desc':
            search = search.sort(f"-{args.sort_by}")
        else:
            search = search.sort(args.sort_by)

        if args.organization and len(args.organization) > 0 and args.organization != ['']:
            search = search.filter('terms', organization=args.organization)

        if args.repo_synced is False:
            search = search.filter('term', from_repo_sync=False)

        if args.active:
            search = search.filter('terms', active=args.active)

        if args.tags and len(args.tags) > 0 and args.tags[0] != '':
            search = search.filter('terms', tags=args.tags)

        if args.status and len(args.status) > 0 and args.status[0] != '':
            search = search.filter('terms', status=args.status)

        if args.warnings and len(args.warnings) > 0:
            search = search.filter('terms', warnings=args.warnings)

        if args.repository and len(args.repository) > 0 and args.repository[0] != '':
            if 'None' in args.repository:
                # If the user has selected None filter for detections with no value for repository
                search = search.filter(
                    'bool', should=[Q('terms', repository=args.repository), Q('bool', must_not=Q('exists', field='repository'))])
            else:
                search = search.filter('terms', repository=args.repository)

        # If both min and max average hits per day are provided, filter for detections that fall within the range
        if args.min_average_hits_per_day > 0 and args.max_average_hits_per_day > 0:
            search = search.filter('range', average_hits_per_day={
                                   'gte': args.min_average_hits_per_day, 'lte': args.max_average_hits_per_day})
            
        # If only min average hits per day is provided, filter for detections that are greater than or equal to the min
        elif args.min_average_hits_per_day > 0:
            search = search.filter('range', average_hits_per_day={
                                   'gte': args.min_average_hits_per_day})
            
        # If only max average hits per day is provided, filter for detections that are less than or equal to the max
        elif args.max_average_hits_per_day > 0:
            search = search.filter('range', average_hits_per_day={
                                   'lte': args.max_average_hits_per_day})

        if args.name__like:
            search = search.filter('wildcard', name=f"*{args.name__like}*")

        if args.description__like:
            search = search.filter('wildcard', description=f"*{args.description__like.lower()}*")

        if args.query__like:
            search = search.filter('wildcard', query__query=f"*{args.query__like.lower()}*")

        if args.rule_type:
            search = search.filter('terms', rule_type=args.rule_type)

        if args.phase_names and args.techniques:
            search = search.filter('bool', must=[Q('nested', path='techniques', query={'terms': {'techniques.external_id': args.techniques}}), Q(
                'nested', path='tactics', query={'terms': {'tactics.shortname': args.phase_names}})])
        elif args.phase_names and not args.techniques:
            search = search.filter('nested', path='tactics', query={
                                   'terms': {'tactics.shortname': args.tactics}})
        elif args.techniques and not args.phase_names:
            search = search.filter('nested', path='techniques', query={
                                   'terms': {'techniques.external_id': args.techniques}})

        if args.tactics and len(args.tactics) > 0 and args.tactics != [""]:
            search = search.filter('nested', path='tactics', query={
                                   'terms': {'tactics.external_id': args.tactics}})
            
        if args.assess_rule:
            search = search.filter('term', assess_rule=True)

        # If the agent parameter is provided do not page the results, load them all
        if 'agent' in args and args.agent not in (None, ''):
            search = search.filter('term', assigned_agent=args.agent)
            detections = list(search.scan())

            # Remove the fields the agent doesn't need such as guide, setup_guide, testing_guide
            for detection in detections:
                for field in ['guide', 'setup_guide', 'testing_guide']:
                    if field in detection:
                        del detection[field]

            total_results = len(detections)
            pages = 1
        else:
            search, total_results, pages = page_results(
                search, args.page, args.page_size)
            detections = search.execute()

        return {
            'detections': detections,
            'pagination': {
                'total_results': total_results,
                'pages': pages,
                'page': args.page,
                'page_size': args.page_size
            }
        }

    @api.doc(security="Bearer")
    @api.marshal_with(mod_detection_details)
    @api.expect(mod_create_detection, validate=True)
    @token_required
    @check_org
    @user_has('create_detection')
    def post(self, current_user):
        '''
        Creates a new detection rule
        '''

        # Only allow a detection with
        if 'organization' in api.payload:

            # Check to make sure the organization is a valid organization
            organization = Organization.get_by_uuid(
                uuid=api.payload['organization'])
            if not organization:
                api.abort(
                    404, f"Organization with UUID {api.payload['organization']} not found")

            exists = Detection.get_by_name(
                name=api.payload['name'], organization=api.payload['organization'])
        else:
            exists = Detection.get_by_name(name=api.payload['name'])

        if not exists:

            detection = Detection(**api.payload)
            detection.detection_id = uuid4()
            detection.version = 1
            detection.last_run = datetime.datetime.fromtimestamp(0)
            detection.assess_rule = True  # Always assess a rule on creation
            detection.save(refresh=True)

            # Redistribute the detection workload for the organization
            redistribute_detections(detection.organization)

            return detection
        else:
            api.abort(409, 'A detection rule with this name already exists')


@api.route("/select_by_filter")
class DetectionUUIDsByFilter(Resource):

    @api.doc(security="Bearer")
    @api.marshal_with(mod_detection_uuids)
    @api.expect(detection_list_parser)
    @token_required
    @user_has("view_detections")
    @default_org
    def get(self, user_in_default_org, current_user):

        args = detection_list_parser.parse_args()

        # Get all detections and aggregate the filters
        detections = Detection.search()

        # If there are any arguments provided, filter the detections

        if args.techniques and len(args.techniques) > 0 and args.techniques != [""]:
            detections = detections.filter('nested', path='techniques', query={
                                           'terms': {'techniques.external_id': args.techniques}})

        if args.tactics and len(args.tactics) > 0 and args.tactics != [""]:
            detections = detections.filter('nested', path='tactics', query={
                                           'terms': {'tactics.external_id': args.tactics}})

        if args.tags and len(args.tags) > 0 and args.tags != [""]:
            detections = detections.filter('terms', tags=args.tags)

        if args.status and len(args.status) > 0 and args.status != [""]:
            detections = detections.filter('terms', status=args.status)

        if args.repository and len(args.repository) > 0 and args.repository[0] != '':
            if 'None' in args.repository:
                # If the user has selected None filter for detections with no value for repository
                detections = detections.filter(
                    'bool', should=[Q('terms', repository=args.repository), Q('bool', must_not=Q('exists', field='repository'))])
            else:
                detections = detections.filter('terms', repository=args.repository)

        # If both min and max average hits per day are provided, filter for detections that fall within the range
        if args.min_average_hits_per_day > 0 and args.max_average_hits_per_day > 0:
            detections = detections.filter('range', average_hits_per_day={
                                   'gte': args.min_average_hits_per_day, 'lte': args.max_average_hits_per_day})
            
        # If only min average hits per day is provided, filter for detections that are greater than or equal to the min
        elif args.min_average_hits_per_day > 0:
            detections = detections.filter('range', average_hits_per_day={
                                   'gte': args.min_average_hits_per_day})
            
        # If only max average hits per day is provided, filter for detections that are less than or equal to the max
        elif args.max_average_hits_per_day > 0:
            detections = detections.filter('range', average_hits_per_day={
                                   'lte': args.max_average_hits_per_day})

        if args.repo_synced is False:
            detections = detections.filter('term', from_repo_sync=False)

        if args.warnings and len(args.warnings) > 0:
            detections = detections.filter('terms', warnings=args.warnings)

        if args.active:
            detections = detections.filter('terms', active=args.active)

        if args.name__like:
            detections = detections.filter('wildcard', name=f"*{args.name__like}*")

        if args.description__like:
            detections = detections.filter('wildcard', description=f"*{args.description__like.lower()}*")

        if args.query__like:
            detections = detections.filter('wildcard', query__query=f"*{args.query__like.lower()}*")

        if args.rule_type:
            detections = detections.filter('terms', rule_type=args.rule_type)

        # If the current_user is in the default org allow all detections, if they are not
        # in the default organization, filter the detections only to their organization
        if user_in_default_org is False:
            detections = detections.filter(
                'terms', organization=[current_user.organization])
        else:
            if args.organization and len(args.organization) > 0 and args.organization != ['']:
                detections = detections.filter(
                    'terms', organization=args.organization)
                
        # Use scan() to return all results
        detections = detections.scan()

        return {
            'detections': [detection.uuid for detection in detections]
        }


@api.route("/filters")
class DetectionFilters(Resource):

    @api.doc(security="Bearer")
    @api.marshal_with(mod_detection_filters)
    @api.expect(detection_list_parser)
    @token_required
    @user_has("view_detections")
    @default_org
    def get(self, user_in_default_org, current_user):
        '''
        Returns a list of available detection filters
        '''

        args = detection_list_parser.parse_args()

        # Get all detections and aggregate the filters
        detections = Detection.search()

        # If there are any arguments provided, filter the detections

        if args.techniques and len(args.techniques) > 0 and args.techniques != [""]:
            detections = detections.filter('nested', path='techniques', query={
                                           'terms': {'techniques.external_id': args.techniques}})

        if args.tactics and len(args.tactics) > 0 and args.tactics != [""]:
            detections = detections.filter('nested', path='tactics', query={
                                           'terms': {'tactics.external_id': args.tactics}})

        if args.tags and len(args.tags) > 0 and args.tags != [""]:
            detections = detections.filter('terms', tags=args.tags)

        if args.status and len(args.status) > 0 and args.status != [""]:
            detections = detections.filter('terms', status=args.status)

        if args.repository and len(args.repository) > 0 and args.repository[0] != '':
            if 'None' in args.repository:
                # If the user has selected None filter for detections with no value for repository
                detections = detections.filter(
                    'bool', should=[Q('terms', repository=args.repository), Q('bool', must_not=Q('exists', field='repository'))])
            else:
                detections = detections.filter('terms', repository=args.repository)

        # If both min and max average hits per day are provided, filter for detections that fall within the range
        if args.min_average_hits_per_day > 0 and args.max_average_hits_per_day > 0:
            detections = detections.filter('range', average_hits_per_day={
                                   'gte': args.min_average_hits_per_day, 'lte': args.max_average_hits_per_day})
            
        # If only min average hits per day is provided, filter for detections that are greater than or equal to the min
        elif args.min_average_hits_per_day > 0:
            detections = detections.filter('range', average_hits_per_day={
                                   'gte': args.min_average_hits_per_day})
            
        # If only max average hits per day is provided, filter for detections that are less than or equal to the max
        elif args.max_average_hits_per_day > 0:
            detections = detections.filter('range', average_hits_per_day={
                                   'lte': args.max_average_hits_per_day})

        if args.repo_synced is False:
            detections = detections.filter('term', from_repo_sync=False)

        if args.warnings and len(args.warnings) > 0:
            detections = detections.filter('terms', warnings=args.warnings)

        if args.active:
            detections = detections.filter('terms', active=args.active)

        if args.name__like:
            detections = detections.filter('wildcard', name=f"*{args.name__like}*")

        if args.description__like:
            detections = detections.filter('wildcard', description=f"*{args.description__like.lower()}*")

        if args.query__like:
            detections = detections.filter('wildcard', query__query=f"*{args.query__like.lower()}*")

        if args.rule_type:
            detections = detections.filter('terms', rule_type=args.rule_type)

        # If the current_user is in the default org allow all detections, if they are not
        # in the default organization, filter the detections only to their organization
        if user_in_default_org is False:
            detections = detections.filter(
                'terms', organization=[current_user.organization])
        else:
            if args.organization and len(args.organization) > 0 and args.organization != ['']:
                detections = detections.filter(
                    'terms', organization=args.organization)

        # Aggregate for tags
        detections.aggs.bucket('tags', 'terms', field='tags', size=1000)

        # Aggregate for tactic names which are nested under tactics
        detections.aggs.bucket('tactics', 'nested', path='tactics').bucket(
            'tactic_names', 'terms', field='tactics.external_id', size=1000)

        # Aggregate for technique names which are nested under techniques
        detections.aggs.bucket('techniques', 'nested', path='techniques').bucket(
            'technique_names', 'terms', field='techniques.external_id', size=1000)

        # Aggregate for status
        detections.aggs.bucket('status', 'terms', field='status', size=1000)

        # Aggregate for organization
        detections.aggs.bucket('organization', 'terms',
                               field='organization', size=1000)

        # Aggregate for repository
        detections.aggs.bucket('repository', 'terms',
                               field='repository', size=1000)

        # Aggregate for warnings
        detections.aggs.bucket('warnings', 'terms',
                               field='warnings', size=1000)
        
        # Aggregate for active
        detections.aggs.bucket('active', 'terms',
                                 field='active', size=1000)
        
        # Aggregator for rule_type
        detections.aggs.bucket('rule_type', 'terms',
                                    field='rule_type', size=1000)

        # Set size to 0
        detections = detections[0:0].execute()

        # Get all the organization keys so we can find their associated names
        org_keys = [
            bucket.key for bucket in detections.aggregations.organization.buckets]

        # Get all the repo keys so we can find their associated names
        repo_keys = [
            bucket.key for bucket in detections.aggregations.repository.buckets]

        # Get all the tactic keys so we can find their associated shortnames
        tactic_keys = [
            bucket.key for bucket in detections.aggregations.tactics.tactic_names.buckets]

        # Get all the technique keys so we can find their associated external_ids
        technique_keys = [
            bucket.key for bucket in detections.aggregations.techniques.technique_names.buckets]

        # Get the names for the keys we found
        _orgs = Organization.get_by_uuid(org_keys)
        if _orgs:
            _orgs = {org.uuid: org.name for org in _orgs}
        _repos = DetectionRepository.get_by_uuid(repo_keys)
        if _repos:
            _repos = {repo.uuid: repo.name for repo in _repos}
        _tactics = MITRETactic.get_by_external_id(tactic_keys)
        if _tactics:
            _tactics = {tactic.external_id: tactic.name for tactic in _tactics}
        _techniques = MITRETechnique.get_by_external_id(technique_keys)
        if _techniques:
            _techniques = {
                technique.external_id: technique.name for technique in _techniques}

        filters = {
            'organization': [],
            'repository': [],
            'tactics': [],
            'techniques': [],
            'tags': [],
            'status': [],
            'warnings': [],
            'active': [],
            'rule_type': []
        }

        # Create a list of orgs with their uuid, name and count
        if _orgs:
            for bucket in detections.aggregations.organization.buckets:
                filters['organization'].append(
                    {'value': bucket.key, 'name': _orgs[bucket.key], 'count': bucket.doc_count})
        if _repos:
            for bucket in detections.aggregations.repository.buckets:
                filters['repository'].append(
                    {'value': bucket.key, 'name': _repos[bucket.key], 'count': bucket.doc_count})
        if _tactics:
            for bucket in detections.aggregations.tactics.tactic_names.buckets:
                filters['tactics'].append(
                    {'value': bucket.key, 'name': _tactics[bucket.key], 'count': bucket.doc_count})
        if _techniques:
            for bucket in detections.aggregations.techniques.technique_names.buckets:
                filters['techniques'].append(
                    {'value': bucket.key, 'name': _techniques[bucket.key], 'count': bucket.doc_count})
        if detections.aggregations.tags.buckets:
            filters['tags'] = [{'name': bucket.key, 'value': bucket.key, 'count': bucket.doc_count}
                               for bucket in detections.aggregations.tags.buckets]

        filters['status'] = [{'name': bucket.key, 'value': bucket.key, 'count': bucket.doc_count}
                             for bucket in detections.aggregations.status.buckets]
        filters['warnings'] = [{'name': bucket.key, 'value': bucket.key, 'count': bucket.doc_count}
                               for bucket in detections.aggregations.warnings.buckets]
        rule_type_names = {
            0: 'Match',
            4: 'New Terms',
            1: 'Threshold',
            2: 'Metric',
            3: 'Field Mismatch',
            5: 'Indicator Match'
        }

        filters['rule_type'] = [{'name': rule_type_names[bucket.key], 'value': bucket.key, 'count': bucket.doc_count} for bucket in detections.aggregations.rule_type.buckets]
        
        active_names = {
            'True': 'Active',
            'False': 'Inactive'
        }
        
        filters['active'] = [{'name': active_names[str(bucket.key)], 'value': bucket.key, 'count': bucket.doc_count} for bucket in detections.aggregations.active.buckets]

        filters['repository'].append({
            'value': 'None',
            'name': 'None',
            'count': 0
        })

        return filters


detection_hit_parser = api.parser()
detection_hit_parser.add_argument(
    'page', type=int, location='args', default=1, required=False)
detection_hit_parser.add_argument(
    'page_size', type=int, location='args', default=10, required=False)
detection_hit_parser.add_argument(
    'sort_by', type=str, location='args', default='created_at', required=False
)
detection_hit_parser.add_argument(
    'sort_direction', type=str, location='args', default='desc', required=False
)


@api.route("/<uuid>/hits")
class DetectionHits(Resource):

    @api.doc(security="Bearer")
    @api.marshal_with(mod_detection_hits_paged)
    @api.expect(detection_hit_parser)
    @token_required
    @user_has('view_events')
    def get(self, uuid, current_user):

        args = detection_hit_parser.parse_args()

        detection = Detection.get_by_uuid(uuid=uuid)
        if detection:

            events = Event.search()

            events = events.filter('term', detection_id=detection.uuid)

            sort_by = args.sort_by
            if args.sort_direction == 'desc':
                sort_by = f"-{sort_by}"

            events = events.sort(sort_by)

            events, total_results, pages = page_results(
                events, args.page, args.page_size)

            events = events.execute()

            response = {
                'events': list(events),
                'pagination': {
                    'total_results': total_results,
                    'pages': pages,
                    'page': args['page'],
                    'page_size': args['page_size']
                }
            }
            return response
        else:
            api.abort(404, f'Detection rule for UUID {uuid} not found')


@api.route("/<uuid>/add_exception")
class AddDetectionException(Resource):

    @api.doc(security="Bearer")
    @api.marshal_with(mod_detection_details)
    @api.expect(mod_detection_exception, validate=True)
    @token_required
    @user_has('update_detection')
    def put(self, uuid, current_user):
        '''
        Adds an exception to a detection rule
        '''

        detection = Detection.get_by_uuid(uuid=uuid)
        if detection:

            # Create the exception inner document and add the auditing meta data
            exception = DetectionException(
                **api.payload,
                uuid=uuid4(),
                created_at=datetime.datetime.utcnow(),
                created_by=_current_user_id_or_none()
            )

            # If the detection already has some exceptions append this new one
            # else start a brand new list
            if detection.exceptions:
                detection.exceptions.append(exception)
            else:
                detection.exceptions = [exception]

            detection.save(refresh=True)

            return detection
        else:
            api.abort(404, f'Detection rule for UUID {uuid} not found')


@api.route("/<uuid>/remove_exception/<exception_uuid>")
class RemoveDetectionException(Resource):

    @api.doc(security="Bearer")
    @api.marshal_with(mod_detection_details)
    @token_required
    @user_has('update_detection')
    def delete(self, uuid, exception_uuid, current_user):
        '''
        Removes an exception from the detection rule
        '''

        detection = Detection.get_by_uuid(uuid=uuid)
        if detection:
            if detection.exceptions:
                detection.exceptions = [
                    exception for exception in detection.exceptions if exception.uuid != exception_uuid]
                detection.save(refresh=True)

            return detection
        else:
            api.abort(404, f'Detection rule for UUID {uuid} not found')


@api.route("/<uuid>")
class DetectionDetails(Resource):

    @api.doc(security="Bearer")
    @api.marshal_with(mod_detection_details)
    @token_required
    @user_has('view_detections')
    def get(self, uuid, current_user):
        '''
        Returns the details of a single detection rule
        '''
        detection = Detection.get_by_uuid(uuid=uuid)
        if detection:
            return detection
        else:
            api.abort(400, f'Detection rule for UUID {uuid} not found')

    @api.doc(security="Bearer")
    @api.marshal_with(mod_detection_details)
    @api.expect(mod_create_detection)
    @token_required
    @user_has('update_detection')
    def put(self, uuid, current_user):
        '''
        Updates the details of a single detection rule
        '''

        should_redistribute = False
        forbidden_user_fields = ['query_time_taken', 'total_hits', 'last_hit', 'last_run',
                                 'created_at', 'created_by', 'updated_at', 'updated_by',
                                 'time_taken', 'warnings', 'version', 'running',
                                 'assigned_agent', 'assess_rule', 'hits_over_time',
                                 'average_hits_per_day', 'last_assessed', 'average_query_time']

        # Prevent users from updating these fields
        if isinstance(current_user, User):
            for field in list(api.payload):
                if field in forbidden_user_fields:
                    del api.payload[field]

        detection = Detection.get_by_uuid(uuid=uuid)
        if detection:

            if 'query' in api.payload and detection.query.query != api.payload['query']:
                api.payload['assess_rule'] = True

            settings = Settings.load(organization=detection.organization)

            # Update the detection version number when the detection is saved and certain fields
            # are present in the update payoad
            if any([field in api.payload for field in ['query', 'description', 'guide', 'title', 'setup_guide', 'testing_guide']]):
                if hasattr(detection, 'version'):
                    detection.version += 1
                else:
                    detection.version = 1

            if 'warnings' not in api.payload:
                if hasattr(detection, 'warnings'):
                    api.payload['warnings'] = detection.warnings

            try:
                SLOW_DETECTION_THRESHOLD = settings.slow_detection_threshold
            except:
                SLOW_DETECTION_THRESHOLD = 1000
            if 'query_time_taken' in api.payload and api.payload['query_time_taken'] > SLOW_DETECTION_THRESHOLD:
                if 'warnings' not in api.payload:
                    api.payload['warnings'] = ['slow-query']
                else:
                    api.payload['warnings'].append('slow-query')
            else:
                if 'warnings' in api.payload and 'slow-query' in api.payload['warnings']:
                    api.payload['warnings'].remove('slow-query')

            try:
                HIGH_VOLUME_THRESHOLD = settings.high_volume_threshold
            except:
                HIGH_VOLUME_THRESHOLD = 10000

            if 'hits' in api.payload and api.payload['hits'] > HIGH_VOLUME_THRESHOLD:
                if 'warnings' not in api.payload:
                    api.payload['warnings'] = ['high-volume']
                else:
                    api.payload['warnings'].append('high-volume')
                api.payload['active'] = False  # Circuit break high volume alerts
            else:
                if 'warnings' in api.payload and 'high-volume' in api.payload['warnings']:
                    api.payload['warnings'].remove('high-volume')

            # Clear all warnings
            if 'warnings' not in api.payload:
                api.payload['warnings'] = []

            if 'active' in api.payload and detection.active != api.payload['active']:
                should_redistribute = True

            detection.update(**api.payload, refresh=True)

            if should_redistribute:
                redistribute_detections(detection.organization)

            return detection
        else:
            api.abort(400, f'Detection rule for UUID {uuid} not found')

    @api.doc(security="Bearer")
    @token_required
    @user_has('delete_detection')
    def delete(self, uuid, current_user):
        '''
        Deletes a single detection rule
        '''
        detection = Detection.get_by_uuid(uuid=uuid)
        if detection:

            organization = detection.organization
            detection.delete(refresh=True)

            # Redistribute the detection workload for the organization
            redistribute_detections(organization)

            # If the detection was part of a repository, remove it from the repository
            if detection.repository:
                repositories = DetectionRepository.get_by_uuid(
                    uuid=detection.repository)
                if repositories:
                    if isinstance(repositories, list):
                        for repo in repositories:
                            repo.detections = [
                                detection for detection in repo.detections if detection != detection.uuid]
                            repo.save(refresh=True)
                    else:
                        repositories.detections.remove(detection.detection_id)
                        repositories.save()

            return {}
        else:
            api.abort(400, f'Detection rule for UUID {uuid} not found')


@api.route("/<uuid>/field_settings")
class DetectionFieldSettings(Resource):
    '''
    Returns information about how the detection rule fields are configured
    '''

    @api.doc(security="Bearer")
    @api.marshal_with(mod_detection_field_settings)
    @token_required
    @user_has('view_detections')
    def get(self, uuid, current_user):
        detection = Detection.get_by_uuid(uuid=uuid)
        if detection:

            final_fields = []
            signature_fields = []

            final_fields = detection.get_field_settings()

            source_input = None

            if detection.signature_fields:
                signature_fields = detection.signature_fields

            # If the detection rule has no field settings or signature fields
            # fetch the settings from the source input
            if not final_fields or not signature_fields:
                source_input = Input.get_by_uuid(detection.source.uuid)

                # If no final_fields were determined, default to the source input field mapping
                if not final_fields:
                    final_fields = source_input.get_field_settings()

                # If no signature fields were determined, default to the source input signature fields
                if not signature_fields:
                    if hasattr(source_input.config, 'signature_fields'):
                        signature_fields = source_input.config.signature_fields
                    else:
                        signature_fields = []

            response = {
                "fields": final_fields,
                "signature_fields": signature_fields
            }

            return response
        else:
            api.abort(400, f'Detection rule for UUID {uuid} not found')


@api.route("/parse_sigma")
class ParseSigma(Resource):

    @api.doc(security="Bearer")
    @api.marshal_with(mod_detection_details, skip_none=True)
    @api.expect(mod_sigma)
    @token_required
    @user_has('create_detection')
    def post(self, current_user):
        '''
        Parses a Sigma rule and returns the detection rule
        '''

        try:
            sp = SigmaParser(**api.payload)
            detection = sp.generate_detection()
        except Exception as e:
            api.abort(400, f'Error parsing Sigma rule: {e}')

        #sigma_parser = SigmaParser()
        #detection = sigma_parser.parse(sigma_rule)

        return detection


@api.route("/<uuid>/export")
class DetectionExport(Resource):

    @api.doc(security="Bearer")
    @api.marshal_with(mod_detection_export)
    @token_required
    @user_has('view_detections')
    def get(self, uuid, current_user):
        '''
        Returns the detection rule as a JSON object
        '''

        detection = Detection.get_by_uuid(uuid=uuid)

        if detection:
            return detection

        else:
            api.abort(400, f'Detection rule for UUID {uuid} not found')


@api.route("/export")
class DetectionExportSelected(Resource):

    @api.doc(security="Bearer")
    @api.marshal_with(mod_detection_export, as_list=True, skip_none=True)
    @api.expect(mod_bulk_detections)
    @token_required
    @user_has('view_detections')
    def post(self, current_user):
        '''
        Returns the detection rules as a JSON object
        '''

        detections = Detection.get_by_uuid(uuid=api.payload['detections'])

        if detections:
            return detections

        else:
            api.abort(400, f'Detection rules not found')


@api.route("/enable")
class BulkEnableDetections(Resource):

    @api.doc(security="Bearer")
    @api.expect(mod_bulk_detections)
    @token_required
    @api.marshal_with(mod_detection_details, as_list=True, skip_none=True)
    @user_has('update_detection')
    def post(self, current_user):
        '''
        Enables the selected detections
        '''

        updated_orgs = []

        # Find all the detections
        detections = Detection.get_by_uuid(uuid=api.payload['detections'], all_results=True)

        if detections:

            # Update each detection
            for detection in detections:

                # If the detection is already active, skip it
                if detection.active:
                    continue

                # TODO: Add a access check to make sure this user has access to update
                # the detection for now we will just check if the user is an admin or in
                # the detection's organization
                if current_user.is_default_org or current_user.organization == detection.organization:
                    detection.update(active=True, refresh=True)

                    # Track which organizations have updated detections so
                    # the detection workload can be redistributed
                    if detection.organization not in updated_orgs:
                        updated_orgs.append(detection.organization)

            # Redistribute the detection workload for each organization
            for organization in updated_orgs:
                redistribute_detections(organization)

            return detections

        else:
            api.abort(400, f'Detection rules not found')


@api.route("/delete")
class BulkDeleteDetections(Resource):

    @api.doc(security="Bearer")
    @api.expect(mod_bulk_detections)
    @token_required
    @api.marshal_with(mod_deleted_detections, as_list=True, skip_none=True)
    @default_org
    @user_has('delete_detection')
    def delete(self, user_in_default_org, current_user):
        '''
        Deletes the selected detections
        '''

        # Find all the detections
        detections = Detection.get_by_uuid(uuid=api.payload['detections'])

        deleted_detections = []

        if detections:

            if any([detection.from_repo_sync for detection in detections]):
                api.abort(
                    400, f'Detection rules cannot be deleted because they were created by a repository sync')

            # Update each detection
            for detection in detections:

                # Skip detections that are currently active, can only delete inactive detections
                if detection.active:
                    continue

                # TODO: Add a access check to make sure this user has access to update
                # the detection for now we will just check if the user is an admin or in
                # the detection's organization
                if user_in_default_org or current_user.organization == detection.organization:
                    detection_uuid = detection.uuid

                    # If the detection was part of a repository, remove it from the repository
                    if detection.repository:
                        repositories = DetectionRepository.get_by_uuid(
                            uuid=detection.repository)
                        if repositories:
                            if isinstance(repositories, list):
                                for repo in repositories:
                                    repo.remove_detections([detection])
                            else:
                                repositories.remove_detections([detection])

                        # Set from_repo_sync to False on any detections synchronized from this detection
                        synchronized_detections = Detection.get_by_detection_id(
                            detection.detection_id)
                        if synchronized_detections:
                            for synchronized_detection in synchronized_detections:
                                if synchronized_detection.uuid != detection_uuid:
                                    synchronized_detection.update(
                                        from_repo_sync=False)

                    # Delete the detection
                    detection.delete()
                    deleted_detections.append(detection_uuid)

        return {'detections': deleted_detections}


@api.route("/disable")
class BulkDisableDetections(Resource):

    @api.doc(security="Bearer")
    @api.expect(mod_bulk_detections)
    @token_required
    @api.marshal_with(mod_detection_details, as_list=True, skip_none=True)
    @user_has('update_detection')
    def post(self, current_user):
        '''
        Disables the selected detections
        '''

        updated_orgs = []

        # Find all the detections
        detections = Detection.get_by_uuid(uuid=api.payload['detections'], all_results=True)

        if detections:

            # Update each detection
            for detection in detections:

                # If the detection is already disabled, skip it
                if not detection.active:
                    continue

                # TODO: Add a access check to make sure this user has access to update
                # the detection for now we will just check if the user is an admin or in
                # the detection's organization
                if current_user.default_org or current_user.organization == detection.organization:
                    detection.update(active=False, refresh=True)

                    # Track which organizations have updated detections so
                    # the detection workload can be redistributed
                    if detection.organization not in updated_orgs:
                        updated_orgs.append(detection.organization)

            # Redistribute the detection workload for each organization
            for organization in updated_orgs:
                redistribute_detections(organization)

            return detections

        else:
            api.abort(400, f'Detection rules not found')


@api.route("/import")
class DetectionImport(Resource):

    @api.doc(security="Bearer")
    @api.expect(mod_detection_import)
    @api.marshal_with(mod_detection_details, as_list=True, skip_none=True)
    @token_required
    @user_has('create_detection')
    def post(self, current_user):
        '''
        Imports a detection rule or rules
        '''

        imported_detections = []

        if 'detections' in api.payload:
            for detection in api.payload['detections']:
                d = Detection.create_from_json(detection)
                imported_detections.append(d)

        return imported_detections
