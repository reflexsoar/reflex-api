import datetime

from uuid import uuid4
from app.api_v2.model.detection import DetectionException
from app.api_v2.model.user import User
from app.api_v2.model.utils import _current_user_id_or_none
from ..utils import check_org, token_required, user_has
from flask_restx import Resource, Namespace, fields, inputs as xinputs
from ..model import (
    Detection,
    Organization,
    Event,
    Q,
    Agent
)
from .shared import mod_pagination, ISO8601, mod_user_list
from .utils import redistribute_detections
from ..utils import page_results
from .mitre import mod_tactic_brief, mod_technique_brief
from ..sigma_parsing.main import SigmaParser

api = Namespace(
    'Detection', description='Reflex detection rules', path='/detection', strict=True)

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
    'list': fields.Nested(mod_intel_list)
}, strict=True)

mod_detection_exception_list = api.model('DetectionExceptionList', {
    'uuid': fields.String,
    'description': fields.String,
    'condition': fields.String,
    'values': fields.List(fields.String),
    'field': fields.String,
    'list': fields.Nested(mod_intel_list),
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
    'tlp': fields.Integer,
    'tags': fields.List(fields.String)
})

mod_detection_details = api.model('DetectionDetails', {
    'uuid': fields.String,
    'name': fields.String,
    'query': fields.Nested(mod_query_config),
    'from_sigma': fields.Boolean,
    'sigma_rule': fields.String,
    'organization': fields.String,
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
    'case_template': fields.String,
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
    'include_source_meta_data': fields.Boolean(),
    'created_at': ISO8601,
    'created_by': fields.Nested(mod_user_list, skip_none=True),
    'updated_at': ISO8601,
    'updated_by': fields.Nested(mod_user_list, skip_none=True)
}, strict=True)

mod_create_detection = api.model('CreateDetection', {
    'name': fields.String(default='Sample Rule', required=True),
    'query': fields.Nested(mod_query_config, required=True),
    'from_sigma': fields.Boolean(default=False, required=False, skip_none=True),
    'sigma_rule': fields.String(required=False, skip_none=True),
    'sigma_rule_id': fields.String(required=False),
    'organization': fields.String,
    'description': fields.String(default="A detailed description.", required=True),
    'guide': fields.String(default="An investigation guide on how to triage this detection"),
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
    'observable_fields': fields.List(fields.Nested(mod_observable_field)),
    'interval': fields.Integer(default=5, required=True, min=1),
    'lookbehind': fields.Integer(default=5, required=True, min=1),
    'mute_period': fields.Integer(default=5, required=True, min=0),
    'skip_event_rules': fields.Boolean(default=False),
    'exceptions': fields.List(fields.Nested(mod_detection_exception_list)),
    'threshold_config': fields.Nested(mod_threshold_config),
    'metric_change_config': fields.Nested(mod_metric_change_config),
    'field_mismatch_config': fields.Nested(mod_field_mistmatch_config),
    'new_terms_config': fields.Nested(mod_new_terms_config),
    'include_source_meta_data': fields.Boolean(default=False)
}, strict=True)

mod_update_detection = api.model('UpdateDetection', {
    'name': fields.String,
    'organization': fields.String,
    'detection_id': fields.String,
    'description': fields.String,
    'guide': fields.String,
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
    'include_source_meta_data': fields.Boolean()
}, strict=True)

mod_detection_list_paged = api.model('DetectionListPaged', {
    'detections': fields.List(fields.Nested(mod_detection_details)),
    'pagination': fields.Nested(mod_pagination)
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

detection_list_parser = api.parser()
detection_list_parser.add_argument(
    'agent', location='args', type=str, required=False)
detection_list_parser.add_argument(
    'active', location='args', type=xinputs.boolean, required=False)
detection_list_parser.add_argument(
    'page', type=int, location='args', default=1, required=False)
detection_list_parser.add_argument(
    'sort_by', type=str, location='args', default='created_at', required=False)
detection_list_parser.add_argument(
    'sort_direction', type=str, location='args', default='asc', required=False)
detection_list_parser.add_argument(
    'page_size', type=int, location='args', default=10, required=False)
detection_list_parser.add_argument(
    'techniques', location='args',  action='append', type=str, required=False)
detection_list_parser.add_argument(
    'tactics', location='args', action='append', type=str, required=False)
detection_list_parser.add_argument(
    'organization', location='args', type=str, required=False)


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

        if isinstance(current_user, Agent):
            args.agent = current_user.uuid

        search = Detection.search()
        if args.sort_direction == 'desc':
            search = search.sort(f"-{args.sort_by}")
        else:
            search = search.sort(args.sort_by)

        if args.organization:
            search = search.filter('term', organization=args.organization)

        if 'active' in args and args.active in (True, False):
            search = search.filter('term', active=args.active)

        if args.tactics and args.techniques:
            search = search.filter('bool', must=[Q('nested', path='techniques', query={'terms': {'techniques.external_id': args.techniques}}), Q(
                'nested', path='tactics', query={'terms': {'tactics.shortname': args.tactics}})])
        elif args.tactics and not args.techniques:
            search = search.filter('nested', path='tactics', query={
                                   'terms': {'tactics.shortname': args.tactics}})
        elif args.techniques and not args.tactics:
            search = search.filter('nested', path='techniques', query={
                                   'terms': {'techniques.external_id': args.techniques}})

        # If the agent parameter is provided do not page the results, load them all
        if 'agent' in args and args.agent not in (None, ''):
            search = search.filter('term', assigned_agent=args.agent)
            detections = list(search.scan())
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
            detection.save(refresh=True)

            # Redistribute the detection workload for the organization
            redistribute_detections(detection.organization)

            return detection
        else:
            api.abort(409, 'A detection rule with this name already exists')


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
                                 'created_at', 'created_by', 'updated_at', 'updated_by', 'time_taken', 'warnings', 'version', 'running',
                                 'assigned_agent']

        # Prevent users from updating these fields
        if isinstance(current_user, User):
            for field in list(api.payload):
                if field in forbidden_user_fields:
                    del api.payload[field]

        detection = Detection.get_by_uuid(uuid=uuid)
        if detection:

            # Update the detection version number when the detection is saved and certain fields
            # are present in the update payoad
            if any([field in api.payload for field in ['query', 'description', 'guide']]):
                if hasattr(detection, 'version'):
                    detection.version += 1
                else:
                    detection.version = 1

            # TODO: Move the time_taken high watermark to an organizational global setting
            # Defaults to longer than 30 seconds, clear all warnings on update
            api.payload['warnings'] = []
            if 'query_time_taken' in api.payload and api.payload['query_time_taken'] > 30_000:
                api.payload['warnings'].append('slow-query')

            # TODO: Move the high watermark on hits to an organizational global setting
            # Defaults to 10000
            if 'hits' in api.payload and api.payload['hits'] > 10_000:
                api.payload['warnings'].append('high-volume')

            if 'active' in api.payload and detection.active != api.payload['active']:
                should_redistribute = True

            detection.update(**api.payload, refresh=True)

            if should_redistribute:
                redistribute_detections(detection.organization)

            print(detection.updated_at)

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

            return {}
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
