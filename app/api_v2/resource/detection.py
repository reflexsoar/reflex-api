from uuid import uuid4
from ..utils import check_org, token_required, user_has, ip_approved
from flask_restx import Resource, Namespace, fields
from ..model import (
    Detection
)
from .shared import FormatTags, mod_pagination, ISO8601
from .utils import redistribute_detections

api = Namespace('Detection', description='Reflex detection rules', path='/detection')


mod_detection_exception = api.model('DetectionException', {
    'description': fields.String,
    'query': fields.String
}, strict=True)

mod_threshold_config = api.model('ThesholdConfig', {
    'threshold': fields.Integer,
    'key_field': fields.String
}, strict=True)

mod_metric_change_config = api.model('MetricChangeConfig', {
    'avg_period': fields.Integer,
    'threshold': fields.Integer,
    'threshold_format': fields.Integer,
    'increase': fields.Boolean()    
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
    'source': fields.String
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
    'query': fields.List(fields.Nested(mod_query_config)),
    'from_sigma': fields.Boolean,
    'sigma_rule': fields.String,
    'organization': fields.String,
    'detection_id': fields.String,
    'description': fields.String,
    'guide': fields.String,
    'tags': fields.List(fields.String),
    'tactics': fields.List(fields.String),
    'techniques': fields.List(fields.String),
    'references': fields.List(fields.String),
    'kill_chain_phase': fields.String,
    'rule_type': fields.Integer,
    'version': fields.Integer,
    'active': fields.Boolean,
    'warnings': fields.List(fields.String),
    'source': fields.List(fields.Nested(mod_source_config)),
    'case_template': fields.String,
    'risk_score': fields.Integer,
    'severity': fields.Integer,
    'signature_fields': fields.List(fields.String),
    'observable_fields': fields.List(fields.Nested(mod_observable_field)),
    'query_time': fields.Integer,
    'interval': fields.Integer,
    'lookbehind': fields.Integer,
    'skip_event_rules': fields.Boolean,
    'last_run': ISO8601,
    'running': fields.Boolean,
    'assigned_agent': fields.String,
    'exceptions': fields.List(fields.Nested(mod_detection_exception)),
    'threshold_config': fields.Nested(mod_threshold_config),
    'metric_change_config': fields.Nested(mod_metric_change_config),
    'field_mismatch_config': fields.Nested(mod_field_mistmatch_config)
})

mod_create_detection = api.model('CreateDetection', {
    'name': fields.String(default='Sample Rule', required=True),
    'query': fields.List(fields.Nested(mod_query_config), required=True),
    'from_sigma': fields.Boolean(default=False),
    'sigma_rule': fields.String,
    'organization': fields.String,
    'description': fields.String(default="A detailed description.", required=True),
    'guide': fields.String(default="An investigation guide on how to triage this detection"),
    'tags': fields.List(fields.String),
    'tactics': fields.List(fields.String),
    'techniques': fields.List(fields.String),
    'references': fields.List(fields.String),
    'kill_chain_phase': fields.String,
    'rule_type': fields.Integer(required=True),
    'active': fields.Boolean,
    'source': fields.List(fields.Nested(mod_source_config), required=True),
    'case_template': fields.String,
    'risk_score': fields.Integer(default=50),
    'severity': fields.Integer(required=True, default=1),
    'signature_fields': fields.List(fields.String),
    'observable_fields': fields.List(fields.Nested(mod_observable_field)),
    'interval': fields.Integer(default=5, required=True),
    'lookbehind': fields.Integer(default=5, required=True),
    'skip_event_rules': fields.Boolean(default=False),
    'exceptions': fields.List(fields.Nested(mod_detection_exception)),
    'threshold_config': fields.Nested(mod_threshold_config),
    'metric_change_config': fields.Nested(mod_metric_change_config),
    'field_mismatch_config': fields.Nested(mod_field_mistmatch_config)
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
    'kill_chain_phase': fields.String,
    'rule_type': fields.Integer,
    'active': fields.Boolean,
    'source': fields.String,
    'case_template': fields.String,
    'risk_score': fields.Integer,
    'severity': fields.Integer,
    'signature_fields': fields.List(fields.String),
    'observable_fields': fields.List(fields.String),
    'interval': fields.Integer,
    'lookbehind': fields.Integer,
    'skip_event_rules': fields.Boolean
}, strict=True)

mod_detection_list_paged = api.model('DetectionListPaged', {
    'detections': fields.List(fields.Nested(mod_detection_details)),
    'pagination': fields.Nested(mod_pagination)
})



@api.route("")
class DetectionList(Resource):

    @api.doc(security="Bearer")
    @api.marshal_with(mod_detection_list_paged)
    #@api.expect(mod_detection_list_parser)
    @token_required
    @user_has('view_detections')
    def get(self, current_user):
        '''
        Returns a list of detections
        '''

        search = Detection.search()

        detections = list(search.scan())

        return {
            'detections': detections,
            'pagination': {}
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
            exists = Detection.get_by_name(name=api.payload['name'], organization=api.payload['organization'])
        else:
            exists = Detection.get_by_name(name=api.payload['name'])

        if not exists:

            detection = Detection(**api.payload)
            detection.detection_id = uuid4()
            detection.version = 1
            detection.save()

            # Redistribute the detection workload for the organization
            redistribute_detections(detection.organization)

            return detection
        else:
            api.abort(409, 'A detection rule with this name already exists')


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
        detection = Detection.get_by_uuid(uuid=uuid)
        if detection:
            print(api.payload)

            # Update the detection version number when the detection is saved
            if hasattr(detection, 'version'):
                detection.version += 1            

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
            detection.delete()
            return {}
        else:
            api.abort(400, f'Detection rule for UUID {uuid} not found')