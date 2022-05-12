from ..utils import token_required, user_has, ip_approved
from flask_restx import Resource, Namespace, fields
from ..model import (
    Detection
)
from .shared import FormatTags, mod_pagination, ISO8601

api = Namespace('Detection', description='Reflex detection rules', path='/detection')

mod_detection_details = api.model('DetectionDetails', {
    'uuid': fields.String,
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
    'version': fields.Float,
    'active': fields.Boolean,
    'warnings': fields.List(fields.String),
    'source': fields.String,
    'case_template': fields.String,
    'risk_score': fields.Integer,
    'severity': fields.Integer,
    'signature_fields': fields.List(fields.String),
    'observable_fields': fields.List(fields.String),
    'query_time': fields.Integer,
    'interval': fields.Integer,
    'lookbehind': fields.Integer,
    'skip_event_rules': fields.Boolean,
    'last_run': ISO8601,
    'running': fields.Boolean
})

mod_create_detection = api.model('CreateDetection', {
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
        return {
            'detections': [],
            'pagination': {}
        }


    @api.doc(security="Bearer")
    @api.marshal_with(mod_detection_details)
    @api.expect(mod_create_detection)
    @token_required
    @user_has('create_detection')
    def post(self, current_user):
        '''
        Creates a new detection rule
        '''

        detection = Detection(**api.payload)
        detection.version = 1

        return {}

@api.route("/<uuid>/run")
class RunDetection(Resource):

    @api.doc(security="Bearer")
    @api.marshal_with(mod_detection_details)
    @token_required
    @user_has('update_detection')
    def put(self, uuid, current_user):
        '''
        Sets the detection rule as currently running so that other agents do 
        not pick up the rule and run it at the same time
        '''

        detection = Detection.get_by_uuid(uuid=uuid)
        detection.set_run_flag(flag=True)
        return detection


@api.route("/<uuid>/stop")
class StopDetection(Resource):

    @api.doc(security="Bearer")
    @api.marshal_with(mod_detection_details)
    @token_required
    @user_has('update_detection')
    def put(self, uuid, current_user):
        '''
        Sets the detection rule as run complete and ready to run at the next run interval
        '''

        detection = Detection.get_by_uuid(uuid=uuid)
        detection.set_run_flag(flag=False)
        return detection


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