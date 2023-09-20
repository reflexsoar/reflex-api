from app.api_v2.model import MITRETactic, MITRETechnique, Q, Detection
from flask import request
from flask_restx import Resource, Namespace, fields, inputs as xinputs
from .shared import mod_pagination
from ..utils import page_results, token_required, user_has


api = Namespace(
    'MITRE', description='MITRE ATT&CK related information', path='/mitre')

mod_data_sources = api.model('MITREDataSources', {
    'data_sources': fields.List(fields.String)
})

mod_external_reference = api.model('MITREExternalReference', {
    'external_id': fields.String,
    'url': fields.String,
    'source_name': fields.String
})

mod_kill_chain_phase = api.model('MITREKillChainPhase', {
    'kill_chain_name': fields.String,
    'phase_name': fields.String
})

mod_tactic_details = api.model('MITRETactic', {
    'uuid': fields.String,
    'mitre_id': fields.String,
    'external_id': fields.String,
    'name': fields.String,
    'shortname': fields.String,
    'description': fields.String,
    'external_references': fields.List(fields.Nested(mod_external_reference))
})

mod_tactic_brief = api.model('MITRETacticBrief', {
    'mitre_id': fields.String,
    'external_id': fields.String,
    'name': fields.String,
    'shortname': fields.String
})

mod_technique_details = api.model('MITRETechnique', {
    'uuid': fields.String,
    'mitre_id': fields.String,
    'external_id': fields.String,
    'external_id_parent': fields.String,
    'has_subs': fields.Boolean,
    'is_sub': fields.Boolean(attribute='is_sub_technique'),
    'is_deprecated': fields.Boolean,
    'name': fields.String,
    'shortname': fields.String,
    'description': fields.String,
    'external_references': fields.List(fields.Nested(mod_external_reference)),
    'phase_names': fields.List(fields.String),
    'kill_chain_phases': fields.List(fields.Nested(mod_kill_chain_phase)),
    'data_sources': fields.List(fields.String)
})

mod_technique_brief = api.model('MITRETechniqueBrief', {
    'mitre_id': fields.String,
    'external_id': fields.String,
    'name': fields.String,
    'shortname': fields.String
})

mod_tactics_paged = api.model('MITRETacticPaged', {
    'tactics': fields.List(fields.Nested(mod_tactic_details)),
    'pagination': fields.Nested(mod_pagination)
})

mod_techniques_paged = api.model('MITRETechniquePaged', {
    'techniques': fields.List(fields.Nested(mod_technique_details)),
    'pagination': fields.Nested(mod_pagination)
})

tactic_list_parser = api.parser()
tactic_list_parser.add_argument('name__like', location='args', type=str, required=False)

tactic_list_parser.add_argument('external_id__like', location='args', type=str, required=False)
tactic_list_parser.add_argument(
    'page', type=int, location='args', default=1, required=False)
tactic_list_parser.add_argument(
    'page_size', type=int, location='args', default=25, required=False)


@api.route("/tactic")
class TacticList(Resource):

    @api.doc(security="Bearer")
    @api.marshal_with(mod_tactics_paged)
    @api.expect(tactic_list_parser)
    @token_required
    def get(self, current_user):
        '''
        Returns a list of MITRE ATT&CK Tactics
        '''

        total_results = 0
        pages = 0

        args = tactic_list_parser.parse_args()
        
        search = MITRETactic.search()
        
        if args.name__like and not args.external_id__like:
            search = search.filter('wildcard', name=f"{args.name__like}*")

        if args.external_id__like and not args.name__like:
            search = search.filter('wildcard', external_id=f"{args.external_id__like.upper()}*")

        if args.name__like and args.external_id__like:
            search = search.filter('bool', should=[Q('wildcard', external_id=f"{args.external_id__like.upper()}*"), Q('wildcard', name=f"*{args.name__like}*")])

        # Sort by external_id
        search = search.sort('external_id')

        search, total_results, pages = page_results(search, args.page, args.page_size)
        tactics = search.execute()

        return {
            'tactics': list(tactics),
            'pagination': {
                'total_results': total_results,
                'pages': pages,
                'page': args.page,
                'page_size': args.page_size
            }
        }

technique_list_parser = api.parser()
technique_list_parser.add_argument('name__like', location='args', type=str, required=False)
technique_list_parser.add_argument('external_id', location='args', type=str, required=False)
technique_list_parser.add_argument('external_id__like', location='args', type=str, required=False)
technique_list_parser.add_argument('phase_names', location='args', required=False, type=str, action='split')
technique_list_parser.add_argument(
    'page', type=int, location='args', default=1, required=False)
technique_list_parser.add_argument(
    'page_size', type=int, location='args', default=25, required=False)
technique_list_parser.add_argument(
    'show_revoked', type=xinputs.boolean, location='args', default=False, required=False
)

@api.route("/technique")
class TechniqueList(Resource):

    @api.doc(security="Bearer")
    @api.marshal_with(mod_techniques_paged)
    @api.expect(technique_list_parser)
    @token_required
    def get(self, current_user):
        '''
        Returns a list of MITRE ATT&CK Tactics
        '''

        total_results = 0
        pages = 0

        args = technique_list_parser.parse_args()
        
        search = MITRETechnique.search()

        if args.external_id:
            search = search.filter('term', external_id=args.external_id)

        if args.name__like and not args.external_id__like:
            search = search.filter('wildcard', name=f"{args.name__like}*")

        if args.external_id__like and not args.name__like:
            search = search.filter('wildcard', external_id=f"{args.external_id__like.upper()}*")

        if args.name__like and args.external_id__like:
            search = search.filter('bool', should=[Q('wildcard', external_id=f"{args.external_id__like.upper()}*"), Q('wildcard', name=f"*{args.name__like}*")])

        if args.phase_names and len(args.phase_names) > 0 and args.phase_names != ['']:
            search = search.filter('terms', phase_names=args.phase_names)


        if args.show_revoked:
            search = search.filter('terms', is_revoked=[True, False])
        else:
            search = search.filter('term', is_revoked=False)

        # Sort by external_id
        search = search.sort('external_id')

        search, total_results, pages = page_results(search, args.page, args.page_size)
        techniques = search.execute()

        # Create a map of the number of times a techniques external_id_parent appears
        # in the results.  This will be used to determine if a technique has sub-techniques
        # or not.
        technique_counts = {}

        for technique in techniques:
            if technique.external_id_parent not in technique_counts:
                technique_counts[technique.external_id_parent] = 0
            technique_counts[technique.external_id_parent] += 1

        # Loop through the techniques and set the has_subs property
        for technique in techniques:
            technique.has_subs = technique_counts.get(technique.external_id, 0) > 1
        
        return {
            'techniques': list(techniques),
            'pagination': {
                'total_results': total_results,
                'pages': pages,
                'page': args.page,
                'page_size': args.page_size
            }
        }

@api.route("/data_sources")
class DataSourceList(Resource):

    @api.doc(security="Bearer")
    @api.marshal_with(mod_data_sources)
    @token_required
    def get(self, current_user):
        '''
        Returns a list of MITRE ATT&CK Data Sources
        '''
        
        search = MITRETechnique.search()
        search = search[0:]
        search.aggs.bucket('data_sources', 'terms', field='data_sources', size=1000)

        results = search.execute()
        return {'data_sources': [bucket.key for bucket in results.aggregations.data_sources.buckets]}
    

detection_list_parser = api.parser()
detection_list_parser.add_argument('organization', location='args', type=str, required=False)

@api.route("/detections")
class DetectionList(Resource):

    @api.doc(security="Bearer")
    @api.expect(detection_list_parser)
    @token_required
    @user_has("view_detections")
    def get(self, current_user):
        '''
        Returns a list of techniques with the UUIDs of all the detections
        that map to them.
        '''

        args = detection_list_parser.parse_args()

        search = Detection.search()

        if args.organization:
            if not current_user.is_default_org():
                search = search.filter('term', organization=current_user.organization)
            else:
                search = search.filter('term', organization=args.organization)

        # Count the number of detections per techniques.external_id.  techniques.external_id is
        # nested under techniques
        search.aggs.bucket('techniques', 'nested', path='techniques').bucket('external_ids', 'terms', field='techniques.external_id', size=10000)
        search.aggs.bucket('active', 'filter', filter={'term': {'active': True}}).bucket('techniques', 'nested', path='techniques').bucket('external_ids', 'terms', field='techniques.external_id', size=10000)

        # Set the size to 0 so we don't return any hits
        search = search[0:0]

        # Return the results
        results = search.execute()

        # Create a dictionary of technique.external_id to detection UUIDs
        detection_mapping = {
            'techniques': {}
        }

        technique_active_total = {}
        # Create a lookup dictionary of the external_id and the count of active detections
        for bucket in results.aggregations.active.techniques.external_ids.buckets:
            technique_active_total[bucket.key] = bucket.doc_count
        
        for bucket in results.aggregations.techniques.external_ids.buckets:
            #detection_mapping['techniques'].append({
            #    'external_id': bucket.key,
            #    'count': bucket.doc_count
            #})
            detection_mapping['techniques'][bucket.key] = {
                'total': bucket.doc_count,
                'active': technique_active_total.get(bucket.key, 0)
            }

        return detection_mapping

        

