from app.api_v2.model import MITRETactic, MITRETechnique, Q
from flask import request
from flask_restx import Resource, Namespace, fields, inputs as xinputs
from .shared import mod_pagination
from ..utils import page_results, token_required


api = Namespace(
    'MITRE', description='MITRE ATT&CK related information', path='/mitre')


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
            search = search.filter('bool', should=[Q('wildcard', external_id__keyword=f"{args.external_id__like.upper()}*"), Q('wildcard', name=f"*{args.name__like}*")])


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
            search = search.filter('term', external_id__keyword=args.external_id)

        if args.name__like and not args.external_id__like:
            search = search.filter('wildcard', name=f"{args.name__like}*")

        if args.external_id__like and not args.name__like:
            search = search.filter('wildcard', external_id__keyword=f"{args.external_id__like.upper()}*")

        if args.name__like and args.external_id__like:
            search = search.filter('bool', should=[Q('wildcard', external_id__keyword=f"{args.external_id__like.upper()}*"), Q('wildcard', name=f"*{args.name__like}*")])

        if args.phase_names and len(args.phase_names) > 0 and args.phase_names != ['']:
            search = search.filter('terms', phase_names=args.phase_names)

        import json
        print(json.dumps(search.to_dict(), indent=2))

        search, total_results, pages = page_results(search, args.page, args.page_size)
        techniques = search.execute()

        return {
            'techniques': list(techniques),
            'pagination': {
                'total_results': total_results,
                'pages': pages,
                'page': args.page,
                'page_size': args.page_size
            }
        }
