import datetime
from flask import request
from flask_restx import Resource, Namespace, fields, inputs as xinputs

from app.api_v2.model.agent import AgentGroup, AgentPolicy
from .shared import FormatTags, mod_pagination, ISO8601, mod_user_list
from .utils import redistribute_detections
from ..utils import check_org, token_required, user_has, ip_approved, page_results, generate_token, default_org
from .agent_group import mod_agent_group_list
from ..schemas import mod_input_list

api = Namespace(
    'Agent Policy', description='Agent Policy administration', path='/agent_policy', strict=True)


mod_runner_config = api.model('RunnerRoleConfig', {
    'concurrent_actions': fields.Integer(default=10),
    'graceful_exit': fields.Boolean(default=True),
    'wait_interval': fields.Integer(default=30),
    'plugin_poll_interval': fields.Integer(default=30),
    'logging_level': fields.String(default='ERROR'),
})

mod_detector_config = api.model('DetectorRoleConfig', {
    'concurrent_rules': fields.Integer(default=10),
    'graceful_exit': fields.Boolean(default=True),
    'catchup_period': fields.Integer(default=60),
    'wait_interval': fields.Integer(default=30),
    'max_threshold_events': fields.Integer(default=1000),
    'logging_level': fields.String(default='ERROR')
})

mod_poller_config = api.model('PollerRoleConfig', {
    'concurrent_inputs': fields.Integer(default=5),
    'graceful_exit': fields.Boolean(default=True),
    'logging_level': fields.String(default='ERROR'),
    'max_input_attempts': fields.Integer(default=3),
    'signature_cache_ttl': fields.Integer(default=3600),
})

mod_agent_policy = api.model('AgentPolicy', {
    'name': fields.String,
    'organization': fields.String,
    'description': fields.String,
    'roles': fields.List(fields.String, default=['runner', 'detector', 'poller']),
    'health_check_interval': fields.Integer,
    'logging_level': fields.String(default='ERROR'),
    'max_intel_db_size': fields.Integer,
    'disable_event_cache_check': fields.Boolean(default=False),
    'event_realert_ttl': fields.Integer(default=3600),
    'poller_config': fields.Nested(mod_poller_config),
    'detector_config': fields.Nested(mod_detector_config),
    'runner_config': fields.Nested(mod_runner_config),
    'tags': fields.List(fields.String, default=[]),
    'priority': fields.Integer(default=1)
}, strict=True)

mod_agent_policy_detailed = api.clone('AgentPolicyDetailed', mod_agent_policy, {
    'uuid': fields.String,
    'revision': fields.Integer,
    'created_at': ISO8601,
    'updated_at': ISO8601,
    'created_by': fields.Nested(mod_user_list),
    'updated_by': fields.Nested(mod_user_list)
})

mod_agent_policy_list = api.model('AgentPolicyList', {
    'policies': fields.List(fields.Nested(mod_agent_policy_detailed)),
    'pagination': fields.Nested(mod_pagination)
})


policy_list_parser = api.parser()
policy_list_parser.add_argument('organization', location='args', required=False)
policy_list_parser.add_argument(
    'page', type=int, location='args', default=1, required=False)
policy_list_parser.add_argument(
    'page_size', type=int, location='args', default=10, required=False)
policy_list_parser.add_argument(
    'sort_by', type=str, location='args', default='created_at', required=False
)
policy_list_parser.add_argument(
    'sort_direction', type=str, location='args', default='desc', required=False
)

@api.route("/<uuid>")
class AgentPolicyDetails(Resource):

    @api.doc(security="Bearer")
    @api.expect(mod_agent_policy, validate=True)
    @api.marshal_with(mod_agent_policy_detailed)
    @token_required
    @default_org
    @check_org
    @user_has('update_agent_policy')
    def put(self, uuid, user_in_default_org, current_user):

        policy = None
        import json
        print(json.dumps(request.json))
        if user_in_default_org:
            policy = AgentPolicy.get_by_uuid(uuid)
        else:
            policy = AgentPolicy.get_by_uuid(uuid, current_user.organization)

        if policy:

            existing_policy = None
            if 'name' in api.payload:
                
                if user_in_default_org:
                    if 'organization' in api.payload:
                        existing_policy = AgentPolicy.get_by_name(api.payload['name'], api.payload['organization'])
                    else:
                        existing_policy = AgentPolicy.get_by_name(api.payload['name'], policy.organization)
                else:
                    existing_policy = AgentPolicy.get_by_name(api.payload['name'], current_user.organization)

            if existing_policy and existing_policy.uuid != policy.uuid and existing_policy.name == api.payload['name']:
                api.abort(409, f"Agent policy with name {api.payload['name']} already exists")

            if 'organization' in api.payload and api.payload['organization'] != policy.organization:
                agent_group = AgentGroup.get_by_policy(policy.uuid)
                if agent_group:
                    api.abort(400, f"Unable to move policy to different organization. Policy is currently assigned to agent group {agent_group.name}")
            
            policy.update(**api.payload)
            return policy
            
        else:
            api.abort(400, f"Agent policy with uuid {uuid} does not exist")

@api.route("")
class AgentPolicyList(Resource):

    @api.doc(security="Bearer")
    @api.expect(mod_agent_policy)
    @api.marshal_with(mod_agent_policy_detailed)
    @token_required
    @default_org
    @check_org
    @user_has('create_agent_policy')
    def post(self, user_in_default_org, current_user):

        policy = AgentPolicy(**api.payload)
        policy.revision = 1
        policy.save()
        return policy


    @api.doc(security="Bearer")
    @api.marshal_with(mod_agent_policy_list)
    @api.expect(policy_list_parser)
    @token_required
    @default_org
    @user_has('view_agent_policies')
    def get(self, user_in_default_org, current_user):

        args = policy_list_parser.parse_args()

        policies = AgentPolicy.search()

        if user_in_default_org:
            if args.organization:
                policies = policies.filter('term', organization=args.organization)

        sort_by = args.sort_by
        if sort_by not in ['name']:
            sort_by = 'created_at'

        if args.sort_direction == 'desc':
            sort_by = f"-{sort_by}"

        policies = policies.sort(sort_by)

        policies, total_results, pages = page_results(policies, args.page, args.page_size)

        return {
            'policies': list(policies),
            'pagination': {
                'total_results': total_results,
                'pages': pages,
                'page': args.page,
                'page_size': args.page_size
            }
        }

        
        