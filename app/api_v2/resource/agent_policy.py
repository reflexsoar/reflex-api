import datetime
from flask import request
from flask_restx import Resource, Namespace, fields, inputs as xinputs
from ..model import (
    Agent,
    Settings,
    Role,
    AgentGroup,
    ExpiredToken
)
from .shared import FormatTags, mod_pagination, ISO8601, mod_user_list
from .utils import redistribute_detections
from ..utils import check_org, token_required, user_has, ip_approved, page_results, generate_token, default_org
from .agent_group import mod_agent_group_list
from ..schemas import mod_input_list

api = Namespace(
    'Agent Policy', description='Agent Policy administration', path='/agent_policy', strict=True)


mod_runner_config = api.model('RunnerRoleConfig', {
    'concurrent_actions': fields.Integer,
    'graceful_exit': fields.Boolean,
    'wait_interval': fields.Integer,
    'plugin_poll_interval': fields.Integer,
    'logging_level': fields.String,
})

mod_detector_config = api.model('DetectorRoleConfig', {
    'concurrent_rules': fields.Integer,
    'graceful_exit': fields.Boolean,
    'catchup_period': fields.Integer,
    'wait_interval': fields.Integer,
    'max_threshold_events': fields.Integer,
    'logging_level': fields.String
})

mod_poller_config = api.model('PollerRoleConfig', {
    'concurrent_inputs': fields.Integer,
    'graceful_exit': fields.Boolean,
    'logging_level': fields.String,
    'max_input_attempts': fields.Integer,
    'signature_cache_ttl': fields.Integer,
})

mod_agent_policy = api.model('AgentPolicy', {
name
roles
health_check_interval
logging_level
max_intel_db_size
disable_event_cache_check
event_realert_ttl
poller_config
detector_config
runner_config
tags
priority
})
