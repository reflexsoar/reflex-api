import json
import dateutil.parser

from flask_restx import Model, fields, reqparse
from opensearch_dsl import AttrDict


class NullableString(fields.String):
    ''' Returns a String or None '''
    __schema_type__ = ['string', 'null']
    __schema_example__ = 'string or null'

class AsAttrDict(fields.Raw):
    ''' Converts an AttrDict to a normal Dict'''

    def format(self, value):
        if isinstance(value, AttrDict):
            return value.to_dict()


class ISO8601(fields.Raw):
    ''' Returns a Python DateTime object in ISO8601 format with the Zulu time indicator '''

    __schema_example__ = '2019-01-01T00:00:00.000Z'
    __schema_type__ = 'string'

    def format(self, value):
        if isinstance(value, str):
            value = dateutil.parser.parse(value)
        return value.isoformat()+"Z"


class ValueCount(fields.Raw):
    ''' Returns the number of values in a list'''

    def format(self, value):
        return len(value)


class AsNewLineDelimited(fields.Raw):
    ''' Returns an array as a string delimited by new line characters '''

    def format(self, value):
        return '\n'.join(list(value))


class JSONField(fields.Raw):
    def format(self, value):
        return value


class ObservableCount(fields.Raw):
    ''' Returns the number of observables '''

    def format(self, value):
        return len(value)


class IOCCount(fields.Raw):
    ''' Returns the number of observables that are IOC '''

    def format(self, value):
        iocs = [o for o in value if 'ioc' in o and o['ioc'] is True]
        return len(iocs)


class FormatTags(fields.Raw):
    ''' Returns tags in a specific format for the API response'''

    def format(self, value):
        return [{'name': v} for v in value]


class AsDict(fields.Raw):
    def format(self, value):
        try:
            return json.loads(value)
        except:
            return value


mod_pagination = Model('Pagination', {
    'total_results': fields.Integer,
    'pages': fields.Integer,
    'page_size': fields.Integer,
    'page': fields.Integer
})

mod_data_type_list = Model('DataTypeList', {
    'uuid': fields.String,
    'name': fields.String,
    'description': fields.String,
    'regex': fields.String,
    'created_at': ISO8601(attribute='created_at'),
    'updated_at': ISO8601(attribute='updated_at')
})

mod_observable_list = Model('ObservableList', {
    'uuid': fields.String,
    'tags': fields.List(fields.String),
    'value': fields.String,
    'ioc': fields.Boolean,
    'tlp': fields.Integer,
    'spotted': fields.Boolean,
    'safe': fields.Boolean,
    'data_type': fields.String,
    'uuid': fields.String,
    'case': fields.String,
    'source_field': fields.String,
    'original_source_field': fields.String
})

mod_observable_list_paged = Model('PagedObservableList', {
    'observables': fields.List(fields.Nested(mod_observable_list)),
    'total_observables': fields.Integer,
    'pagination': fields.Nested(mod_pagination)
})

mod_observable_brief = Model('ShortObservableDetails', {
    'uuid': fields.String,
    'value': fields.String,
    'data_type': fields.String,
    'tags': fields.List(fields.String),
    'source_field': fields.String,
    'original_source_field': fields.String
})

mod_permissions = Model('Permissions', {
    'add_user': fields.Boolean,
    'update_user': fields.Boolean,
    'delete_user': fields.Boolean,
    'add_user_to_role': fields.Boolean,
    'remove_user_from_role': fields.Boolean,
    'reset_user_password': fields.Boolean,
    'unlock_user': fields.Boolean,
    'view_users': fields.Boolean,
    'add_role': fields.Boolean,
    'update_role': fields.Boolean,
    'delete_role': fields.Boolean,
    'set_role_permissions': fields.Boolean,
    'view_roles': fields.Boolean,
    'create_user_group': fields.Boolean,
    'view_user_groups': fields.Boolean,
    'update_user_groups': fields.Boolean,
    'delete_user_group': fields.Boolean,
    'create_event_rule': fields.Boolean,
    'add_event': fields.Boolean,
    'view_events': fields.Boolean,
    'view_case_events': fields.Boolean,
    'update_event': fields.Boolean,
    'delete_event': fields.Boolean,
    'view_event_rules': fields.Boolean,
    'update_event_rule': fields.Boolean,
    'delete_event_rule': fields.Boolean,
    'add_observable': fields.Boolean,
    'update_observable': fields.Boolean,
    'delete_observable': fields.Boolean,
    'add_tag_to_observable': fields.Boolean,
    'remove_tag_from_observable': fields.Boolean,
    'add_playbook': fields.Boolean,
    'update_playbook': fields.Boolean,
    'delete_playbook': fields.Boolean,
    'view_playbooks': fields.Boolean,
    'add_tag_to_playbook': fields.Boolean,
    'remove_tag_from_playbook': fields.Boolean,
    'view_agents': fields.Boolean,
    'update_agent': fields.Boolean,
    'delete_agent': fields.Boolean,
    'pair_agent': fields.Boolean,
    'add_agent_group': fields.Boolean,
    'view_agent_groups': fields.Boolean,
    'update_agent_group': fields.Boolean,
    'delete_agent_group': fields.Boolean,
    'create_agent_policy': fields.Boolean,
    'view_agent_policies': fields.Boolean,
    'update_agent_policy': fields.Boolean,
    'delete_agent_policy': fields.Boolean,
    'add_input': fields.Boolean,
    'view_inputs': fields.Boolean,
    'update_input': fields.Boolean,
    'delete_input': fields.Boolean,
    'add_tag': fields.Boolean,
    'update_tag': fields.Boolean,
    'delete_tag': fields.Boolean,
    'view_tags': fields.Boolean,
    'create_case': fields.Boolean,
    'view_cases': fields.Boolean,
    'update_case': fields.Boolean,
    'delete_case': fields.Boolean,
    'upload_case_files': fields.Boolean,
    'view_case_files': fields.Boolean,
    'delete_case_files': fields.Boolean,
    'create_case_task': fields.Boolean,
    'view_case_tasks': fields.Boolean,
    'update_case_task': fields.Boolean,
    'delete_case_task': fields.Boolean,
    'create_case_template': fields.Boolean,
    'view_case_templates': fields.Boolean,
    'update_case_template': fields.Boolean,
    'delete_case_template': fields.Boolean,
    'create_case_template_task': fields.Boolean,
    'view_case_template_tasks': fields.Boolean,
    'update_case_template_task': fields.Boolean,
    'delete_case_template_task': fields.Boolean,
    'create_case_comment': fields.Boolean,
    'view_case_comments': fields.Boolean,
    'update_case_comment': fields.Boolean,
    'delete_case_comment': fields.Boolean,
    'create_case_status': fields.Boolean,
    'update_case_status': fields.Boolean,
    'delete_case_status': fields.Boolean,
    'view_plugins': fields.Boolean,
    'create_plugin': fields.Boolean,
    'delete_plugin': fields.Boolean,
    'update_plugin': fields.Boolean,
    'add_credential': fields.Boolean,
    'update_credential': fields.Boolean,
    'decrypt_credential': fields.Boolean,
    'delete_credential': fields.Boolean,
    'view_credentials': fields.Boolean,
    'add_organization': fields.Boolean(optional=True),
    'view_organizations': fields.Boolean(optional=True),
    'update_organization': fields.Boolean(optional=True),
    'delete_organization': fields.Boolean(optional=True),
    'add_list': fields.Boolean,
    'update_list': fields.Boolean,
    'view_lists': fields.Boolean,
    'delete_list': fields.Boolean,
    'create_data_type': fields.Boolean,
    'update_data_type': fields.Boolean,
    'update_settings': fields.Boolean,
    'view_settings': fields.Boolean,
    'create_detection': fields.Boolean,
    'update_detection': fields.Boolean,
    'view_detections': fields.Boolean,
    'delete_detection': fields.Boolean,
    'create_notification_channel': fields.Boolean,
    'view_notification_channels': fields.Boolean,
    'update_notification_channel': fields.Boolean,
    'delete_notification_channel': fields.Boolean,
    'view_notifications': fields.Boolean,
    'create_persistent_pairing_token': fields.Boolean,
    'use_api': fields.Boolean(optional=True),
    'create_service_account': fields.Boolean,
    'view_service_accounts': fields.Boolean,
    'delete_service_account': fields.Boolean,
    'create_asset': fields.Boolean,
    'view_assets': fields.Boolean,
    'update_asset': fields.Boolean,
    'delete_asset': fields.Boolean,
    'create_detection_repository': fields.Boolean,
    'view_detection_repositories': fields.Boolean,
    'update_detection_repository': fields.Boolean,
    'delete_detection_repository': fields.Boolean,
    'share_detection_repository': fields.Boolean,
    'subscribe_detection_repository': fields.Boolean,
    'create_integration': fields.Boolean,
    'update_integration': fields.Boolean,
    'delete_integration': fields.Boolean,
    'view_integrations': fields.Boolean,
    'view_integration_configurations': fields.Boolean,
    'create_integration_configuration': fields.Boolean,
    'update_integration_configuration': fields.Boolean,
    'delete_integration_configuration': fields.Boolean,
    'create_sso_provider': fields.Boolean,
    'update_sso_provider': fields.Boolean,
    'delete_sso_provider': fields.Boolean,
    'view_sso_providers': fields.Boolean,
    'create_sso_mapping_policy': fields.Boolean,
    'update_sso_mapping_policy': fields.Boolean,
    'delete_sso_mapping_policy': fields.Boolean,
    'view_sso_mapping_policies': fields.Boolean,
    'create_package': fields.Boolean,
    'update_package': fields.Boolean,
    'delete_package': fields.Boolean,
    'view_packages': fields.Boolean,
    'create_data_source_template': fields.Boolean,
    'update_data_source_template': fields.Boolean,
    'delete_data_source_template': fields.Boolean,
    'view_data_source_templates': fields.Boolean,
    'view_fim_rules': fields.Boolean,
    'create_fim_rule': fields.Boolean,
    'update_fim_rule': fields.Boolean,
    'delete_fim_rule': fields.Boolean,
    'create_schedule': fields.Boolean,
    'update_schedule': fields.Boolean,
    'delete_schedule': fields.Boolean,
    'view_schedules': fields.Boolean,
    'view_benchmarks': fields.Boolean,
    'create_benchmark_rule': fields.Boolean,
    'update_benchmark_rule': fields.Boolean,
    'view_benchmark_rulesets': fields.Boolean,
    'create_benchmark_ruleset': fields.Boolean,
    'update_benchmark_ruleset': fields.Boolean,
    'delete_benchmark_ruleset': fields.Boolean,
    'view_benchmark_exceptions': fields.Boolean,
    'create_benchmark_exclusion': fields.Boolean,
    'update_benchmark_exclusion': fields.Boolean,
    'delete_benchmark_exclusion': fields.Boolean,
    'create_benchmark_result': fields.Boolean,
    'view_agent_tags': fields.Boolean,
    'create_agent_tag': fields.Boolean,
    'update_agent_tag': fields.Boolean,
    'delete_agent_tag': fields.Boolean
}, strict=True)

mod_user_list = Model('UserList', {
    'username': fields.String,
    'uuid': fields.String,
    'organization': fields.String
})



DEFAULT_ORG_ONLY_PERMISSIONS = [
    'create_service_account',
    'view_service_accounts',
    'delete_service_account'
    'update_service_account'
]

pager_parser = reqparse.RequestParser()
pager_parser.add_argument('page_size', location='args',
                          required=False, type=int, default=25)
pager_parser.add_argument('page', location='args',
                          required=False, type=int, default=1)