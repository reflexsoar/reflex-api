"""
./app/api_v2/schemas.py

Contains all marshal schemas for API responses and inputs
"""

import json
from flask_restx import Model, fields

class AsDict(fields.Raw):
    def format(self, value):
        try:
            return json.loads(value)
        except:
            return value

class JSONField(fields.Raw):
    def format(self, value):
        return value

class ObservableCount(fields.Raw):
    ''' Returns the number of observables '''
    def format(self, value):
        return len(value)

class ValueCount(fields.Raw):
    ''' Returns the number of values in a list'''
    def format(self, value):
        return len(value)

class IOCCount(fields.Raw):
    ''' Returns the number of observables that are IOC '''

    def format(self, value):
        iocs = [o for o in value if 'ioc' in o and o['ioc'] is True]
        return len(iocs)

class ISO8601(fields.Raw):
    ''' Returns a Python DateTime object in ISO8601 format with the Zulu time indicator '''
    def format(self, value):
        return value.isoformat()+"Z"

class AsNewLineDelimited(fields.Raw):
    ''' Returns an array as a string delimited by new line characters '''
    def format(self, value):
        return '\n'.join(list(value))

class FormatTags(fields.Raw):
    ''' Returns tags in a specific format for the API response'''

    def format(self, value):
        return [{'name': v} for v in value]

class EventStatusName(fields.Raw):
    ''' Returns a final value from the source value '''
    def format(self, value):
        return value['name']

mod_pagination = Model('Pagination', {
    'total_results': fields.Integer,
    'pages': fields.Integer,
    'page_size': fields.Integer,
    'page': fields.Integer
})

mod_auth = Model('AuthModel', {
    'email': fields.String(default='admin@reflexsoar.com'),
    'password': fields.String(default='reflex')
})

mod_auth_success_token = Model('AuthSuccessToken', {
    'access_token': fields.String
})

mod_refresh_token = Model('RefreshToken', {
    'refresh_token': fields.String
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
    'add_organization': fields.Boolean,
    'view_organizations': fields.Boolean,
    'update_organization': fields.Boolean,
    'delete_organization': fields.Boolean,
    'add_list': fields.Boolean,
    'update_list': fields.Boolean,
    'view_lists': fields.Boolean,
    'delete_list': fields.Boolean,
    'create_data_type': fields.Boolean,
    'update_data_type': fields.Boolean,
    'update_settings': fields.Boolean,
    'view_settings': fields.Boolean,
    'create_persistent_pairing_token': fields.Boolean,
    'use_api': fields.Boolean
})

mod_role_create = Model('RoleCreate', {
    'name': fields.String,
    'description': fields.String,
    'permissions': fields.Nested(mod_permissions)
})

mod_user_list = Model('UserList', {
    'username': fields.String,
    'uuid': fields.String
})

mod_user_role = Model('UserRole', {
    'uuid': fields.String,
    'name': fields.String
})

mod_user_role_no_members = Model('UserRole', {
    'uuid': fields.String,
    'permissions': fields.Nested(mod_permissions),
    'name': fields.String,
    'description': fields.String
})

mod_user_role_no_perms = Model('UserRoleNoPerms', {
    'uuid': fields.String,
    'name': fields.String,
    'description': fields.String
})

mod_user_brief = Model('UserBrief', {
    'uuid': fields.String,
    'username': fields.String,
    'email': fields.String,
    'first_name': fields.String,
    'last_name': fields.String
})

mod_role_list = Model('Role', {
    'uuid': fields.String,
    'name': fields.String,
    'description': fields.String,
    'members': fields.List(fields.String),
    'permissions': fields.Nested(mod_permissions)
})

mod_user_full = Model('UserFull', {
    'uuid': fields.String,
    'organization': fields.String,
    'username': fields.String,
    'email': fields.String,
    'first_name': fields.String,
    'last_name': fields.String,
    'last_logon': ISO8601(attribute='last_logon'),
    'locked': fields.Boolean,
    'mfa_enabled': fields.Boolean,
    'failed_logons': fields.Integer,
    'disabled': fields.Boolean,
    'created_at': ISO8601(attribute='created_at'),
    'updated_at': ISO8601(attribute='updated_at'),
    'role': fields.Nested(mod_user_role_no_perms)
})

mod_user_create_success = Model('UserCreateSuccess', {
    'message': fields.String,
    'user': fields.Nested(mod_user_full)
})

mod_user_create = Model('UserCreate', {
    'username': fields.String,
    'email': fields.String,
    'password': fields.String,
    'first_name': fields.String,
    'last_name': fields.String,
    'locked': fields.Boolean
})

mod_api_key = Model('UserApiKey', {
    'api_key': fields.String
})

mod_toggle_user_mfa = Model('UserUUIDs', {
    'users': fields.List(fields.String),
    'mfa_enabled': fields.Boolean
})

mod_user_self = Model('UserSelf', {
    'uuid': fields.String,
    'username': fields.String,
    'first_name': fields.String,
    'last_name': fields.String,
    'email': fields.String,
    'role': fields.Nested(mod_user_role_no_members),
    'mfa_enabled': fields.Boolean,
    'default_org': fields.Boolean
})

mod_tag_list = Model('TagList', {
    'uuid': fields.String,
    'name': fields.String
})

mod_tag = Model('Tag', {
    'name': fields.String
})

mod_plugin_create = Model('PluginCreate', {
    "name": fields.String,
    "description": fields.String,
    "filename": fields.String,
    "file_hash": fields.String
})

mod_plugin_name = Model('PluginDetailsLimited', {
    "name": fields.String
})

mod_plugin_config_list = Model('PluginConfigList', {
    "name": fields.String,
    "description": fields.String,
    "plugin": fields.Nested(mod_plugin_name),
    "plugin_uuid": fields.String,
    "config": fields.String,
    'created_at': ISO8601(attribute='created_at'),
    'modified_at': ISO8601(attribute='modified_at')

})

mod_plugin_manifest_action = Model('PluginManifestAction', {
    "name": fields.String,
    "used_by": fields.List(fields.String),
    "description": fields.String
})

mod_plugin_manifest = Model('PluginManifest', {
    "actions": fields.List(fields.Nested(mod_plugin_manifest_action)),
    "description": fields.String,
    "name": fields.String,
    "config_template": fields.String
})

mod_plugin_list = Model('PluginList', {
    "uuid": fields.String,
    "name": fields.String,
    "logo": fields.String,
    "description": fields.String,
    "enabled": fields.Boolean,
    "manifest": fields.Nested(mod_plugin_manifest),
    #"config_template": JSONField,
    "filename": fields.String,
    "file_hash": fields.String,
    'created_at': ISO8601(attribute='created_at'),
    'modified_at': ISO8601(attribute='modified_at'),
    "configs": fields.List(fields.Nested(mod_plugin_config_list))
})

mod_observable_create = Model('ObservableCreate', {
    'value': fields.String(required=True),
    'ioc': fields.Boolean,
    'tlp': fields.Integer,
    'spotted': fields.Boolean,
    'safe': fields.Boolean,
    'data_type': fields.String(required=True),
    'tags': fields.List(fields.String),
    'source_field': fields.String,
    'original_source_field': fields.String
})

mod_observable_update = Model('ObservableUpdate', {
    'tags': fields.List(fields.String),
    'ioc': fields.Boolean,
    'tlp': fields.Integer,
    'spotted': fields.Boolean,
    'safe': fields.Boolean,
    'data_type': fields.String
})

mod_observable_list = Model('ObservableList', {
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
    'pagination': fields.Nested(mod_pagination)
})

mod_bulk_add_observables = Model('BulkObservables', {
    'observables': fields.List(fields.Nested(mod_observable_create))
})

mod_observable_brief = Model('ShortObservableDetails', {
    'uuid': fields.String,
    'value': fields.String,
    'data_type': fields.String,
    'tags': fields.List(fields.String),
    'source_field': fields.String,
    'original_source_field': fields.String
})

mod_raw_log = Model('RawLog', {
    'source_log': fields.String
})

mod_event_status = Model('EventStatusString', {
    'name': fields.String,
    'closed': fields.Boolean
})

mod_event_create = Model('EventCreate', {
    'title': fields.String(required=True),
    'reference': fields.String(required=True),
    'description': fields.String(required=True),
    'tags': fields.List(fields.String),
    'tlp': fields.Integer,
    'severity': fields.Integer,
    'source': fields.String,
    'signature': fields.String,
    'observables': fields.List(fields.Nested(mod_observable_create)),
    'raw_log': fields.String
})

mod_event_list = Model('EventList', {
    'uuid': fields.String,
    'title': fields.String(required=True),
    'reference': fields.String(required=True),
    'description': fields.String(required=True),
    'tlp': fields.Integer,
    'severity': fields.Integer,
    'status': fields.Nested(mod_event_status),
    'source': fields.String,
    #'tags': fields.List(fields.Nested(mod_tag_list), attribute='_tags'),
    #'observables': fields.List(fields.Nested(mod_observable_brief)),
    'tags': fields.List(fields.String),
    #'observables': fields.List(fields.Nested(mod_observable_brief)),
    #'observable_count': ObservableCount(attribute='observables'),
    #'ioc_count': IOCCount(attribute='observables'),
    'created_at': ISO8601(attribute='created_at'),
    'updated_at': ISO8601(attribute='updated_at'),
    'case': fields.String,
    'signature': fields.String,
    'related_events_count': fields.Integer,
    #'related_events_count': ValueCount(attribute='related_events'),
    #'related_events': fields.List(fields.String),
    #'dismiss_reason': fields.Nested(mod_close_reason_list)
    'raw_log': fields.Nested(mod_raw_log, attribute='_raw_log')
})

mod_event_paged_list = Model('PagedEventList', {
   'events': fields.List(fields.Nested(mod_event_list)),
   'observables': JSONField,
   'pagination': fields.Nested(mod_pagination)
})

mod_related_events = Model('RelatedEvents', {
    'events': fields.List(fields.String)
})

mod_event_create_bulk = Model('EventCreateBulk', {
    'events': fields.List(fields.Nested(mod_event_create))
})

mod_event_bulk_dismiss = Model('EventBulkDismiss', {
    'events': fields.List(fields.String),
    'dismiss_reason_uuid': fields.String,
    'dismiss_comment': fields.String,
})

mod_event_details = Model('EventDetails', {
    'uuid': fields.String,
    'title': fields.String(required=True),
    'reference': fields.String(required=True),
    'description': fields.String(required=True),
    'tlp': fields.Integer,
    'severity': fields.Integer,
    'status': fields.Nested(mod_event_status),
    'source': fields.String,
    'tags': fields.List(fields.String),
    'observables': fields.List(fields.Nested(mod_observable_list)),
    'observable_count': ObservableCount(attribute='observables'),
    'ioc_count': IOCCount(attribute='observables'),
    #'dismiss_reason': fields.Nested(mod_close_reason_list),
    'case': fields.String,
    'created_at': ISO8601(attribute='created_at'),
    'modified_at': ISO8601(attribute='updated_at'),
    'raw_log': fields.String,
    'signature': fields.String,
    'dismiss_reason': fields.String,
    'dismiss_comment': fields.String
})


mod_event_rql = Model('EventDetailsRQLFormatted', {
    'uuid': fields.String,
    'title': fields.String(required=True),
    'reference': fields.String(required=True),
    'description': fields.String(required=True),
    'tlp': fields.Integer,
    'severity': fields.Integer,
    'source': fields.String,
    'status': fields.Nested(mod_event_status),
    'tags': fields.List(fields.String),
    'observables': fields.List(fields.Nested(mod_observable_list)),
    'case': fields.String,
    'created_at': ISO8601(attribute='created_at'),
    'modified_at': ISO8601(attribute='updated_at'),
    'raw_log': AsDict,
    'signature': fields.String
})

mod_event_rql_list = Model('EventDetailsListRQLFormatted', {
    'events': fields.List(fields.Nested(mod_event_rql))
})

mod_settings = Model('SettingsList', {
    'base_url': fields.String,
    'require_case_templates': fields.Boolean,
    'allow_comment_deletion': fields.Boolean,
    'email_from': fields.String,
    'email_server': fields.String,
    'email_secret_uuid': fields.String,
    'playbook_action_timeout': fields.Integer,
    'playbook_timeout': fields.Integer,
    'logon_password_attempts': fields.Integer,
    'api_key_valid_days': fields.Integer,
    'agent_pairing_token_valid_minutes': fields.Integer,
    'persistent_pairing_token': fields.String,
    'require_event_dismiss_comment': fields.Boolean,
    'require_case_close_comment': fields.Boolean,
    'allow_event_deletion': fields.Boolean,
    'assign_case_on_create': fields.Boolean,
    'assign_task_on_start': fields.Boolean,
    'allow_comment_editing': fields.Boolean,
    'events_page_refresh': fields.Integer,
    'events_per_page': fields.Integer,
    'data_types': fields.List(fields.String),
    'require_approved_ips': fields.Boolean,
    'approved_ips': AsNewLineDelimited(),
    'require_mfa': fields.Boolean,
    'minimum_password_length': fields.Integer,
    'enforce_password_complexity': fields.Boolean,
    'disallowed_password_keywords': AsNewLineDelimited()
})

mod_persistent_pairing_token = Model('PeristentPairingToken', {
    'token': fields.String
})

mod_credential_create = Model('CredentialCreate', {
    'username': fields.String(required=True),
    'secret': fields.String(required=True),
    'name': fields.String(required=True),
    'description': fields.String(required=True)
})

mod_credential_update = Model('CredentialUpdate', {
    'username': fields.String,
    'secret': fields.String,
    'name': fields.String,
    'description': fields.String
})

mod_credential_full = Model('Credential', {
    'uuid': fields.String,
    'username': fields.String,
    'name': fields.String,
    'description': fields.String
})

mod_credential_list = Model('CredentialLIst', {
    'uuid': fields.String,
    'name': fields.String,
    'username': fields.String,
    'description': fields.String
})

mod_credential_return = Model('CredentialReturn', {
    'secret': fields.String
})

mod_input_list = Model('InputList', {
    'uuid': fields.String,
    'organization': fields.String,
    'name': fields.String,
    'plugin': fields.String,
    'description': fields.String,
    'enabled': fields.Boolean,
    'credential': fields.String,
    'tags': fields.List(fields.String),
    'config': JSONField(attribute="_config"),
    'field_mapping': JSONField(attribute="_field_mapping"),
    'created_at': ISO8601(attribute='created_at'),
    'updated_at': ISO8601(attribute='updated_at')
})

mod_input_create = Model('CreateInput', {
    'name': fields.String,
    'organization': fields.String,
    'description': fields.String,
    'plugin': fields.String,
    'enabled': fields.Boolean,
    'credential': fields.String(required=True),
    'tags': fields.List(fields.String),
    'config': fields.String,
    'field_mapping': fields.String
})


mod_agent_create = Model('AgentCreate', {
    'name': fields.String,
    'roles': fields.List(fields.String),
    'ip_address': fields.String,
    'inputs': fields.List(fields.String)
})

mod_agent_list = Model('AgentList', {
    'uuid': fields.String,
    'name': fields.String,
    'inputs': fields.List(fields.Nested(mod_input_list), attribute="_inputs"),
    'roles': fields.List(fields.String),
    'groups': fields.List(fields.String),
    'active': fields.Boolean,
    'ip_address': fields.String,
    'last_heartbeat': ISO8601(attribute='last_heartbeat')
})

mod_agent_group_list = Model('AgentGroupList', {
    'uuid': fields.String,
    'name': fields.String,
    'description': fields.String
})

mod_paged_agent_group_list = Model('PagedAgentGroupList', {
    'groups': fields.List(fields.Nested(mod_agent_group_list)),
    'pagination': fields.Nested(mod_pagination)
})

mod_agent_group_create = Model('AgentGroupList', {
    'uuid': fields.String,
    'name': fields.String,
    'description': fields.String
})

mod_data_type_list = Model('DataTypeList', {
    'uuid': fields.String,
    'name': fields.String,
    'description': fields.String,
    'regex': fields.String,
    'created_at': ISO8601(attribute='created_at'),
    'updated_at': ISO8601(attribute='updated_at')
})

mod_data_type_create = Model('CreateDataType', {
    'name': fields.String,
    'description': fields.String,
    'regex': fields.String
})

mod_add_events_to_case = Model('AddEventsToCase', {
    'events': fields.List(fields.String)
})

mod_response_message = Model('ResponseMessage', {
    'message': fields.String
})

mod_add_events_response = Model('AddEventsToCaseResponse', {
    'results': fields.List(fields.Nested(mod_response_message)),
    'success': fields.Boolean,
    #'case': fields.Nested(mod_case_full)
})

mod_list_list = Model('ListView', {
    'uuid': fields.String,
    'name': fields.String,
    'list_type': fields.String,
    'tag_on_match': fields.Boolean,
    'data_type': fields.Nested(mod_data_type_list),
    'url': fields.String,
    'poll_interval': fields.Integer,
    'last_polled': ISO8601(attribute='last_polled'),
    'values': AsNewLineDelimited(attribute='values'),
    #'values_list': fields.List(fields.String, attribute='values'),
    'active': fields.Boolean,
    'value_count': ValueCount(attribute='values'),
    'created_at': ISO8601(attribute='created_at'),
    'updated_at': ISO8601(attribute='updated_at')
})

mod_list_create = Model('ListCreate', {
    'name': fields.String(required=True, example='SpamHaus eDROP'),
    'list_type': fields.String(required=True, example='values'),
    'tag_on_match': fields.Boolean(example=False),
    'data_type_uuid': fields.String(required=True),
    'values': fields.String(example='127.0.0.1\n4.4.4.4\n1.1.1.1'),
    'polling_interval': fields.Integer(example=3600),
    'url': fields.Url(description='A URL to pull threat data from', example='https://www.spamhaus.org/drop/edrop.txt'),
    'active': fields.Boolean(example=True)
})

mod_list_values = Model('ListValues', {
    'values': fields.List(fields.String)
})

mod_event_rule_test = Model('TestEventRuleQuery', {
    'query': fields.String(required=True),
    'uuid': fields.String,
    'event_count': fields.Integer(required=True),
    'return_results': fields.Boolean,
    'start_date': fields.String,
    'end_date': fields.String,
})

mod_event_rule_create = Model('CreateEventRule', {
    'name': fields.String,
    'description': fields.String,
    'event_signature': fields.String,
    'merge_into_case': fields.Boolean,
    'target_case_uuid': fields.String,
    'query': fields.String,
    'dismiss': fields.Boolean,
    'dismiss_reason': fields.String,
    'dismiss_comment': fields.String,
    'expire': fields.Boolean,
    'expire_days': fields.Integer,
    'active': fields.Boolean
})

mod_event_rule_list = Model('EventRuleList', {
    'uuid': fields.String,
    'name': fields.String,
    'description': fields.String,
    'event_signature': fields.String,
    'dismiss_comment': fields.String,
    'dismiss_reason': fields.String,
    'rule_signature': fields.String,
    'merge_into_case': fields.Boolean,
    'target_case_uuid': fields.String,
    'dismiss': fields.Boolean,
    'expire': fields.Boolean,
    'expire_days': fields.Integer,
    'active': fields.Boolean,
    'query': fields.String,
    'hits': fields.Integer,
    'hits_last_24': fields.Integer,
    'observables': fields.List(fields.Nested(mod_observable_brief)),
    'expire_at': ISO8601(attribute='expire_at'),
    'created_at': ISO8601(attribute='created_at'),
    'updated_at': ISO8601(attribute='updated_at'),
    'last_matched_date': ISO8601(attribute='last_matched_date')
})

mod_event_rule_list_paged = Model('PagedEventRuleList', {
    'event_rules': fields.List(fields.Nested(mod_event_rule_list)),
    'pagination': fields.Nested(mod_pagination)
})

mod_case_history = Model('CaseHistoryEntry', {
    'message': fields.String,
    'created_at': ISO8601(attribute='created_at'),
    'created_by': fields.Nested(mod_user_list)
})

mod_case_observables = Model('CaseObservables', {
    'observables': fields.List(fields.Nested(mod_observable_list))
})

mod_case_close_reason = Model('CaseCloseList', {
    'uuid': fields.String,
    'title': fields.String,
    'description': fields.String
})

mod_comment = Model('CommentDetails', {
    'uuid': fields.String,
    'message': fields.String,
    'edited': fields.Boolean,
    'is_closure_comment': fields.Boolean,
    'closure_reason': fields.Nested(mod_case_close_reason),
    'created_by': fields.Nested(mod_user_list),
    'created_at': ISO8601(attribute='created_at'),
    'case_uuid': fields.String
})

mod_comment_create = Model('CommentCreate', {
    'case_uuid': fields.String(required=True),
    'message': fields.String(required=True)
})

mod_case_task_create = Model('CaseTaskCreate', {
    'title': fields.String,
    'order': fields.Integer,
    'description': fields.String,
    'group_uuid': fields.String,
    'owner_uuid': fields.String,
    'case_uuid': fields.String
})

mod_case_task_note_details = Model('CaseTaskNoteDetails', {
    'note': fields.String,
    'created_by': fields.Nested(mod_user_list),
    'created_at': ISO8601(attribute='created_at')
})

mod_case_task_full = Model('CaseTaskList', {
    'uuid': fields.String,
    'title': fields.String,
    'description': fields.String,
    'order': fields.Integer,
    'created_at': ISO8601(attribute='created_at'),
    'updated_at': ISO8601(attribute='updated_at'),
    'start_date': ISO8601(attribute='start_date'),
    'finish_date': ISO8601(attribute='finish_date'),
    #'group': fields.Nested(mod_user_group_list),
    'owner': fields.Nested(mod_user_list),
    'case': fields.String,
    'status': fields.Integer,
    'from_template': fields.Boolean,
    'notes': fields.Nested(mod_case_task_note_details, attribute='_notes')
})

mod_case_task_note_create = Model('CreateTaskNote', {
    'note': fields.String
})

mod_case_task_note = Model('CaseTaskNote', {
    'note': fields.String
})

mod_case_template_task_create = Model('CaseTemplateTaskCreate', {
    'title': fields.String,
    'order': fields.Integer,
    'description': fields.String,
    'group_uuid': fields.String,
    'owner_uuid': fields.String
})

mod_case_template_create = Model('CaseTemplateCreate', {
    'title': fields.String(required=True),
    'owner_uuid': fields.String,
    'description': fields.String(required=True),
    'tags': fields.List(fields.String),
    'tlp': fields.Integer,
    'tasks': fields.List(fields.Nested(mod_case_template_task_create)),
    'severity': fields.Integer
})

mod_case_template_task_full = Model('CaseTemplateTaskList', {
    'uuid': fields.String,
    'title': fields.String,
    'description': fields.String,
    'order': fields.Integer,
    'created_at': ISO8601(attribute='created_at'),
    'updated_at': ISO8601(attribute='updated_at'),
    #'group': fields.Nested(mod_user_group_list),
    #'owner': fields.Nested(mod_user_list),
    'status': fields.Integer
})

mod_case_template_full = Model('CaseTemplateList', {
    'uuid': fields.String,
    'title': fields.String,
    #'owner': fields.Nested(mod_user_list),
    'description': fields.String,
    'tags': fields.List(fields.String),
    'tlp': fields.Integer,
    'severity': fields.Integer,
    #'status': fields.Nested(mod_event_status),
    'created_at': ISO8601(attribute='created_at'),
    'updated_at': ISO8601(attribute='updated_at'),
    'tasks': fields.List(fields.Nested(mod_case_template_task_full)),
    'task_count': ValueCount(attribute='tasks')
})

mod_close_reason_create = Model('CreateCloseReason', {
    'title': fields.String,
    'description': fields.String
})

mod_close_reason_list = Model('CloseReasonList', {
    'uuid': fields.String,
    'title': fields.String,
    'description': fields.String
})

mod_case_status = Model('CaseStatusString', {
    'uuid': fields.String,
    'name': fields.String,
    'closed': fields.Boolean
})

mod_case_status_create = Model('CaseStatusCreate', {
    'name': fields.String,
    'description': fields.String
})

mod_case_status_list = Model('CaseStatusList', {
    'uuid': fields.String,
    'name': fields.String,
    'description': fields.String,
    'closed': fields.Boolean
})

mod_case_template_brief = Model('CaseTemplateBrief', {
    'uuid': fields.String,
    'title': fields.String,
})

mod_related_case = Model('RelatedCase', {
    'id': fields.Integer,
    'uuid': fields.String,
    'title': fields.String,
    'event_count': ValueCount(attribute='events'),
    'observable_count': ObservableCount(attribute='observables'),
    'owner': fields.Nested(mod_user_list),
    'status': fields.Nested(mod_case_status)
})

mod_case_create = Model('CaseCreate', {
    'title': fields.String(required=True),
    'owner_uuid': fields.String,
    'description': fields.String(required=True),
    'tags': fields.List(fields.String),
    'tlp': fields.Integer(required=True),
    'severity': fields.Integer(required=True),
    'observables': fields.List(fields.String),
    'events': fields.List(fields.String),
    'case_template_uuid': fields.String,
    'include_related_events': fields.Boolean,
    'generate_event_rule': fields.Boolean
})

mod_case_list = Model('CaseList', {
    #'id': fields.String,
    'uuid': fields.String,
    'title': fields.String,
    'owner': fields.Nested(mod_user_list),
    #'description': fields.String,
    #'tags': fields.List(fields.String),
    'tlp': fields.Integer,
    'severity': fields.Integer,
    'status': fields.Nested(mod_case_status),
    'event_count': ValueCount(attribute='events'),
    #'open_tasks': fields.Integer,
    #'total_tasks': ValueCount(attribute='tasks'),
    'created_at': ISO8601(attribute='created_at'),
    'updated_at': ISO8601(attribute='updated_at'),
    #'created_by': fields.Nested(mod_user_list),
    #'updated_by': fields.Nested(mod_user_list),
    #'observable_count': ValueCount(attribute='observables'),
    #'close_reason': fields.Nested(mod_close_reason_list),
    #'closed': fields.Boolean(),
    #'case_template': fields.Nested(mod_case_template_brief)
})

mod_case_details = Model('CaseDetails', {
    #'id': fields.String,
    'uuid': fields.String,
    'title': fields.String,
    'owner': fields.Nested(mod_user_list),
    'description': fields.String,
    'tags': FormatTags(attribute='tags'),
    'tlp': fields.Integer,
    'severity': fields.Integer,
    'status': fields.Nested(mod_case_status),
    'event_count': ValueCount(attribute='events'),
    'related_cases': ValueCount(attribute='related_cases'),
    'open_tasks': fields.Integer,
    #'total_tasks': ValueCount(attribute='tasks'),
    'total_tasks': fields.Integer,
    'created_at': ISO8601(attribute='created_at'),
    'updated_at': ISO8601(attribute='updated_at'),
    'created_by': fields.Nested(mod_user_list),
    'updated_by': fields.Nested(mod_user_list),
    'observable_count': ValueCount(attribute='observables')
    #'close_reason': fields.Nested(mod_close_reason_list),
    #'case_template': fields.Nested(mod_case_template_brief)
})

mod_case_paged_list = Model('PagedCaseList', {
   'cases': fields.List(fields.Nested(mod_case_list)),
   'pagination': fields.Nested(mod_pagination)
})

mod_link_cases = Model('LinkCases', {
    'cases': fields.List(fields.String)
})

mod_audit_log = Model('AuditLog', {
    'created_at': ISO8601(),
    'organization': fields.String,
    'event_type': fields.String,
    'message': fields.String,
    'source_user': fields.String,
    'status': fields.String,
    'event_reference': fields.String,
    'time_taken': fields.String
})

mod_audit_log_paged_list = Model('AuditLogPagedList', {
    'logs': fields.List(fields.Nested(mod_audit_log)),
    'pagination': fields.Nested(mod_pagination)
})

mod_mfa_token = Model('MFATOTP', {
    'token': fields.String
})

mod_mfa_challenge = Model('MFAChallenge', {
    'mfa_challenge_token': fields.String,
    'token': fields.String
})

mod_create_backup = Model('CreateBackup', {
    'password': fields.String
})

mod_bulk_event_uuids = Model('BulkEventUUIDs', {
    'events': fields.List(fields.String)
})

schema_models = [mod_user_role_no_members, mod_user_self, mod_user_full,
mod_auth, mod_auth_success_token, mod_refresh_token, mod_event_list, mod_event_create,
mod_observable_brief, mod_observable_create, mod_observable_update, mod_raw_log, mod_permissions,
mod_api_key,mod_user_create, mod_user_create_success, mod_settings, mod_persistent_pairing_token,
mod_credential_create, mod_credential_update, mod_credential_full, mod_credential_list,
mod_credential_return, mod_input_create, mod_input_list, mod_agent_list, mod_agent_create,
mod_list_list, mod_list_create, mod_event_rule_create, mod_event_rule_list, mod_data_type_list,
mod_data_type_create, mod_user_role_no_perms, mod_user_brief, mod_role_list, mod_role_create,
mod_case_history, mod_comment, mod_comment_create, mod_case_close_reason, mod_case_template_create,
mod_case_template_task_create, mod_case_task_create, mod_case_template_task_full,
mod_case_template_full, mod_close_reason_create, mod_close_reason_list, mod_case_status,
mod_case_status_create, mod_case_status_list, mod_case_template_brief, mod_case_create,
mod_case_list, mod_case_details, mod_case_paged_list, mod_user_list, mod_tag_list, mod_tag,
mod_related_case, mod_link_cases, mod_case_task_full, mod_event_status, mod_event_paged_list,
mod_event_details, mod_observable_list, mod_observable_list_paged, mod_bulk_add_observables,
mod_case_observables, mod_related_events, mod_pagination, mod_event_create_bulk,
mod_agent_group_list, mod_paged_agent_group_list, mod_agent_group_create, mod_case_task_note,
mod_case_task_note_create, mod_case_task_note_details, mod_audit_log, mod_audit_log_paged_list,
mod_event_bulk_dismiss,mod_add_events_to_case, mod_response_message, mod_add_events_response,
mod_plugin_create,mod_plugin_name,mod_plugin_config_list,mod_plugin_list,mod_plugin_manifest_action,
mod_plugin_manifest, mod_mfa_token, mod_mfa_challenge, mod_event_rule_test, mod_event_rql,
mod_event_rql_list, mod_toggle_user_mfa, mod_create_backup, mod_event_rule_list_paged, mod_bulk_event_uuids,
mod_list_values]
