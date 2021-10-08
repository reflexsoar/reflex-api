from app.models import Observable
import json
from flask import current_app
from flask_restx import Model, fields
from .models import Observable

class ObservableCount(fields.Raw):
    ''' Returns the number of observables '''

    def format(self, value):
        return len(value)

class ValueCount(fields.Raw):
    def format(self, value):
        return len(value)

class IOCCount(fields.Raw):
    ''' Returns the number of observables that are IOC '''

    def format(self, value):
        iocs = [o for o in value if 'ioc' in o and o['ioc'] == True]
        return len(iocs)

class ISO8601(fields.Raw):
    ''' Returns a Python DateTime object in ISO8601 format with the Zulu time indicator '''
    def format(self, value):
        return value.isoformat()+"Z"

class AsNewLineDelimited(fields.Raw):
    ''' Returns an array as a string delimited by new line characters '''
    def format(self, value):
        return '\n'.join([v for v in value])

class OpenTaskCount(fields.Raw):
    ''' Returns a count of open tasks '''

    def format(self, value):
        return len([a for a in value if a.status != 2])

class FormatTags(fields.Raw):

    def format(self, value):
        return [{'name': v} for v in value]

mod_pagination = Model('Pagination', {
    'total_results': fields.Integer,
    'pages': fields.Integer,
    'page_size': fields.Integer,
    'page': fields.Integer
})

mod_auth = Model('AuthModel', {
    'username': fields.String(default='reflex'),
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
    'view_organizatons': fields.Boolean,
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
    'username': fields.String,
    'email': fields.String,
    'first_name': fields.String,
    'last_name': fields.String,
    'last_logon': ISO8601(attribute='last_logon'),
    'locked': fields.Boolean,
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

mod_user_self = Model('UserSelf', {
    'uuid': fields.String,
    'username': fields.String,
    'first_name': fields.String,
    'last_name': fields.String,
    'email': fields.String,
    'role': fields.Nested(mod_user_role_no_members),
})

mod_tag_list = Model('TagList', {
    'uuid': fields.String,
    'name': fields.String
})

mod_tag = Model('Tag', {
    'name': fields.String
})

mod_observable_create = Model('ObservableCreate', {
    'value': fields.String(required=True),
    'ioc': fields.Boolean,
    'tlp': fields.Integer,
    'spotted': fields.Boolean,
    'safe': fields.Boolean,
    'data_type': fields.String(required=True),
    'tags': fields.List(fields.String)
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
    'case': fields.String
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
    'data_type': fields.String
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
    'tags': fields.List(fields.Nested(mod_tag_list), attribute='_tags'),
    'observables': fields.List(fields.Nested(mod_observable_brief), attribute='_observables'),
    'tags': fields.List(fields.String),
    'observables': fields.List(fields.Nested(mod_observable_brief)),
    'observable_count': ObservableCount(attribute='observables'),
    'ioc_count': IOCCount(attribute='observables'),
    'created_at': ISO8601(attribute='created_at'),
    'updated_at': ISO8601(attribute='updated_at'),
    'case': fields.String,
    'signature': fields.String,
    'related_events_count': fields.Integer,
    'related_events': fields.List(fields.String),
    #'dismiss_reason': fields.Nested(mod_close_reason_list)
    'raw_log': fields.Nested(mod_raw_log, attribute='_raw_log')
})

mod_event_paged_list = Model('PagedEventList', {
   'events': fields.List(fields.Nested(mod_event_list)),
   'pagination': fields.Nested(mod_pagination)
})

mod_related_events = Model('RelatedEvents', {
    'events': fields.List(fields.String)
})

mod_event_create_bulk = Model('EventCreateBulk', {
    'events': fields.List(fields.Nested(mod_event_create))
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
    'signature': fields.String
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
    'data_types': fields.List(fields.String)
})

mod_persistent_pairing_token = Model('PeristentPairingToken', {
    'token': fields.String
})

mod_credential_create = Model('CredentialCreate', {
    'username': fields.String,
    'secret': fields.String,
    'name': fields.String,
    'description': fields.String
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
    'name': fields.String,
    'plugin': fields.String,
    'description': fields.String,
    'enabled': fields.Boolean,
    'credential': fields.String,
    'tags': fields.List(fields.String),
    'config': fields.String,
    'field_mapping': fields.String,
    'created_at': ISO8601(attribute='created_at'),
    'updated_at': ISO8601(attribute='updated_at')
})

mod_input_create = Model('CreateInput', {
    'name': fields.String,
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
    'inputs': fields.List(fields.String),
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
    'description': fields.String
})

mod_list_list = Model('ListView', {
    'uuid': fields.String,
    'name': fields.String,
    'list_type': fields.String,
    'tag_on_match': fields.Boolean,
    'data_type': fields.Nested(mod_data_type_list),
    'values': AsNewLineDelimited(attribute='values'),
    'values_list': fields.List(fields.String, attribute='values'),
    'value_count': ValueCount(attribute='values'),
    'created_at': ISO8601(attribute='created_at'),
    'updated_at': ISO8601(attribute='updated_at')
})

mod_list_create = Model('ListCreate', {
    'name': fields.String,
    'list_type': fields.String,
    'tag_on_match': fields.Boolean,
    'data_type': fields.String,
    'values': fields.String
})

mod_event_rule_create = Model('CreateEventRule', {
    'name': fields.String,
    'description': fields.String,
    'event_signature': fields.String,
    'merge_into_case': fields.Boolean,
    'target_case_uuid': fields.String,
    'observables': fields.List(fields.Nested(mod_observable_create)),
    'dismiss': fields.Boolean,
    'expire': fields.Boolean,
    'expire_days': fields.Integer,
    'active': fields.Boolean    
})

mod_event_rule_list = Model('EventRuleList', {
    'uuid': fields.String,
    'name': fields.String,
    'description': fields.String,
    'event_signature': fields.String,
    'rule_signature': fields.String,
    'merge_into_case': fields.Boolean,
    'target_case_uuid': fields.String,
    'dismiss': fields.Boolean,
    'expire': fields.Boolean,
    'active': fields.Boolean,
    'observables': fields.List(fields.Nested(mod_observable_brief)),
    'expire_at': ISO8601(attribute='expire_at'),
    'created_at': ISO8601(attribute='created_at'),
    'updated_at': ISO8601(attribute='updated_at')
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
    'case_uuid': fields.String,
    'message': fields.String
})

mod_case_task_create = Model('CaseTaskCreate', {
    'title': fields.String,
    'order': fields.Integer,
    'description': fields.String,
    'group_uuid': fields.String,
    'owner_uuid': fields.String,
    'case_uuid': fields.String
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
    'from_template': fields.Boolean
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
    'tlp': fields.Integer,
    'severity': fields.Integer,
    'observables': fields.List(fields.String),
    'events': fields.List(fields.String)
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
    #'open_tasks': OpenTaskCount(attribute='tasks'),
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
    'open_tasks': OpenTaskCount(attribute='tasks'),
    'total_tasks': ValueCount(attribute='tasks'),
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

schema_models = [mod_user_role_no_members, mod_user_self, mod_user_full, 
mod_auth, mod_auth_success_token, mod_refresh_token, mod_event_list, mod_event_create, 
mod_observable_brief, mod_observable_create, mod_observable_update, mod_raw_log, mod_permissions, mod_api_key,
mod_user_create, mod_user_create_success, mod_settings, mod_persistent_pairing_token,
mod_credential_create, mod_credential_update, mod_credential_full, mod_credential_list, mod_credential_return,
mod_input_create, mod_input_list, mod_agent_list, mod_agent_create, mod_list_list, mod_list_create,
mod_event_rule_create, mod_event_rule_list, mod_data_type_list, mod_data_type_create, mod_user_role_no_perms,
mod_user_brief, mod_role_list, mod_role_create, mod_case_history, mod_comment, mod_comment_create, mod_case_close_reason,
mod_case_template_create, mod_case_template_task_create, mod_case_task_create, mod_case_template_task_full,
mod_case_template_full, mod_close_reason_create, mod_close_reason_list, mod_case_status, mod_case_status_create,
mod_case_status_list, mod_case_template_brief, mod_case_create, mod_case_list, mod_case_details, mod_case_paged_list,
mod_user_list, mod_tag_list, mod_tag, mod_related_case, mod_link_cases, mod_case_task_full, mod_event_status,
mod_event_paged_list, mod_event_details, mod_observable_list, mod_observable_list_paged,
mod_bulk_add_observables, mod_case_observables, mod_related_events, mod_pagination, mod_event_create_bulk,
mod_agent_group_list, mod_paged_agent_group_list, mod_agent_group_create]


