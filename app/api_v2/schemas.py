import json
from flask import current_app
from flask_restx import Model, fields

class ObservableCount(fields.Raw):
    ''' Returns the number of observables '''

    def format(self, value):
        return len(value)

class IOCCount(fields.Raw):
    ''' Returns the number of observables that are IOC '''

    def format(self, value):
        iocs = [o for o in value if 'ioc' in o and o['ioc'] == True]
        return len(iocs)


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

mod_user_full = Model('UserFull', {
    'uuid': fields.String,
    'username': fields.String,
    'email': fields.String,
    'first_name': fields.String,
    'last_name': fields.String,
    'last_logon': fields.String,
    'locked': fields.Boolean,
    'failed_logons': fields.Integer,
    'disabled': fields.Boolean
    #'role': fields.Nested(mod_user_role)
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
    'create_agent_group': fields.Boolean,
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

mod_user_role_no_members = Model('UserRole', {
    'uuid': fields.String,
    'permissions': fields.Nested(mod_permissions),
    'name': fields.String,
    'description': fields.String
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

mod_observable_create = Model('ObservableCreate', {
    'value': fields.String(required=True),
    'ioc': fields.Boolean,
    'tlp': fields.Integer,
    'spotted': fields.Boolean,
    'safe': fields.Boolean,
    'dataType': fields.String(required=True),
    'tags': fields.List(fields.String)
})

mod_observable_list = Model('ObservableList', {
    'tags': fields.List(fields.Nested(mod_tag_list)),
    'value': fields.String,
    'ioc': fields.Boolean,
    'tlp': fields.Integer,
    'spotted': fields.Boolean,
    'safe': fields.Boolean,
    'data_type': fields.String,
    'uuid': fields.String
})

mod_observable_brief = Model('ShortObservableDetails', {
    'uuid': fields.String,
    'value': fields.String,
    'data_type': fields.String
})

mod_raw_log = Model('RawLog', {
    'source_log': fields.String
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
    #'status': fields.Nested(mod_event_status),
    'source': fields.String,
    #'tags': fields.List(fields.Nested(mod_tag_list), attribute='_tags'),
    #'observables': fields.List(fields.Nested(mod_observable_brief), attribute='_observables'),
    'tags': fields.List(fields.String),
    'observables': fields.List(fields.Nested(mod_observable_brief)),
    'observable_count': ObservableCount(attribute='observables'),
    'ioc_count': IOCCount(attribute='observables'),
    'created_at': fields.String,#ISO8601(attribute='created_at'),
    'modified_at': fields.String, #ISO8601(attribute='modified_at'),
    'case_uuid': fields.String,
    'signature': fields.String,
    'related_events_count': fields.Integer,
    'related_events': fields.List(fields.String),
    #'dismiss_reason': fields.Nested(mod_close_reason_list)
    'raw_log': fields.Nested(mod_raw_log, attribute='_raw_log')
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
    'events_per_page': fields.Integer
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


schema_models = [mod_user_role_no_members, mod_user_self, mod_user_full, 
mod_auth, mod_auth_success_token, mod_refresh_token, mod_event_list, mod_event_create, 
mod_observable_brief, mod_observable_create, mod_raw_log, mod_permissions, mod_api_key,
mod_user_create, mod_user_create_success, mod_settings, mod_persistent_pairing_token,
mod_credential_create, mod_credential_update, mod_credential_full, mod_credential_list, mod_credential_return]