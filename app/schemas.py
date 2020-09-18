from flask_restx import Model, fields


class ValueCount(fields.Raw):
    def format(self, value):
        return len(value)

class ObservableCount(fields.Raw):
    ''' Returns the number of observables '''

    def format(self, value):
        return len(value)


class IOCCount(fields.Raw):
    ''' Returns the number of observables that are IOC '''

    def format(self, value):
        iocs = [o for o in value if o.ioc == True]
        return len(iocs)


class JSONField(fields.Raw):
    def format(self, value):
        return value


# Models
mod_user_list = Model('UserList', {
    'username': fields.String,
    'uuid': fields.String
})

mod_user_role = Model('UserRole', {
    'uuid': fields.String,
    'name': fields.String
})

mod_user_full = Model('UserFull', {
    'uuid': fields.String,
    'username': fields.String,
    'email': fields.String,
    'password': fields.String,
    'first_name': fields.String,
    'last_name': fields.String,
    'last_logon': fields.DateTime,
    'locked': fields.Boolean,
    'role': fields.Nested(mod_user_role)
})

mod_user_create = Model('UserCreate', {
    'username': fields.String,
    'email': fields.String,
    'password': fields.String,
    'first_name': fields.String,
    'last_name': fields.String
})

mod_user_self = Model('UserSelf', {
    'username': fields.String,
    'email': fields.String
})

mod_user_group_create = Model('UserGroupCreate', {
    'name': fields.String,
    'description': fields.String
})

mod_user_group_list = Model('UserGroupList', {
    'uuid': fields.String,
    'name': fields.String,
    'description': fields.String,
    'created_at': fields.DateTime,
    'modified_at': fields.DateTime,
    'members': fields.List(fields.Nested(mod_user_list))
})

mod_add_user_to_group = Model('UsersToGroup', {
    'members': fields.List(fields.String)
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

mod_role_create = Model('RoleCreate', {
    'name': fields.String,
    'description': fields.String
})

mod_role_uuid = Model('RoleUUID', {
    'uuid': fields.String
})

permission_fields = {
    'add_user': fields.Boolean,
    'update_user': fields.Boolean,
    'delete_user': fields.Boolean,
    'add_user_to_role': fields.Boolean,
    'remove_user_from_role': fields.Boolean,
    'reset_user_password': fields.Boolean,
    'unlock_user': fields.Boolean,
    'view_users': fields.Boolean,
    'add_event': fields.Boolean,
    'view_events': fields.Boolean,
    'update_event': fields.Boolean,
    'delete_event': fields.Boolean,
    'add_tag_to_event': fields.Boolean,
    'remove_tag_from_event': fields.Boolean,
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
    'add_role': fields.Boolean,
    'update_role': fields.Boolean,
    'delete_role': fields.Boolean,
    'set_role_permissions': fields.Boolean,
    'view_roles': fields.Boolean,
    "add_tag": fields.Boolean,
    "update_tag": fields.Boolean,
    "delete_tag": fields.Boolean,
    "view_tags": fields.Boolean,
    "add_credential": fields.Boolean,
    "update_credential": fields.Boolean,
    "decrypt_credential": fields.Boolean,
    "delete_credential": fields.Boolean,
    "view_credentials": fields.Boolean,
    "view_agents": fields.Boolean,
    "update_agent": fields.Boolean,
    "delete_agent": fields.Boolean,
    "pair_agent": fields.Boolean,
    'add_input': fields.Boolean,
    "view_inputs": fields.Boolean,
    "update_input": fields.Boolean,
    "delete_input": fields.Boolean,
    "create_case": fields.Boolean,
    "view_cases": fields.Boolean,
    "update_case": fields.Boolean,
    "delete_case": fields.Boolean,
    "create_case_comment": fields.Boolean,
    "view_case_comments": fields.Boolean,
    "update_case_comment": fields.Boolean,
    "delete_case_comment": fields.Boolean,
    "view_plugins": fields.Boolean,
    "create_plugin": fields.Boolean,
    "delete_plugin": fields.Boolean,
    "update_plugin": fields.Boolean,
    "create_agent_group": fields.Boolean,
    "view_agent_groups": fields.Boolean,
    "update_agent_group": fields.Boolean,
    "delete_agent_group": fields.Boolean,
    "create_user_group": fields.Boolean,
    "view_user_groups": fields.Boolean,
    "update_user_groups": fields.Boolean,
    "delete_user_group": fields.Boolean,
    "create_case_template": fields.Boolean,
    "view_case_templates": fields.Boolean,
    "update_case_template": fields.Boolean,
    "delete_case_template": fields.Boolean,
    "create_case_task": fields.Boolean,
    "view_case_tasks": fields.Boolean,
    "update_case_task": fields.Boolean,
    "delete_case_task": fields.Boolean,
    "create_case_template_task": fields.Boolean,
    "view_case_template_tasks": fields.Boolean,
    "update_case_template_task": fields.Boolean,
    "delete_case_template_task": fields.Boolean,
    "create_case_status": fields.Boolean,
    "update_case_status": fields.Boolean,
    "delete_case_status": fields.Boolean,
    "update_settings": fields.Boolean
}

mod_permission_role_view = Model('PermissionRoleView', {
    **permission_fields,
    **{'uuid': fields.String}})

mod_permission_list = Model('Permission', {
    **permission_fields,
    **{
        'uuid': fields.String,
        'roles': fields.List(fields.Nested(mod_role_uuid))
    }
})

mod_permission_full = Model('PermissionFull', {
    **permission_fields
})

mod_role_list = Model('Role', {
    'uuid': fields.String,
    'name': fields.String,
    'description': fields.String,
    'users': fields.List(fields.Nested(mod_user_list)),
    'permissions': fields.List(fields.Nested(mod_permission_role_view))
})

mod_tag = Model('Tag', {
    'name': fields.String
})

mod_tag_list = Model('TagList', {
    'uuid': fields.String,
    'name': fields.String
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
    'description': fields.String
})

mod_credential_return = Model('CredentialReturn', {
    'secret': fields.String
})

mod_bulk_tag = Model('BulkTag', {
    'tags': fields.List(fields.String)
})

mod_credential_decrypt = Model('CredentialDecrypt', {
    'uuid': fields.String,
    'master_password': fields.String
})

mod_credential_decrypted = Model('CredentialDecrypted', {
    'secret': fields.String
})

mod_playbook_create = Model('ProjectCreate', {
    'name': fields.String,
    'description': fields.String,
    'tags': fields.List(fields.String)
})

mod_playbook_full = Model('Project', {
    'uuid': fields.String,
    'name': fields.String,
    'description': fields.String,
    'enabled': fields.String
})

mod_playbook_list = Model('ProjectList', {
    'uuid': fields.String,
    'name': fields.String,
    'description': fields.String,
    'enabled': fields.String,
    'tags': fields.List(fields.Nested(mod_tag_list))
})

mod_observable_create = Model('Observable', {
    'value': fields.String(required=True),
    'ioc': fields.Boolean,
    'tlp': fields.Integer,
    'spotted': fields.Boolean,
    'safe': fields.Boolean,
    'dataType': fields.String(required=True),
    'tags': fields.List(fields.String)
})

mod_observable_type_name = Model('ObservableTypeName', {
    'name': fields.String
})

mod_observable_list = Model('ObservableList', {
    'tags': fields.List(fields.Nested(mod_tag_list)),
    'value': fields.String,
    'ioc': fields.Boolean,
    'tlp': fields.Integer,
    'spotted': fields.Boolean,
    'safe': fields.Boolean,
    'dataType': fields.Nested(mod_observable_type_name),
    'uuid': fields.String
})

mod_bulk_tag = Model('BulkTag', {
    'tags': fields.List(fields.String)
})

mod_event_create = Model('EventCreate', {
    'title': fields.String(required=True),
    'reference': fields.String(required=True),
    'description': fields.String(required=True),
    'tags': fields.List(fields.String),
    'tlp': fields.Integer,
    'severity': fields.Integer,
    'observables': fields.List(fields.Nested(mod_observable_create)),
    'raw_log': fields.String
})

mod_event_status = Model('EventStatusString', {
    'name': fields.String
})

mod_case_status_uuid = Model('CaseStatusUUID', {
    'uuid': fields.String
})

mod_case_uuid = Model('CaseUUID', {
    'uuid': fields.String
})

mod_event_details = Model('EventDetails', {
    'uuid': fields.String,
    'title': fields.String(required=True),
    'reference': fields.String(required=True),
    'description': fields.String(required=True),
    'tlp': fields.Integer,
    'severity': fields.Integer,
    'status': fields.Nested(mod_event_status),
    'tags': fields.List(fields.Nested(mod_tag_list)),
    'observables': fields.List(fields.Nested(mod_observable_list)),
    'observable_count': ObservableCount(attribute='observables'),
    'ioc_count': IOCCount(attribute='observables'),
    'case_uuid': fields.String,
    'created_at': fields.DateTime,
    'modified_at': fields.DateTime,
    'raw_log': JSONField()
})

mod_event_create_bulk = Model('EventCreateBulk', {
    'events': fields.List(fields.Nested(mod_event_create))
})

mod_observable = Model('ObservableDetails', {
    'tags': fields.List(fields.Nested(mod_tag_list)),
    'value': fields.String,
    'ioc': fields.Boolean,
    'tlp': fields.Integer,
    'spotted': fields.Boolean,
    'dataType': fields.Nested(mod_observable_type_name)
})

mod_event_list = Model('EventList', {
    'uuid': fields.String,
    'title': fields.String(required=True),
    'reference': fields.String(required=True),
    'description': fields.String(required=True),
    'tlp': fields.Integer,
    'severity': fields.Integer,
    'status': fields.Nested(mod_event_status),
    'tags': fields.List(fields.Nested(mod_tag_list)),
    'observables': fields.List(fields.Nested(mod_observable_list)),
    'observable_count': ObservableCount(attribute='observables'),
    'ioc_count': IOCCount(attribute='observables'),
    'created_at': fields.DateTime,
    'modified_at': fields.DateTime,
    'case_uuid': fields.String
})

mod_observable_type = Model('ObservableType', {
    'name': fields.String,
    'uuid': fields.String
})

mod_create_observable_type = Model('ObservableTypeName', {
    'name': fields.String
})

mod_input_list = Model('InputList', {
    'uuid': fields.String,
    'name': fields.String,
    'plugin': fields.String,
    'description': fields.String,
    'enabled': fields.Boolean,
    'credential': fields.Nested(mod_credential_list),
    'tags': fields.List(fields.Nested(mod_tag_list)),
    'config': JSONField(),
    'field_mapping': JSONField(),
    'created_at': fields.DateTime,
    'modified_at': fields.DateTime
})

mod_input_create = Model('CreateInput', {
    'name': fields.String,
    'description': fields.String,
    'plugin': fields.String,
    'enabled': fields.Boolean,
    'credential': fields.String(required=True),
    'tags': fields.List(fields.String),
    'config': JSONField(),
    'field_mapping': JSONField()
})

mod_agent_role_list = Model('AgentRoleList', {
    'name': fields.String,
    'description': fields.String
})

mod_agent_group_list = Model('AgentGroupList', {
    'uuid': fields.String,
    'name': fields.String,
    'description': fields.String
})

mod_agent_group_create = Model('AgentGroupList', {
    'uuid': fields.String,
    'name': fields.String,
    'description': fields.String
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
    'inputs': fields.List(fields.Nested(mod_input_list)),
    'roles': fields.List(fields.Nested(mod_agent_role_list)),
    'groups': fields.List(fields.Nested(mod_agent_group_list)),
    'active': fields.Boolean,
    'ip_address': fields.String,
    'last_heartbeat': fields.DateTime
})

mod_case_template_task_create = Model('CaseTemplateTaskCreate', {
    'title': fields.String,
    'order': fields.Integer,
    'description': fields.String,
    'group_uuid': fields.String,
    'owner_uuid': fields.String,
    'case_template_uuid': fields.String
})

mod_case_template_task_full = Model('CaseTemplateTaskList', {
    'uuid': fields.String,
    'title': fields.String,
    'description': fields.String,
    'order': fields.Integer,
    'created_at': fields.DateTime,
    'modified_at': fields.DateTime,
    'group': fields.Nested(mod_user_group_list),
    'owner': fields.Nested(mod_user_list),
    'case_template_uuid': fields.String,
    'status': fields.Integer
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
    'created_at': fields.DateTime,
    'modified_at': fields.DateTime,
    'group': fields.Nested(mod_user_group_list),
    'owner': fields.Nested(mod_user_list),
    'case_uuid': fields.String,
    'status': fields.Integer,
    'from_template': fields.Boolean
})

mod_add_tasks_to_case = Model('TasksToCase', {
    'tasks': fields.List(fields.String)
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

mod_case_template_create = Model('CaseTemplateCreate', {
    'title': fields.String(required=True),
    'owner_uuid': fields.String,
    'description': fields.String(required=True),
    'tags': fields.List(fields.String),
    'tlp': fields.Integer,
    'severity': fields.Integer
})

mod_case_history = Model('CaseHistoryEntry', {
    'message': fields.String,
    'created_at': fields.DateTime,
    'created_by': fields.Nested(mod_user_list)
})

mod_case_template_full = Model('CaseTemplateList', {
    'uuid': fields.String,
    'title': fields.String,
    'owner': fields.Nested(mod_user_list),
    'description': fields.String,
    'tags': fields.List(fields.Nested(mod_tag_list)),
    'tlp': fields.Integer,
    'severity': fields.Integer,
    'status': fields.Nested(mod_event_status),
    'created_at': fields.DateTime,
    'modified_at': fields.DateTime,
    'tasks': fields.List(fields.Nested(mod_case_template_task_full)),
    'task_count': ValueCount(attribute='tasks')
})


mod_case_status = Model('CaseStatusString', {
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
    'description': fields.String
})

mod_comment = Model('CommentDetails', {
    'message': fields.String,
    'created_by': fields.Nested(mod_user_list),
    'created_at': fields.DateTime
})

mod_comment_create = Model('CommentCreate', {
    'case_uuid': fields.String,
    'message': fields.String
})


mod_bulk_add_observables = Model('BulkObservables', {
    'observables': fields.List(fields.Nested(mod_observable_create))
})

mod_case_observables = Model('CaseObservables', {
    'observables': fields.List(fields.Nested(mod_observable_list))
})

mod_case_full = Model('CaseDetails', {
    'id': fields.Integer,
    'uuid': fields.String,
    'title': fields.String,
    'owner': fields.Nested(mod_user_list),
    'description': fields.String,
    'tags': fields.List(fields.Nested(mod_tag)),
    'tlp': fields.Integer,
    'severity': fields.Integer,
    'comments': fields.List(fields.Nested(mod_comment)),
    'status_uuid': fields.String,
    'status': fields.Nested(mod_case_status),
    'observable_count': ObservableCount(attribute='observables'),
    'created_at': fields.DateTime,
    'modified_at': fields.DateTime,
    'created_by': fields.Nested(mod_user_list),
    'updated_by': fields.Nested(mod_user_list),
    'observables': fields.List(fields.Nested(mod_observable_list)),
    'events': fields.List(fields.Nested(mod_event_details)),
    'history': fields.List(fields.Nested(mod_case_history)),
    'tasks': fields.List(fields.Nested(mod_case_task_full))
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
    'created_at': fields.DateTime,
    'modified_at': fields.DateTime

})

mod_plugin_list = Model('PluginList', {
    "uuid": fields.String,
    "name": fields.String,
    "logo": fields.String,
    "description": fields.String,
    "enabled": fields.Boolean,
    "manifest": JSONField,
    "config_template": JSONField,
    "filename": fields.String,
    "file_hash": fields.String,
    'created_at': fields.DateTime,
    'modified_at': fields.DateTime,
    "configs": fields.List(fields.Nested(mod_plugin_config_list))
})

mod_plugin_config_create = Model('PluginConfigCreate', {
    "name": fields.String,
    "description": fields.String,
    "plugin_uuid": fields.String,
    "config": fields.String
})

mod_settings = Model('SettingsList', {
    'base_url': fields.String,
    'require_case_templates': fields.Boolean,
    'allow_comment_deletion': fields.Boolean,
    'email_from': fields.String,
    'email_server': fields.String,
    'email_secret': fields.Nested(mod_credential_list),
    'playbook_action_timeout': fields.Integer,
    'playbook_timeout': fields.Integer
})

schema_models = [mod_auth, mod_auth_success_token, mod_refresh_token, mod_user_full, mod_user_create,
                 mod_user_list, mod_user_self, mod_role_list, mod_role_create,
                 mod_tag, mod_tag_list, mod_credential_create, mod_credential_full, mod_credential_return,
                 mod_credential_decrypted, mod_credential_decrypt, mod_credential_update,
                 mod_permission_full, mod_permission_list, mod_role_uuid, mod_permission_role_view, mod_bulk_tag,
                 mod_playbook_full,  mod_playbook_create, mod_playbook_list, mod_bulk_tag,
                 mod_observable, mod_observable_create, mod_observable_list, mod_observable_type, mod_observable_type_name,
                 mod_event_create, mod_event_details, mod_event_list, mod_credential_list,
                 mod_input_create, mod_input_list, mod_event_create_bulk, mod_event_status,
                 mod_agent_create, mod_agent_list, mod_agent_role_list,
                 mod_case_create, mod_case_status, mod_case_full,
                 mod_plugin_create, mod_plugin_list,
                 mod_agent_group_create, mod_agent_group_list,
                 mod_plugin_config_list, mod_plugin_config_create, mod_plugin_name,
                 mod_user_group_create, mod_user_group_list, mod_add_user_to_group,
                 mod_case_template_create, mod_case_template_full,
                 mod_case_template_task_create, mod_case_template_task_full, mod_add_tasks_to_case, mod_comment, mod_comment_create,
                 mod_case_history, mod_bulk_add_observables, mod_case_observables,
                 mod_case_status_create, mod_case_status_list,
                 mod_case_task_create, mod_case_task_full, mod_user_role, mod_settings]
