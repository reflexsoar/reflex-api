from flask_restx import Model, fields

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

mod_user_full = Model('UserFull', {
    'uuid': fields.String,
    'username': fields.String,
    'email': fields.String,
    'password': fields.String,
    'first_name': fields.String,
    'last_name': fields.String
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
    'email': fields.String,
})

mod_auth = Model('AuthModel', {
    'username': fields.String,
    'password': fields.String
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
    'add_alert': fields.Boolean,
    'update_alert': fields.Boolean,
    'delete_alert': fields.Boolean,
    'add_tag_to_alert': fields.Boolean,
    'remove_tag_from_alert': fields.Boolean,
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
    "view_credentials": fields.Boolean
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
    'spotted': fields.Boolean,
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
    'spotted': fields.Boolean,
    'dataType': fields.Nested(mod_observable_type_name),
    'uuid': fields.String
})

mod_bulk_tag = Model('BulkTag', {
    'tags': fields.List(fields.String)
})

mod_alert_create = Model('AlertCreate', {
    'title': fields.String(required=True),
    'reference': fields.String(required=True),
    'description': fields.String(required=True),
    'tags': fields.List(fields.String),
    'observables': fields.List(fields.Nested(mod_observable_create))
})

mod_alert_details = Model('AlertDetails', {
    'title': fields.String(required=True),
    'reference': fields.String(required=True),
    'description': fields.String(required=True),
    'tags': fields.List(fields.String),
    'observables': fields.List(fields.Nested(mod_observable_create))
})

mod_observable = Model('ObservableDetails', {
    'tags': fields.List(fields.Nested(mod_tag_list)),
    'value': fields.String,
    'ioc': fields.Boolean,
    'spotted': fields.Boolean,
    'dataType': fields.Nested(mod_observable_type_name)
})

mod_alert_list = Model('AlertList', {
    'uuid': fields.String,
    'title': fields.String(required=True),
    'reference': fields.String(required=True),
    'description': fields.String(required=True),
    'tags': fields.List(fields.Nested(mod_tag_list)),
    'observables': fields.List(fields.Nested(mod_observable)),
    'observable_count': ObservableCount(attribute='observables'),
    'ioc_count': IOCCount(attribute='observables'),
    'created_at': fields.DateTime,
    'modified_at': fields.DateTime
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
    'description': fields.String,
    'enabled': fields.Boolean,
    'credential': fields.Nested(mod_credential_list),
    'config': JSONField()
})

mod_input_create = Model('CreateInput', {
    'name': fields.String,
    'description': fields.String,
    'enabled': fields.Boolean,
    'credential': fields.String(required=True),
    'config': JSONField()
})

schema_models = [mod_auth, mod_auth_success_token, mod_refresh_token, mod_user_full, mod_user_create,
                 mod_user_list, mod_user_self, mod_role_list, mod_role_create,
                 mod_tag, mod_tag_list,mod_credential_create, mod_credential_full, mod_credential_return,
                 mod_credential_decrypted, mod_credential_decrypt, mod_credential_update,
                 mod_permission_full, mod_permission_list, mod_role_uuid, mod_permission_role_view, mod_bulk_tag,
                 mod_playbook_full,  mod_playbook_create, mod_playbook_list, mod_bulk_tag,
                 mod_observable, mod_observable_create, mod_observable_list, mod_observable_type, mod_observable_type_name,
                 mod_alert_create, mod_alert_details, mod_alert_list, mod_credential_list,
                 mod_input_create, mod_input_list]