from flask_restx import Model, fields

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
    'add_org': fields.Boolean,
    'update_org': fields.Boolean,
    'delete_org': fields.Boolean,
    'add_tag_to_org': fields.Boolean,
    'remove_tag_from_org': fields.Boolean,
    'view_orgs': fields.Boolean,
    'add_project': fields.Boolean,
    'update_project': fields.Boolean,
    'delete_project': fields.Boolean,
    'add_tag_to_project': fields.Boolean,
    'remove_tag_from_project': fields.Boolean,
    'view_projects': fields.Boolean,
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
    'name': fields.String,
    'color': fields.String
})

mod_credential_create = Model('CredentialCreate', {
    'username': fields.String,
    'password': fields.String,
    'master_password': fields.String,
    'name': fields.String,
    'description': fields.String,
    'project_uuid': fields.String
})

mod_credential_update = Model('CredentialUpdate', {
    'username': fields.String,
    'password': fields.String,
    'master_password': fields.String,
    'name': fields.String,
    'description': fields.String
})

mod_credential_full = Model('Credential', {
    'uuid': fields.String,
    'username': fields.String,
    'name': fields.String,
    'description': fields.String,
    'project_uuid': fields.String
})

mod_credential_return = Model('CredentialReturn', {
    'password': fields.String
})

mod_bulk_tag = Model('BulkTag', {
    'tags': fields.List(fields.String)
})

mod_credential_decrypt = Model('CredentialDecrypt', {
    'uuid': fields.String,
    'master_password': fields.String    
})

mod_credential_decrypted = Model('CredentialDecrypted', {
    'password': fields.String
})

schema_models = [mod_auth, mod_auth_success_token, mod_refresh_token, mod_user_full, mod_user_create,
                 mod_user_list, mod_user_self, mod_role_list, mod_role_create,
                 mod_tag, mod_tag_list,mod_credential_create, mod_credential_full, mod_credential_return,
                 mod_credential_decrypted, mod_credential_decrypt, mod_credential_update,
                 mod_permission_full, mod_permission_list, mod_role_uuid, mod_permission_role_view, mod_bulk_tag]