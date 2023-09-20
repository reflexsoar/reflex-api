'''/app/api_v2/model/user.py

Contains all the models related to users of the system
'''

import datetime

from flask_restx import ValidationError
from app.api_v2.model.system import EventLog, Settings
import jwt
import onetimepass
import base64
import os
from flask import current_app, request
from flask_bcrypt import Bcrypt

from . import (
    Text,
    Integer,
    Boolean,
    Date,
    Keyword,
    Nested,
    InnerDoc,
    base,
    utils,
    Object,
    analyzer
)

FLASK_BCRYPT = Bcrypt()

class OrganizationScope(InnerDoc):
    ''' Defines the scope of an organization '''

    organization = Keyword()
    role = Keyword()

class UserNotificationSettings(InnerDoc):
    ''' Defines the notification settings for a user '''

    email_mention = Boolean() # Notify the user when they are mentioned in a comment
    email_case_comment = Boolean()
    email_case_status = Boolean()
    email_case_assign = Boolean()
    email_new_case = Boolean()
    email_case_task_status = Boolean()
    email_case_task_assign = Boolean()
    email_case_task_create = Boolean()
    email_case_task_status = Boolean()
    product_updates = Boolean()
    only_watched_cases = Boolean()

user_email_analyzer = analyzer('user_email_analyzer',
    tokenizer='keyword',
    filter=['lowercase']
)

class User(base.BaseDocument):
    '''
    A User of the Reflex system
    '''

    email = Text(fields={'keyword':Keyword()}, analyzer=user_email_analyzer)
    username = Text(fields={'keyword':Keyword()}, analyzer=user_email_analyzer)
    first_name = Text(fields={'keyword':Keyword()})
    last_name = Text(fields={'keyword':Keyword()})
    last_logon = Date()
    password_hash = Text()
    failed_logons = Integer()
    deleted = Boolean()
    locked = Boolean()
    #groups = Nested(Group)
    api_key = Text(fields={'keyword':Keyword()})
    auth_method = Keyword() # local, ldap, saml
    auth_realm = Keyword() # Which authentication realm to log in to
    otp_secret = Keyword()
    mfa_enabled = Boolean()
    local_auth = Boolean()
    sso_auth = Boolean()
    from_sso_auto_provision = Boolean()
    watched_cases = Keyword() # What cases is the user currently watching
    notification_settings = Object(UserNotificationSettings)
    hide_product_updates = Boolean()
    access_scope = Nested(OrganizationScope)

    class Index: # pylint: disable=too-few-public-methods
        ''' Defines the index to use '''
        name = 'reflex-users'
        settings = {
            'refresh_interval': '1s'
        }
        version = "0.1.5"

    def get_access_scope_orgs(self):
        '''Returns the UUIDs of the organizations the user has access to'''
        uuids = [scope.organization for scope in self.access_scope]
        if self.organization not in uuids:
            uuids.append(self.organization)
        return uuids
    
    def has_org_access(self, organization):
        ''' Checks if the user has access to the specified organization '''

        if self.access_scope is None:
            return False

        for scope in self.access_scope:
            if scope.organization == organization:
                return True

        return False
    
    def scope_permissions(self, organization=None):
        ''' Returns this users permissions for the specified organization
        based on the role assigned in their permission scope mapping
        '''
        
        if self.organization == organization or organization is None:
            self.load_role()
            return self.role.permissions
        
        for scope in self.access_scope:
            if scope.organization == organization:
                role = utils.get_role_by_uuid(scope.role)
                return role.permissions
        return {}
    
    def has_org_permission(self, permission, organization=None):
        ''' Checks if the user has the specified permission for the specified organization as
        defined in their scope mapping. By default the user has access to their own organization
        from an organizational scope but their permissions are defined by their direct role
        membership
        '''

        self.load_role()

        if organization is not None:
            if self.organization == organization:
                return hasattr(self.role.permissions, permission) and getattr(self.role.permissions, permission) is True
            
            for scope in self.access_scope:
                if scope.organization == organization:
                    role = Role.get_by_uuid(scope.role)
                    return hasattr(role.permissions, permission) and getattr(role.permissions, permission) is True
        else:
            return hasattr(self.role.permissions, permission) and getattr(self.role.permissions, permission) is True
        
        return False
        
    def watch_case(self, case_uuid):
        ''' Adds a case to the list of cases the user is watching '''

        if self.watched_cases is None:
            self.watched_cases = []

        if case_uuid not in self.watched_cases:
            self.watched_cases.append(case_uuid)
            self.save()

    def unwatch_case(self, case_uuid):
        ''' Removes a case from the list of cases the user is watching '''

        if self.watched_cases is None:
            self.watched_cases = []

        if case_uuid in self.watched_cases:
            self.watched_cases.remove(case_uuid)
            self.save()


    @classmethod
    def scoped_search(cls):
        ''' Returns a search object that is scoped to the current user '''
        
        search = cls.search()

        current_user = request.current_user
        if current_user and current_user.request_org_filter:
            search = search.filter('terms', organization=current_user.request_org_filter)

        import json
        print(f"Search: {json.dumps(search.to_dict(), default=str)}")

        results = search.execute()
        return results


    def set_password(self, password):
        '''
        Encrypts the password for the user. The Document base class
        does not support @property setters/getters so a custom function
        is required to make this work
        '''

        self.password_hash = FLASK_BCRYPT.generate_password_hash(
            password).decode('utf-8')
        self.save()

    def generate_api_key(self):
        '''
        Generates a long living API key, which the user can use to make
        API calls without having to authenticate using username/password

        The API Key should only be presented once and will be added to the
        expired token table
        '''

        organization = Organization.get_by_uuid(self.organization)

        _api_key = jwt.encode({
            'uuid': self.uuid,
            'organization': self.organization,
            'default_org': organization.default_org if organization else False,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(days=365),
            'iat': datetime.datetime.utcnow(),
            'type': 'api'
        }, current_app.config['SECRET_KEY'])

        if self.api_key is not None:
            expired_token = ExpiredToken(token=self.api_key)
            expired_token.save()
            self.api_key = _api_key
        else:
            self.api_key = _api_key
        self.save()
        return {'api_key': self.api_key}

    def create_access_token(self):
        '''
        Generates an access_token that is presented each time the
        user calls the API, valid for 6 hours by default
        '''

        organization = Organization.get_by_uuid(self.organization)
        settings = Settings.load(organization=self.organization)

        jwt_exp = settings.logon_expire_at if hasattr(settings,'logon_expire_at') and settings.logon_expire_at else 6

        _access_token = jwt.encode({
            'uuid': self.uuid,
            'organization': self.organization,
            'default_org': organization.default_org if organization else False,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=60*jwt_exp),
            'iat': datetime.datetime.utcnow(),
            'type': 'user'
        }, current_app.config['SECRET_KEY'])

        return _access_token
    
    @property
    def roles(self):
        ''' Returns a list of all the roles the user is a member of '''
        return [r for r in Role.search().filter('term', members=self.uuid).scan()]

    def create_password_reset_token(self):
        _token = jwt.encode({
            'uuid': self.uuid,
            'organization': self.organization,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30),
            'iat': datetime.datetime.utcnow(),
            'type': 'password_reset'
        }, current_app.config['SECRET_KEY'])

        return _token

    def create_mfa_challenge_token(self):
        ''' Creates a JWT that is used on MFA TOTP requests to make sure the 
        individual attempting to perform a TOTP validation actually made it
        through username/password validation first
        '''

        _token = jwt.encode({
            'uuid': self.uuid,
            'organization': self.organization,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30),
            'iat': datetime.datetime.utcnow(),
            'type': 'mfa_challenge'
        }, current_app.config['SECRET_KEY'])

        return _token

    def create_refresh_token(self, user_agent_string):

        organization = Organization.get_by_uuid(self.organization)

        _refresh_token = jwt.encode({
            'uuid': self.uuid,
            'organization': self.organization,
            'default_org': organization.default_org if organization else False,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(days=30),
            'iat': datetime.datetime.utcnow(),
            'type': 'refresh'
        }, current_app.config['SECRET_KEY'])

        #user_agent_hash = hashlib.md5(user_agent_string).hexdigest()

        # refresh_token = RefreshToken.query.filter_by(
        #    user_agent_hash=user_agent_hash).first()

        # if not refresh_token:
        #    refresh_token = RefreshToken(
        #        user_uuid=self.uuid, refresh_token=_refresh_token, user_agent_hash=user_agent_hash)
        #    refresh_token.create()
        #    _refresh_token = refresh_token.refresh_token
        # else:
        #    refresh_token.refresh_token = _refresh_token
        #    db.session.commit()

        return _refresh_token

    def check_password(self, password):
        '''
        Tries to validate the users password against the
        local authentication database
        '''

        return FLASK_BCRYPT.check_password_hash(self.password_hash, password)

    def ldap_login(self, password):
        '''
        If configured in the organizations settings
        will attempt to log the user in via LDAP
        '''

        raise NotImplementedError
    
    @property
    def permissions(self):
        '''
        Returns a list of all the users permissions
        '''

        role = Role.search().query('term', members=self.uuid).scan()

        # If there is more than one role assigned to the user
        # merge the permissions together such that any permission that is true
        # overrides false
        permissions = {}
        for r in role:
            for p in r.permissions:
                if p not in permissions:
                    permissions[p] = r.permissions[p]
                else:
                    if r.permissions[p] is True:
                        permissions[p] = r.permissions[p]
        return permissions

    def has_right(self, permission):
        '''
        Checks to see if the user has the proper
        permissions to perform an API action
        '''

        permissions = self.permissions

        if permission in permissions and permissions[permission]:
            return True
        return False

    @classmethod
    def get_by_organization(self, organization):
        response = self.search().query(
            'term', organization=organization).execute()
        return response

    @classmethod
    def get_by_username(self, username, as_text=True):

        field = 'username' if as_text else 'username__keyword'
        
        if isinstance(username, str):
            response = self.search().query(
                'match', **{field: username}).execute()
            if response:
                response = response[0]

        if isinstance(username, list):
            response = self.search().query(
                'terms', **{field: username}).execute()
        return response

    @classmethod
    def get_by_email(self, email, as_text=True):

        field = 'email' if as_text else 'email__keyword'

        response = self.search().query(
            'match', **{field: email})
        response= response.source(excludes=[])

        response = response.execute()
        if response:
            user = response[0]
            return user
        return response

    def unlock(self):
        '''
        Unlocks a user account and resets their failed_logons back to 0
        '''
        if self.locked:
            self.locked = False
            self.failed_logons = 0
            self.save()

    def load_roles(self):
        self.role = [r for r in Role.search().filter('term', members=self.uuid).scan()]

    def load_role(self):
        self.role = Role.get_by_member(self.uuid)

    def get_totp_uri(self):
        '''
        Returns a TOTP/HOTP URI for QR encoding to add
        MFA to an account
        '''
        return 'otpauth://totp/Reflex:{0}?secret={1}&issuer=Reflex' \
            .format(self.username, self.otp_secret)

    def generate_mfa_secret(self, **kwargs):
        ''' Sets an OTP secret for the user when they enabled MFA
        '''

        if self.otp_secret is None:
            self.update(otp_secret = base64.b32encode(os.urandom(15)).decode('utf-8'))

    def enable_mfa(self):
        ''' Removes the otp secret when the user disables MFA
        '''
        
        self.update(mfa_enabled = True)

    def disable_mfa(self):
        ''' Removes the otp secret when the user disables MFA
        '''
        self.update(mfa_enabled = False, otp_secret = None)

        #self.save()

    def verify_mfa_setup_complete(self, token):
        ''' Once the user submits a TOTP that is correct enable MFA'''
        
        if onetimepass.valid_totp(token, self.otp_secret):
            self.update(mfa_enabled=True)
            return True
        return False

    def verify_totp(self, token):
        ''' Checks to see if the submitted TOTP token is valid'''
        return onetimepass.valid_totp(token, self.otp_secret)
    
    def is_default_org(self):
        ''' Checks to see if the user belongs to the default org'''
        if hasattr(self, 'default_org'):
            return self.default_org
        return False


class OrganizationSLASettings(InnerDoc):
    '''
    Defines all the organizational SLA settings
    '''
    sla_enabled = Boolean()
    holidays = Keyword() # A list of dates that are holidays stored as YYYY-MM-DD
    work_hours = Keyword() # A list of work hours stored as HH:MM-HH:MM
    work_hours_override_default = Boolean() # If true the work hours will override the default work hours
    holidays_override_default = Boolean() # If true the holidays will override the default holidays


class Organization(base.BaseDocument):
    '''
    Defines an Organization/Tenant that users and other objects belong to
    '''

    class Index():
        name = 'reflex-organizations'
        settings = {
            'refresh_interval': '1s'
        }

    name = Keyword()
    description = Text(fields={'keyword':Keyword()})
    url = Keyword()
    logon_domains = Keyword()
    default_org = Boolean()
    install_uuid = Keyword()

    @classmethod
    def get_by_name(self, name):
        response = self.search().query(
            'match', name=name).execute()
        if response:
            org = response[0]
            return org
        return response

    @classmethod
    def get_by_logon_domain(self, domains):
        response = self.search()
        response = response.filter('terms', logon_domains=domains)
        response = response.execute()
        if response:
            return response[0]
        return response


class Permission(InnerDoc):
    '''
    Defines what permissions are available in the system for a
    specified role
    '''

    # User Permissions
    add_user = Boolean()
    update_user = Boolean()
    delete_user = Boolean()
    add_user_to_role = Boolean()
    remove_user_from_role = Boolean()
    reset_user_password = Boolean()
    unlock_user = Boolean()
    view_users = Boolean()

    # Role Permissions
    add_role = Boolean()
    update_role = Boolean()
    delete_role = Boolean()
    set_role_permissions = Boolean()
    view_roles = Boolean()

    # User Group Permissions
    create_user_group = Boolean()
    view_user_groups = Boolean()
    update_user_groups = Boolean()
    delete_user_group = Boolean()

    # EVENTS
    add_event = Boolean()  # Allows a user to add an event
    view_events = Boolean()  # Allows a user to view/list events
    view_case_events = Boolean() # Allows a user to see the events on a case
    update_event = Boolean()  # Allows a user to update an events mutable properties
    delete_event = Boolean()  # Allows a user to delete an event

    # EVENT RULES
    create_event_rule = Boolean()
    view_event_rules = Boolean()
    update_event_rule = Boolean()
    delete_event_rule = Boolean()

    # Observable Permissions
    add_observable = Boolean()
    update_observable = Boolean()
    delete_observable = Boolean()
    add_tag_to_observable = Boolean()
    remove_tag_from_observable = Boolean()

    # Playbook Permission
    add_playbook = Boolean()
    update_playbook = Boolean()
    delete_playbook = Boolean()
    view_playbooks = Boolean()
    add_tag_to_playbook = Boolean()
    remove_tag_from_playbook = Boolean()

    # Agent Permissions
    add_agent = Boolean()
    view_agents = Boolean()
    update_agent = Boolean()
    delete_agent = Boolean()
    pair_agent = Boolean()

    # Agent Group Permissions
    add_agent_group = Boolean()
    view_agent_groups = Boolean()
    update_agent_group = Boolean()
    delete_agent_group = Boolean()

    # Input Permissions
    add_input = Boolean()
    view_inputs = Boolean()
    update_input = Boolean()
    delete_input = Boolean()

    # Tag Permissions
    add_tag = Boolean()
    update_tag = Boolean()
    delete_tag = Boolean()
    view_tags = Boolean()

    # Case Permissions
    create_case = Boolean()
    view_cases = Boolean()
    update_case = Boolean()
    delete_case = Boolean()

    # Case File Permissions
    upload_case_files = Boolean()
    view_case_files = Boolean()
    delete_case_files = Boolean()

    # Case Template Task Permissions
    create_case_task = Boolean()
    view_case_tasks = Boolean()
    update_case_task = Boolean()
    delete_case_task = Boolean()

    # Case Template Permissions
    create_case_template = Boolean()
    view_case_templates = Boolean()
    update_case_template = Boolean()
    delete_case_template = Boolean()

    # Case Template Task Permissions
    create_case_template_task = Boolean()
    view_case_template_tasks = Boolean()
    update_case_template_task = Boolean()
    delete_case_template_task = Boolean()

    # Case Comment Permissions
    create_case_comment = Boolean()
    view_case_comments = Boolean()
    update_case_comment = Boolean()
    delete_case_comment = Boolean()

    # Case Status Permissions
    create_case_status = Boolean()
    update_case_status = Boolean()
    delete_case_status = Boolean()

    # Close Reason Permissions
    create_close_reason = Boolean()
    update_close_reason = Boolean()
    delete_close_reason = Boolean()

    # Plugin Permissions
    view_plugins = Boolean()
    create_plugin = Boolean()
    delete_plugin = Boolean()
    update_plugin = Boolean()

    # Credential Permissions
    add_credential = Boolean()
    update_credential = Boolean()
    decrypt_credential = Boolean()
    delete_credential = Boolean()
    view_credentials = Boolean()

    # Organization Administration
    add_organization = Boolean()
    view_organizatons = Boolean()
    update_organization = Boolean()
    delete_organization = Boolean()

    # List Permissions
    add_list = Boolean()
    update_list = Boolean()
    view_lists = Boolean()
    delete_list = Boolean()

    # Data Type Permissions
    create_data_type = Boolean()
    update_data_type = Boolean()

    # Update Settings
    update_settings = Boolean()
    view_settings = Boolean()
    create_persistent_pairing_token = Boolean()

    # API Permissions
    use_api = Boolean()

    # Detections permissions
    create_detection = Boolean()
    update_detection = Boolean()
    view_detections = Boolean()
    delete_detection = Boolean()
    create_detection_repository = Boolean()
    view_detection_repositories = Boolean()
    update_detection_repository = Boolean()
    delete_detection_repository = Boolean()
    share_detection_repository = Boolean()
    subscribe_detection_repository = Boolean()
    create_repo_sharing_token = Boolean()
    create_detection_exclusion = Boolean()
    update_detection_exclusion = Boolean()
    view_detection_exclusions = Boolean()
    delete_detection_exclusion = Boolean()    

    # Notification Channel Permissions
    create_notification_channel = Boolean()
    view_notification_channels = Boolean()
    update_notification_channel = Boolean()
    delete_notification_channel = Boolean()
    view_notifications = Boolean()

    # Agent Policy Permissions
    create_agent_policy = Boolean()
    view_agent_policies = Boolean()
    update_agent_policy = Boolean()
    delete_agent_policy = Boolean()
    create_agent_log_message = Boolean()
    view_agent_logs = Boolean()

    # Service Account Permissions
    create_service_account = Boolean()
    view_service_accounts = Boolean()
    update_service_account = Boolean()
    delete_service_account = Boolean()

    # Asset Permissions
    create_asset = Boolean()
    view_assets = Boolean()
    update_asset = Boolean()
    delete_asset = Boolean()

    # Integration Permissions
    create_integration = Boolean()
    update_integration = Boolean()
    delete_integration = Boolean()
    create_integration_configuration = Boolean()
    update_integration_configuration = Boolean()
    delete_integration_configuration = Boolean()

    # SSO Permissions
    create_sso_provider = Boolean()
    update_sso_provider = Boolean()
    delete_sso_provider = Boolean()
    view_sso_providers = Boolean()

    # SSO Mapping Policies
    create_sso_mapping_policy = Boolean()
    update_sso_mapping_policy = Boolean()
    delete_sso_mapping_policy = Boolean()
    view_sso_mapping_policies = Boolean()


class ServiceAccount(base.BaseDocument):
    '''
    Defines an API key that is used by a service to interact with the API
    '''

    class Index():
        name = 'reflex-service-accounts'
        settings = {
            'refresh_interval': '1s'
        }

    name = Keyword() # The name of the service account, must be unique
    description = Text(fields={'keyword':Keyword()}) # A description of the service account
    permissions = Object(Permission) # The permissions that this service account has
    active = Boolean() # Whether or not this service account is active, if not it cannot be used
    last_used = Date() # The last time this service account was used
    organization_scope = Keyword() # The organizations that this service account can access
    tags = Keyword() # The tags that this service account can access
    expires_at = Date() # The date that this service account expires

    @property
    def username(self):
        return self.name
    
    def has_right(self, permission):
        '''
        Returns true if the service account has the specified permission
        '''
        return getattr(self.permissions, permission)
    
    def has_org_access(self, organization):
        ''' Checks if the user has access to the specified organization '''

        if self.organization_scope is None:
            return False

        if organization in self.organization_scope:
            return True

        return False

    def get_by_name(self, name, organization=None):
        '''
        Returns a service account by name
        '''
        search = ServiceAccount.search()
        if isinstance(name, list):
            search = search.filter('terms', name=name)
        else:
            search = search.filter('term', name=name)

        if organization:
            search = search.filter('term', organization=organization)

        return [o for o in search.scan()]

    def create_access_token(self):
        '''
        Generates an access_token that is presented each time the
        user calls the API, valid for 6 hours by default
        '''

        organization = Organization.get_by_uuid(self.organization)
        settings = Settings.load(organization=self.organization)

        jwt_exp = settings.api_key_expire if hasattr(settings,'api_key_expire') and settings.api_key_expire else 365

        _access_token = jwt.encode({
            'uuid': str(self.uuid),
            'organization': self.organization,
            'default_org': organization.default_org if organization else False,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(days=jwt_exp),
            'iat': datetime.datetime.utcnow(),
            'type': 'service_account'
        }, current_app.config['SECRET_KEY'])

        self.expires_at = (datetime.datetime.utcnow() + datetime.timedelta(days=jwt_exp))
        self.save()

        return _access_token

    def save(self, *args, **kwargs):
        '''
        Saves the service account
        '''
        exists = self.get_by_name(name=self.name)
        success = True
        if exists:
            success = False
            log = EventLog(
                source_user = utils._current_user_id_or_none()['username'],
                source_ip = request.remote_addr,
                status = 'failure',
                message = f'Attempt to create a service account with the name {self.name} failed because a service account with that name already exists'
            )
            log.save()
            raise ValidationError('A service account with that name already exists')
            
        super(ServiceAccount, self).save(*args, **kwargs)

        log = EventLog(
            source_user = utils._current_user_id_or_none(),
            source_ip = request.remote_addr,
            status = 'success',
            message = f'Service account {self.name} created'
        )


class Role(base.BaseDocument):
    '''
    A role in the Reflex system defines what a user can do
    They could be an administrator, an analyst, or a custom role
    that can only perform certain actions
    '''

    name = Keyword()  # The name of the role (should be unique)
    description = Text(fields={'keyword':Keyword()})  # A brief description of the role
    members = Keyword()  # Contains a list of user IDs
    permissions = Nested(Permission)
    system_generated = Boolean() # If this is a default Role in the system

    class Index: # pylint: disable=too-few-public-methods
        ''' Defines the index to use '''
        name = 'reflex-user-roles'
        settings = {
            'refresh_interval': '1s'
        }

    def add_user_to_role(self, user_id):
        '''
        Adds users unique IDs to the members field
        '''
        if isinstance(user_id, list):
            self.members = self.members + user_id
        else:
            if self.members and user_id not in self.members:
                self.members.append(user_id)
            else:
                self.members = [user_id]
        self.save(refresh=True)

    def remove_user_from_role(self, user_id):
        '''
        Removes members from the members field
        '''
        if isinstance(user_id, list):
            self.members = [m for m in self.members if m not in user_id]
        else:
            if self.members is not None and user_id in self.members:
                self.members.remove(user_id)
        self.save(refresh=True)

    @classmethod
    def get_by_member(self, uuid):
        response = self.search().query('match', members=uuid).execute()
        if response:
            role = response[0]
            return role
        return response

    @classmethod
    def get_by_name(self, name, organization=None):
        '''
        Fetches a document by the name field
        Uses a term search on a keyword field for EXACT matching
        '''
        response = self.search()
        response = response.filter('term', name=name)
        if organization:
            response=response.filter('term', organization=organization)
            
        response = response.execute()
        if response:
            user = response[0]
            return user
        return response
    
    @classmethod
    def get_by_organization(self, organization):
        response = self.search().query(
            'term', organization=organization).scan()
        return [r for r in response]


class ExpiredToken(base.BaseDocument):
    '''
    An expired JWT token that prevents users from reusing them
    '''

    token = Keyword()

    class Index: # pylint: disable=too-few-public-methods
        ''' Defines the index to use '''
        name = 'reflex-expired-tokens'
