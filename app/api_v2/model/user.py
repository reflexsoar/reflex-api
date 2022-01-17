'''/app/api_v2/model/user.py

Contains all the models related to users of the system
'''

import datetime
import jwt
import onetimepass
import base64
import os
from flask import current_app
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
    utils
)

FLASK_BCRYPT = Bcrypt()

class User(base.BaseDocument):
    '''
    A User of the Reflex system
    '''

    email = Text(fields={'keyword':Keyword()})
    username = Text(fields={'keyword':Keyword()})
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

    class Index: # pylint: disable=too-few-public-methods
        ''' Defines the index to use '''
        name = 'reflex-users'

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

        _access_token = jwt.encode({
            'uuid': self.uuid,
            'organization': self.organization,
            'default_org': organization.default_org if organization else False,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=360),
            'iat': datetime.datetime.utcnow(),
            'type': 'user'
        }, current_app.config['SECRET_KEY'])

        return _access_token

    @property
    def permissions(self):
        return [
            k for k in self.role.permissions.__dict__
            if k not in [
                '_sa_instance_state',
                'created_at',
                'modified_at',
                'created_by',
                'modified_by',
                'uuid',
                'id'
            ]
            and self.role.permissions.__dict__[k] is True
        ]

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

    def has_right(self, permission):
        '''
        Checks to see if the user has the proper
        permissions to perform an API action
        '''

        role = Role.search().query('term', members=self.uuid).execute()
        if role:
            role = role[0]

        if hasattr(role.permissions, permission) and getattr(role.permissions, permission):
            return True
        return False

    @classmethod
    def get_by_username(self, username):
        response = self.search().query(
            'match', username=username).execute()
        if response:
            user = response[0]
            return user
        return response

    @classmethod
    def get_by_email(self, email):
        response = self.search().query(
            'match', email=utils.escape_special_characters(email)).execute()
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
            self.otp_secret = base64.b32encode(os.urandom(15)).decode('utf-8')

        self.save()

    def enable_mfa(self):
        ''' Removes the otp secret when the user disables MFA
        '''
        
        self.mfa_enabled = True
        self.save()

    def disable_mfa(self):
        ''' Removes the otp secret when the user disables MFA
        '''
        
        if self.otp_secret is not None:
            self.otp_secret = None

        self.mfa_enabled = False

        self.save()

    def verify_mfa_setup_complete(self, token):
        ''' Once the user submits a TOTP that is correct enable MFA'''
        
        if onetimepass.valid_totp(token, self.otp_secret):
            self.mfa_enabled = True
            self.save()
            return True
        return False

    def verify_totp(self, token):
        ''' Checks to see if the submitted TOTP token is valid'''
        return onetimepass.valid_totp(token, self.otp_secret)


class Organization(base.BaseDocument):
    '''
    Defines an Organization/Tenant that users and other objects belong to
    '''

    class Index():
        name = 'reflex-organizations'

    name = Keyword()
    description = Text()
    url = Keyword()
    logon_domains = Keyword()
    default_org = Boolean()


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


class Role(base.BaseDocument):
    '''
    A role in the Reflex system defines what a user can do
    They could be an administrator, an analyst, or a custom role
    that can only perform certain actions
    '''

    name = Keyword()  # The name of the role (should be unique)
    description = Text()  # A brief description of the role
    members = Keyword()  # Contains a list of user IDs
    permissions = Nested(Permission)

    class Index: # pylint: disable=too-few-public-methods
        ''' Defines the index to use '''
        name = 'reflex-user-roles'

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
        self.save()

    def remove_user_from_role(self, user_id):
        '''
        Removes members from the members field
        '''
        if isinstance(user_id, list):
            self.members = [m for m in self.members if m not in user_id]
        else:
            if self.members is not None:
                self.members.remove(user_id)
        self.save()

    @classmethod
    def get_by_member(self, uuid):
        response = self.search().query('match', members=uuid).execute()
        if response:
            role = response[0]
            return role
        return response

    @classmethod
    def get_by_name(self, name):
        '''
        Fetches a document by the name field
        Uses a term search on a keyword field for EXACT matching
        '''
        response = self.search().query('term', name=name).execute()
        if response:
            user = response[0]
            return user
        return response


class ExpiredToken(base.BaseDocument):
    '''
    An expired JWT token that prevents users from reusing them
    '''

    token = Keyword()

    class Index: # pylint: disable=too-few-public-methods
        ''' Defines the index to use '''
        name = 'reflex-expired-tokens'
