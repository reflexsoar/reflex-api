import datetime
import uuid
import hashlib
import jwt
import secrets
import base64
from flask import current_app
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.sql import func, text
from sqlalchemy.orm import validates
from sqlalchemy.exc import IntegrityError
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import InvalidToken
from app import FLASK_BCRYPT, db


def generate_uuid():
    ''' Returns a UUID for objects when they are created '''

    return str(uuid.uuid4())


# Relationships
playbook_tag_association = db.Table('tag_playbook', db.metadata,
    db.Column('playbook_uuid', db.String, db.ForeignKey('playbook.uuid')),
    db.Column('tag_id', db.String, db.ForeignKey('tag.uuid'))
)

alert_tag_association = db.Table('tag_alert', db.metadata,
    db.Column('alert_uuid', db.String, db.ForeignKey('alert.uuid')),
    db.Column('tag_id', db.String, db.ForeignKey('tag.uuid'))
)

observable_tag_association = db.Table('tag_observable', db.metadata,
    db.Column('observable_uuid', db.String, db.ForeignKey('observable.uuid')),
    db.Column('tag_id', db.String, db.ForeignKey('tag.uuid'))
)

observable_alert_association = db.Table('observable_alert', db.metadata,
    db.Column('observable_uuid', db.String, db.ForeignKey('observable.uuid')),
    db.Column('alert_uuid', db.String, db.ForeignKey('alert.uuid'))
)

input_tag_association = db.Table('tag_input', db.metadata,
    db.Column('input_uuid', db.String, db.ForeignKey('input.uuid')),
    db.Column('tag_id', db.String, db.ForeignKey('tag.uuid'))
)

agent_role_agent_association = db.Table('agent_role_agent', db.metadata,
    db.Column('agent_uuid', db.String, db.ForeignKey('agent.uuid')),
    db.Column('agent_role_uuid', db.String, db.ForeignKey('agent_role.uuid'))
)

agent_group_agent_association = db.Table('agent_group_agent', db.metadata,
    db.Column('agent_uuid', db.String, db.ForeignKey('agent.uuid')),
    db.Column('agent_group_uuid', db.String, db.ForeignKey('agent_group.uuid'))
)

agent_input_association = db.Table('agent_input', db.metadata,
    db.Column('agent_uuid', db.String, db.ForeignKey('agent.uuid')),
    db.Column('input_uuid', db.String, db.ForeignKey('input.uuid'))
)

observable_case_association = db.Table('observable_case', db.metadata,
    db.Column('observable_uuid', db.String, db.ForeignKey('observable.uuid')),
    db.Column('case_uuid', db.String, db.ForeignKey('case.uuid'))
)

alert_case_association = db.Table('alert_case', db.metadata,
    db.Column('alert_uuid', db.String, db.ForeignKey('alert.uuid')),
    db.Column('case_uuid', db.String, db.ForeignKey('case.uuid'))
)

case_tag_association = db.Table('tag_case', db.metadata,
    db.Column('case_uuid', db.String, db.ForeignKey('case.uuid')),
    db.Column('tag_id', db.String, db.ForeignKey('tag.uuid'))
)

case_template_tag_association = db.Table('tag_case_template', db.metadata,
    db.Column('case_template_uuid', db.String, db.ForeignKey('case_template.uuid')),
    db.Column('tag_id', db.String, db.ForeignKey('tag.uuid'))
)

user_case_association = db.Table('user_case', db.metadata,
    db.Column('user_uuid', db.String, db.ForeignKey('user.uuid')),
    db.Column('case_uuid', db.String, db.ForeignKey('case.uuid'))
)

plugin_config_association = db.Table('plugin_plugin_config', db.metadata,
    db.Column('plugin_uuid', db.String, db.ForeignKey('plugin.uuid')),
    db.Column('plugin_config.uuid', db.String, db.ForeignKey('plugin_config.uuid'))
)

user_group_association = db.Table('user_group_assignment', db.metadata,
    db.Column('user_uuid', db.String, db.ForeignKey('user.uuid')),
    db.Column('user_group_uuid', db.String, db.ForeignKey('user_group.uuid'))
)

# End relationships


class Base(db.Model):

    __abstract__ = True

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    uuid = db.Column(db.String, unique=True, default=generate_uuid)
    created_at = db.Column(db.DateTime, default=datetime.datetime.now)
    modified_at = db.Column(db.DateTime, default=datetime.datetime.now,
                            onupdate=datetime.datetime.now)
    # TODO : Extend created_by
    # TODO : Extend updated_by

    def update(self, data):
        for k in data:
            if hasattr(self, k):
                setattr(self, k, data[k])
        db.session.commit()

    def create(self):
        # Catch on duplicate insertion and return False to indicate the creation failed
        try:
            db.session.add(self)
            db.session.commit()
            return 0
        except IntegrityError:
            return 1
        except Exception:
            return 2

    def save(self):
        db.session.commit()

    def delete(self):
        db.session.delete(self)
        db.session.commit()

    def __repr__(self):
        return ("<{} {}>".format(self.__class__.__name__, self.id))


class Permission(Base):
    ''' Permissions for a Role '''

    # User Permissions
    add_user = db.Column(db.Boolean, default=False)
    update_user = db.Column(db.Boolean, default=False)
    delete_user = db.Column(db.Boolean, default=False)
    add_user_to_role = db.Column(db.Boolean, default=False)
    remove_user_from_role = db.Column(db.Boolean, default=False)
    reset_user_password = db.Column(db.Boolean, default=False)
    unlock_user = db.Column(db.Boolean, default=False)
    view_users = db.Column(db.Boolean, default=False)

    # Role Permissions
    add_role = db.Column(db.Boolean, default=False)
    update_role = db.Column(db.Boolean, default=False)
    delete_role = db.Column(db.Boolean, default=False)
    set_role_permissions = db.Column(db.Boolean, default=False)
    view_roles = db.Column(db.Boolean, default=False)

    # User Group Permissions
    create_user_group = db.Column(db.Boolean, default=False)
    view_user_groups = db.Column(db.Boolean, default=False)
    update_user_groups = db.Column(db.Boolean, default=False)
    delete_user_group = db.Column(db.Boolean, default=False)

    # Alert Permissions
    add_alert = db.Column(db.Boolean, default=False)
    view_alerts = db.Column(db.Boolean, default=False)
    update_alert = db.Column(db.Boolean, default=False)
    delete_alert = db.Column(db.Boolean, default=False)
    add_tag_to_alert = db.Column(db.Boolean, default=False)
    remove_tag_from_alert = db.Column(db.Boolean, default=False)

    # Observable Permissions
    add_observable = db.Column(db.Boolean, default=False)
    update_observable = db.Column(db.Boolean, default=False)
    delete_observable = db.Column(db.Boolean, default=False)
    add_tag_to_observable = db.Column(db.Boolean, default=False)
    remove_tag_from_observable = db.Column(db.Boolean, default=False)

    # Playbook Permission
    add_playbook = db.Column(db.Boolean, default=False)
    update_playbook = db.Column(db.Boolean, default=False)
    delete_playbook = db.Column(db.Boolean, default=False)
    view_playbooks = db.Column(db.Boolean, default=False)
    add_tag_to_playbook = db.Column(db.Boolean, default=False)
    remove_tag_from_playbook = db.Column(db.Boolean, default=False)

    # Agent Permissions
    view_agents = db.Column(db.Boolean, default=False)
    update_agent = db.Column(db.Boolean, default=False)
    delete_agent = db.Column(db.Boolean, default=False)
    pair_agent = db.Column(db.Boolean, default=False)

    # Agent Group Permissions
    create_agent_group = db.Column(db.Boolean, default=False)
    view_agent_groups = db.Column(db.Boolean, default=False)
    update_agent_group = db.Column(db.Boolean, default=False)
    delete_agent_group = db.Column(db.Boolean, default=False)

    # Input Permissions
    add_input = db.Column(db.Boolean, default=False)
    view_inputs = db.Column(db.Boolean, default=False)
    update_input = db.Column(db.Boolean, default=False)
    delete_input = db.Column(db.Boolean, default=False)

    # Tag Permissions
    add_tag = db.Column(db.Boolean, default=False)
    update_tag = db.Column(db.Boolean, default=False)
    delete_tag = db.Column(db.Boolean, default=False)
    view_tags = db.Column(db.Boolean, default=False)

    # Case Permissions
    create_case = db.Column(db.Boolean, default=False)
    view_cases = db.Column(db.Boolean, default=False)
    update_case = db.Column(db.Boolean, default=False)
    delete_case = db.Column(db.Boolean, default=False)

    # Case Template Permissions
    create_case_template = db.Column(db.Boolean, default=False)
    view_case_templates = db.Column(db.Boolean, default=False)
    update_case_template = db.Column(db.Boolean, default=False)
    delete_case_template = db.Column(db.Boolean, default=False)

    # Case Template Task Permissions
    create_case_template_task = db.Column(db.Boolean, default=False)
    view_case_template_tasks = db.Column(db.Boolean, default=False)
    update_case_template_task = db.Column(db.Boolean, default=False)
    delete_case_template_task = db.Column(db.Boolean, default=False)

    # Case Comment Permissions
    create_case_comment = db.Column(db.Boolean, default=False)
    view_case_comments = db.Column(db.Boolean, default=False)
    update_case_comment = db.Column(db.Boolean, default=False)
    delete_case_comment = db.Column(db.Boolean, default=False)

    # Plugin Permissions
    view_plugins = db.Column(db.Boolean, default=False)
    create_plugin = db.Column(db.Boolean, default=False)
    delete_plugin = db.Column(db.Boolean, default=False)
    update_plugin = db.Column(db.Boolean, default=False)

    # Credential Permissions
    add_credential = db.Column(db.Boolean, default=False)
    update_credential = db.Column(db.Boolean, default=False)
    decrypt_credential = db.Column(db.Boolean, default=False)
    delete_credential = db.Column(db.Boolean, default=False)
    view_credentials = db.Column(db.Boolean, default=False)

    # Role relationship
    roles = db.relationship('Role', back_populates='permissions')


class Role(Base):
    ''' A Users role in the system '''
    name = db.Column(db.String(255), unique=True, nullable=False)
    description = db.Column(db.String(255))
    users = db.relationship('User', back_populates='role')
    agents = db.relationship('Agent', back_populates='role')
    permissions = db.relationship('Permission', back_populates='roles')
    permissions_uuid = db.Column(db.String, db.ForeignKey('permission.uuid'))


class User(Base):
    ''' User model for storing user related stuff '''
    email = db.Column(db.String(255), unique=True, nullable=False)
    username = db.Column(db.String(255), unique=True, nullable=False)
    first_name = db.Column(db.String(255), unique=False, nullable=True)
    last_name = db.Column(db.String(255), unique=False, nullable=True)
    password_hash = db.Column(db.String(100))
    locked = db.Column(db.Boolean, default=False)
    deleted = db.Column(db.Boolean, default=False)
    role = db.relationship('Role', back_populates='users')
    role_uuid = db.Column(db.String, db.ForeignKey('role.uuid'))
    groups = db.relationship('UserGroup', secondary=user_group_association, back_populates='members')

    @property
    def password(self):
        raise AttributeError('password: write-only field')

    @password.setter
    def password(self, password):
        self.password_hash = FLASK_BCRYPT.generate_password_hash(password).decode('utf-8')

    def create_access_token(self):
        _access_token = jwt.encode({
            'uuid': self.uuid,
            'exp': datetime.datetime.now() + datetime.timedelta(minutes=360),
            'iat': datetime.datetime.now(),
            'type': 'user'
        }, current_app.config['SECRET_KEY']).decode('utf-8')
        
        return _access_token

    def create_refresh_token(self, user_agent_string):
        _refresh_token = jwt.encode({
            'uuid': self.uuid,
            'exp': datetime.datetime.now() + datetime.timedelta(days=30),
            'iat': datetime.datetime.now()
        }, current_app.config['SECRET_KEY']).decode('utf-8')

        user_agent_hash = hashlib.md5(user_agent_string).hexdigest()

        refresh_token = RefreshToken.query.filter_by(user_agent_hash=user_agent_hash).first()

        if not refresh_token:
            refresh_token = RefreshToken(user_uuid=self.uuid, refresh_token=_refresh_token, user_agent_hash=user_agent_hash)
            refresh_token.create()
            _refresh_token = refresh_token.refresh_token
        else:
            refresh_token.refresh_token = _refresh_token
            db.session.commit()

        return _refresh_token

    def check_password(self, password):
        return FLASK_BCRYPT.check_password_hash(self.password_hash, password)

    def has_right(self, permission):

        perm = {}
        perm[permission] = True

        role = Role.query.filter_by(uuid=self.role_uuid).first()
        if role:
            permission = Permission.query.filter_by(**perm, uuid=role.permissions_uuid).first()
            if permission:
                return True
            else:
                return False
        else:
            return False


class UserGroup(Base):

    name = db.Column(db.String(255))
    description = db.Column(db.String)
    members = db.relationship('User', secondary=user_group_association, back_populates='groups')


class RefreshToken(Base):

    user_uuid = db.Column(db.String(100))
    refresh_token = db.Column(db.String(200))
    user_agent_hash = db.Column(db.String(64))


class AuthTokenBlacklist(Base):

    auth_token = db.Column(db.String(200))


class Case(Base):

    number = db.Column(db.Integer, autoincrement=True)
    title = db.Column(db.String(255), nullable=False)
    description = db.Column(db.String)
    comments = db.relationship('CaseComment')
    severity = db.Column(db.Integer, default=2)
    owner_uuid = db.Column(db.String, db.ForeignKey('user.uuid'))
    owner = db.relationship('User')
    tlp = db.Column(db.Integer, default=2)
    observables = db.relationship('Observable', secondary=observable_case_association)
    alerts = db.relationship('Alert', secondary=alert_case_association)
    tags = db.relationship('Tag', secondary=case_tag_association)
    status_id = db.Column(db.String, db.ForeignKey('case_status.uuid'))
    status = db.relationship("CaseStatus")
    tasks = db.relationship("CaseTask", back_populates='case')


class CaseTask(Base):

    title = db.Column(db.String)
    order = db.Column(db.Integer, default=0)
    description = db.Column(db.String)
    group_uuid = db.Column(db.String, db.ForeignKey('user_group.uuid'))
    group = db.relationship('UserGroup')
    owner_uuid = db.Column(db.String, db.ForeignKey('user.uuid'))
    owner = db.relationship('User')
    case_uuid = db.Column(db.String, db.ForeignKey('case.uuid'))
    case = db.relationship('Case', back_populates='tasks')
    status = db.Column(db.Integer)


class CaseComment(Base):

    message = db.Column(db.String)
    author_uuid = db.Column(db.String, db.ForeignKey('user.uuid'))
    author = db.relationship('User')
    case_uuid = db.Column(db.String, db.ForeignKey('case.uuid'))


class CaseTemplate(Base):

    title = db.Column(db.String, unique=True)
    description = db.Column(db.String)
    severity = db.Column(db.Integer, default=2)
    owner_uuid = db.Column(db.String, db.ForeignKey('user.uuid'))
    owner = db.relationship('User')
    tlp = db.Column(db.Integer, default=2)
    tags = db.relationship('Tag', secondary=case_template_tag_association)
    status_uuid = db.Column(db.String, db.ForeignKey('case_status.uuid'))
    status = db.relationship('CaseStatus')
    tasks = db.relationship('CaseTemplateTask', back_populates='case_template')


class CaseTemplateTask(Base):

    title = db.Column(db.String)
    order = db.Column(db.Integer, default=0)
    description = db.Column(db.String)
    group_uuid = db.Column(db.String, db.ForeignKey('user_group.uuid'))
    group = db.relationship('UserGroup')
    owner_uuid = db.Column(db.String, db.ForeignKey('user.uuid'))
    owner = db.relationship('User')
    case_template_uuid = db.Column(db.String, db.ForeignKey('case_template.uuid'))
    case_template = db.relationship('CaseTemplate', back_populates='tasks')
    status = db.Column(db.Integer)


class Alert(Base):

    title = db.Column(db.String(255), nullable=False)
    reference = db.Column(db.String(255), nullable=False)
    description = db.Column(db.String, nullable=False)
    tlp = db.Column(db.Integer, default=2)
    severity = db.Column(db.Integer, default=2)
    status_id = db.Column(db.String, db.ForeignKey('alert_status.uuid'))
    status = db.relationship("AlertStatus")
    observables = db.relationship('Observable', secondary=observable_alert_association)
    tags = db.relationship('Tag', secondary=alert_tag_association)
    raw_log = db.Column(db.JSON)


class AlertStatus(Base):

    name = db.Column(db.String(255), nullable=False)
    description = db.Column(db.String, nullable=False)
    closed = db.Column(db.Boolean, default=False)


class CaseStatus(Base):

    name = db.Column(db.String(255), nullable=False)
    description = db.Column(db.String, nullable=False)
    closed = db.Column(db.Boolean, default=False)


class Observable(Base):

    value = db.Column(db.String(255))
    dataType_id = db.Column(db.String, db.ForeignKey('data_type.uuid'))
    dataType = db.relationship("DataType")
    tlp = db.Column(db.Integer)
    tags = db.relationship('Tag', secondary=observable_tag_association)
    ioc = db.Column(db.Boolean, default=False)
    spotted = db.Column(db.Boolean, default=False)


class Agent(Base):

    name = db.Column(db.String(255))
    inputs = db.relationship('Input', secondary=agent_input_association)
    roles = db.relationship('AgentRole', secondary=agent_role_agent_association)
    groups = db.relationship('AgentGroup' ,secondary=agent_group_agent_association)
    active = db.Column(db.Boolean, default=True)
    ip_address = db.Column(db.String)
    last_heartbeat = db.Column(db.DateTime)
    role = db.relationship('Role', back_populates='agents')
    role_uuid = db.Column(db.String, db.ForeignKey('role.uuid'))

    def has_right(self, permission):

        perm = {}
        perm[permission] = True

        role = Role.query.filter_by(uuid=self.role_uuid).first()
        if role:
            permission = Permission.query.filter_by(**perm, uuid=role.permissions_uuid).first()
            if permission:
                return True
            else:
                return False
        else:
            return False


class AgentRole(Base):

    name = db.Column(db.String(255))
    description = db.Column(db.String)


class AgentGroup(Base):

    name = db.Column(db.String(255))
    description = db.Column(db.String)


class DataType(Base):

    name = db.Column(db.String(255))
    description = db.Column(db.String)


class Playbook(Base):

    name = db.Column(db.String(255), unique=True, nullable=False)
    description = db.Column(db.String(255))
    enabled = db.Column(db.Boolean(), default=True)
    tags = db.relationship('Tag', secondary=playbook_tag_association)


class Plugin(Base):
    name = db.Column(db.String(255), unique=True, nullable=False)
    description = db.Column(db.String, nullable=False)
    logo = db.Column(db.String)
    manifest = db.Column(db.JSON, nullable=False)
    config_template = db.Column(db.JSON)
    enabled = db.Column(db.Boolean, default=False)
    filename = db.Column(db.String, nullable=False)
    file_hash = db.Column(db.String)
    configs = db.relationship('PluginConfig', back_populates='plugin')


class PluginConfig(Base):
    name = db.Column(db.String(255), unique=True, nullable=False)
    description = db.Column(db.String, nullable=False)
    config = db.Column(db.JSON, nullable=False)
    plugin_uuid = db.Column(db.String, db.ForeignKey('plugin.uuid'))
    plugin = db.relationship('Plugin', back_populates='configs')


class Input(Base):

    name = db.Column(db.String(255), unique=True, nullable=False)
    description = db.Column(db.String, nullable=False)
    plugin = db.Column(db.String, nullable=False)
    enabled = db.Column(db.Boolean, default=True)
    config = db.Column(db.JSON, nullable=False)
    credential_id = db.Column(db.String, db.ForeignKey('credential.uuid'))
    credential = db.relationship('Credential')
    tags = db.relationship('Tag', secondary=input_tag_association)
    field_mapping = db.Column(db.JSON, nullable=False)


class Credential(Base):
    ''' Stores a credential that can be used by worker processes '''

    name = db.Column(db.String(255), unique=True, nullable=False)
    description = db.Column(db.String(255))
    username = db.Column(db.String(255))
    secret = db.Column(db.String)

    def _derive_key(self, secret: bytes, salt: bytes, iterations: int = 100_000) -> bytes:

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=iterations,
            backend=default_backend()
        )
        return base64.urlsafe_b64encode(kdf.derive(secret))

    def encrypt(self, message: bytes, secret: str, iterations: int = 100_000) -> bytes:
        iterations = 100_000
        salt = secrets.token_bytes(16)
        key = self._derive_key(secret.encode(), salt, iterations)
        self.secret = base64.urlsafe_b64encode(b'%b%b%b' % (salt, iterations.to_bytes(4, 'big'), 
                                                               base64.urlsafe_b64encode(Fernet(key).encrypt(message))))

    def decrypt(self, secret: str) -> bytes:
        decoded = base64.urlsafe_b64decode(self.secret)
        salt, iter, token = decoded[:16], decoded[16:20], base64.urlsafe_b64decode(decoded[20:])
        iterations = int.from_bytes(iter, 'big')
        key = self._derive_key(secret.encode(), salt, iterations)
        try:
            return Fernet(key).decrypt(token).decode()
        except InvalidToken:
            return None

class Tag(Base):

    name = db.Column(db.String(200))
    color = db.Column(db.String(7))

    @validates('name')
    def convert_lower(self, key, value):
        return value.lower()