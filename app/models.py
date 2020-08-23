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


# Tag relationships
playbook_tag_association = db.Table('tag_playbook', db.metadata,
    db.Column('playbook_uuid', db.String, db.ForeignKey('playbook.uuid')),
    db.Column('tag_id', db.String, db.ForeignKey('tag.uuid'))
)


class Base(db.Model):

    __abstract__ = True

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    uuid = db.Column(db.String, unique=True, default=generate_uuid)
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())
    modified_at = db.Column(db.DateTime, default=db.func.current_timestamp(),
                            onupdate=db.func.current_timestamp())

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

    # Playbook Permission
    add_playbook = db.Column(db.Boolean, default=False)
    update_playbook = db.Column(db.Boolean, default=False)
    delete_playbook = db.Column(db.Boolean, default=False)
    view_playbooks = db.Column(db.Boolean, default=False)
    add_tag_to_playbook = db.Column(db.Boolean, default=False)
    remove_tag_from_playbook = db.Column(db.Boolean, default=False)

    # Tag Permissions
    add_tag = db.Column(db.Boolean, default=False)
    update_tag = db.Column(db.Boolean, default=False)
    delete_tag = db.Column(db.Boolean, default=False)
    view_tags = db.Column(db.Boolean, default=False)

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
    #tasks = db.relationship('CaseTask', back_populates='assigned_to')

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
            'iat': datetime.datetime.now()
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


class RefreshToken(Base):

    user_uuid = db.Column(db.String(100))
    refresh_token = db.Column(db.String(200))
    user_agent_hash = db.Column(db.String(64))


class AuthTokenBlacklist(Base):

    auth_token = db.Column(db.String(200))


class Playbook(Base):

    name = db.Column(db.String(255), unique=True, nullable=False)
    description = db.Column(db.String(255))
    enabled = db.Column(db.Boolean(), default=True)
    tags = db.relationship('Tag', secondary=playbook_tag_association)


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