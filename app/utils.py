import jwt
import base64
import datetime

from flask import request, current_app, abort
from .models import User, AuthTokenBlacklist, Agent

def generate_token(uuid, duration=10, token_type='agent'):
    _access_token = jwt.encode({
        'uuid': uuid,
        'exp': datetime.datetime.now() + datetime.timedelta(minutes=duration),
        'iat': datetime.datetime.now(),
        'type': token_type
    }, current_app.config['SECRET_KEY']).decode('utf-8')
    
    return _access_token


def token_required(f):
    # Token Wrapper

    def wrapper(*args, **kwargs):
        current_user = _check_token
        return f(*args, **kwargs, current_user=current_user)

    wrapper.__doc__ = f.__doc__
    wrapper.__name__ = f.__name__
    return wrapper


def user_has(permission):
    # User permissions

    def decorator(f):
        def wrapper(*args, **kwargs):
            if(current_app.config['PERMISSIONS_DISABLED']):
                return f(*args, **kwargs)
            current_user = _check_token()

            # If this is a pairing token and its the add_agent permission
            # bypass the route guard and let the route finish
            if current_user == 'PAIRING' and permission == 'add_agent':
                return f(*args, **kwargs)
            try:
                if current_user.has_right(permission):
                    return f(*args, **kwargs)
            except Exception:
                abort(401, 'Unauthorized.')
            else:
                abort(401, 'Unauthorized.')

        wrapper.__doc__ = f.__doc__
        wrapper.__name__ = f.__name__
        return wrapper
    return decorator


def _get_current_user():
    ''' Just returns the current user via their JWT '''

    current_user = _check_token()
    return current_user


def _check_token():
    ''' Check the validity of the token provided '''

    auth_header = request.headers.get('Authorization')
    current_user = None
    if auth_header:
        try:
            access_token = auth_header.split(' ')[1]   
            try:
                token = jwt.decode(access_token, current_app.config['SECRET_KEY'])
                if 'type' in token and token['type'] == 'agent':
                    current_user = Agent.query.filter_by(uuid=token['uuid']).first()
                    
                # The pairing token can only be used on the add_agent endpoint
                # and because the token is signed we don't have to worry about 
                # someone adding a the pairing type to their token
                elif 'type' in token and token['type'] == 'pairing':
                    current_user = "PAIRING"
                else:
                    current_user = User.query.filter_by(uuid=token['uuid']).first()
                blacklisted = AuthTokenBlacklist.query.filter_by(auth_token=access_token).first()
                if blacklisted:
                    raise ValueError('Token retired.')

                if current_user == 'PAIRING':
                    blacklist = AuthTokenBlacklist(auth_token = access_token)
                    blacklist.create()
            except ValueError:
                abort(401, 'Token retired.')
            except jwt.ExpiredSignatureError:
                abort(401, 'Access token expired.')
            except (jwt.DecodeError, jwt.InvalidTokenError):
                abort(401, 'Invalid access token.')
            except:
                abort(401, 'Unknown token error.')

        except IndexError:
            raise jwt.InvalidTokenError
    else:
        abort(403, 'Access token required.')
    return current_user