import jwt
import base64
import datetime
import smtplib
import logging
import ipaddress

from flask import request, current_app, abort
from .models import User, ExpiredToken, Settings, Agent


def generate_token(uuid, duration=10, token_type='agent'):
    token_data = {
        'uuid': uuid,
        'iat': datetime.datetime.utcnow(),
        'type': token_type
    }

    if duration:
        token_data['exp'] = datetime.datetime.utcnow() + datetime.timedelta(minutes=duration)
    _access_token = jwt.encode(token_data, current_app.config['SECRET_KEY'])
    
    return _access_token


def ip_approved(f):
    '''
    Returns 401 Unauthorized if the requestor 
    is not in the approved IP list
    '''

    def wrapper(*args, **kwargs):

        settings = Settings.load()

        if hasattr(settings, 'require_approved_ips') and settings.require_approved_ips:

            ip_list = settings.approved_ips
            if request.headers.getlist('X-Forwarded-For'):
                source_ip = request.headers.getlist('X-Forwarded-For')[0]
            else:
                source_ip = request.remote_addr

            source_ip = ipaddress.ip_address(source_ip)

            approved = False

            for ip in ip_list:
                if '/' in ip:
                    network = ipaddress.ip_network(ip)
                    if source_ip in network:
                        approved = True
                else:
                    ip = ipaddress.ip_address(ip)
                    if source_ip == ip:
                        approved = True
            if not approved:
                abort(401, "Unauthorized")

        return f(*args, **kwargs)
        
    
    wrapper.__doc__ = f.__doc__
    wrapper.__name__ = f.__name__
    return wrapper        


def token_required(f):
    # Token Wrapper

    def wrapper(*args, **kwargs):

        current_user = _check_token()
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
            current_user = kwargs['current_user']

            # If this is a pairing token and its the add_agent permission
            # bypass the route guard and let the route finish
            if isinstance(current_user, dict) and current_user['type'] == 'pairing' and permission == 'add_agent':
                return f(*args, **kwargs)
            if not isinstance(current_user, list) and current_user.has_right(permission):
                return f(*args, **kwargs)
            else:
                abort(401, 'You do not have permission to perform this action.')

        wrapper.__doc__ = f.__doc__
        wrapper.__name__ = f.__name__
        return wrapper
    return decorator


def _get_current_user():
    ''' Just returns the current user via their JWT '''

    current_user = _check_token()
    return current_user


def check_password_reset_token(token):
    '''
    Checks the validity of a password reset token
    '''

    try:
        decoded_token = jwt.decode(token, current_app.config['SECRET_KEY'])

        expired = ExpiredToken.search().filter('term', token=token).execute()
        if expired:
            abort(401, 'Token retired.')

        if 'type' in decoded_token and decoded_token['type'] == 'password_reset':
            user = User.get(id=decoded_token['id'])
            return user
        
    except ValueError:
        abort(401, 'Token retired.')
    except jwt.ExpiredSignatureError:
        abort(401, 'Access token expired.')
    except (jwt.DecodeError, jwt.InvalidTokenError):
        abort(401, 'Invalid access token.')
    except Exception as e:
        abort(401, str(e))


def _check_token():
    ''' Check the validity of the token provided '''

    auth_header = request.headers.get('Authorization')
    current_user = None
    if auth_header:
        try:
            access_token = auth_header.split(' ')[1]   


            expired = ExpiredToken.search().filter('term', token=access_token).execute()
            if expired:
                abort(401, 'Token retired.')
            try:
                token = jwt.decode(access_token, current_app.config['SECRET_KEY'], algorithms=['HS256'])

                # If this is an agents token pull the agents information and
                # set it to current_user

                # TODO: ADD AGENT FUNCTIONALITY BACK IN
                if 'type' in token and token['type'] == 'agent':
                    current_user = Agent.query.filter_by(uuid=token['uuid']).first()

                # Refresh and Password Reset tokens should not be used to access the API
                # only to refresh an access token or reset the password

                # TODO: ADD REFRESH/RESET FUNCTIONALITY BACK IN
                elif 'type' in token and token['type'] in ['refresh','password_reset']:
                    abort(401, 'Unauthorized')
                    
                # The pairing token can only be used on the add_agent endpoint
                # and because the token is signed we don't have to worry about 
                # someone adding a the pairing type to their token

                elif 'type' in token and token['type'] == 'pairing':
                    current_user = token
                else:
                    try:
                        current_user = User.get_by_uuid(token['uuid'])
                    except:
                        abort(401, 'Unknown user error.')

                    # If the user is currently locked
                    # reject the accesss_token and expire it
                    if current_user.locked:
                        expired = ExpiredToken(token=access_token)
                        expired.save()
                        abort(401, 'Unauthorized')

            except ValueError:
                abort(401, 'Token retired.')
            except jwt.ExpiredSignatureError:
                abort(401, 'Access token expired.')
            except (jwt.DecodeError, jwt.InvalidTokenError) as e:
                abort(401, 'Invalid access token.')
            except Exception as e:
                abort(401, 'Unknown token error.')

        except IndexError:
            abort(401, 'Invalid access token.')
            raise jwt.InvalidTokenError
    else:
        abort(403, 'Access token required.')
    return current_user
