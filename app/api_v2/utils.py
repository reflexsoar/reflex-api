from app.api_v2.model.user import Organization
import jwt
import datetime
import smtplib
import string
import random
import ipaddress
import math
import elasticapm
from functools import lru_cache

from flask import request, current_app, abort
from .model import EventLog, User, ExpiredToken, Settings, Agent, ServiceAccount, Organization

@lru_cache(maxsize=None)
def org_uuid_to_name(org_id):
    """Returns the organizatio name based on the UUID"""
    if org_id:
        organization = Organization.get_by_uuid(org_id)
        if organization:
            return organization.name
    return ""

def random_ending(prefix=None, length=10):
    '''
    Generates a random ending that is appended to strings when
    a item is deleted
    '''
    ending = '-'
    letters = string.ascii_lowercase+string.digits

    if prefix:
        ending = ending+prefix+'-'

    ending += ''.join(random.choice(letters) for i in range(length))
    return ending
    

def page_results(search_object, page, page_size):
    '''
    Calculates the pagination information and applies a slice to
    the search_object
    '''
    start = (page - 1)*page_size
    end = (page * page_size)
    search_object = search_object[start:end]
    total_results = search_object.count()
    pages = math.ceil(float(total_results / page_size))
    return search_object, total_results, pages

def escape_special_characters_rql(value):
    '''
    Escapes characters that may interfere with how an RQL query
    is created
    '''

    characters = {
        '\\': '\\\\',
        '"': r'\"',
        "'": r"\'",
        
    }

    if isinstance(value, str):
        for c in characters:
            value = value.replace(c, characters[c])

    return value


def log_event(event_type, *args, **kwargs):
    '''
    Handles logging to the Reflex log database as well
    as to file handler streams and console handler streams
    TODO: Add file handler stream
    TODO: Add console handler stream
    '''

    #with current_app.app_context():
    #    current_app.logger.warning('Event test')

    raw_event = {
        'event_type': event_type
    }

    raw_event.update(kwargs)

    if 'organization' in kwargs:
        raw_event['organization'] = kwargs['organization']

    log = EventLog(**raw_event)
    log.save()


def generate_token(uuid, duration=10, organization=None, token_type='agent'):
    token_data = {
        'uuid': uuid,
        'organization': organization,
        'iat': datetime.datetime.utcnow(),
        'type': token_type
    }

    if duration:
        token_data['exp'] = datetime.datetime.utcnow() + datetime.timedelta(minutes=duration)
    _access_token = jwt.encode(token_data, current_app.config['SECRET_KEY'])
    
    return _access_token


def org_check(current_user, payload):
    '''
    Checks to see if the current user is not a member of the default organization and if they are not
    remove the organization field
    '''
    if 'organization' in payload and hasattr(current_user,'default_org') and not current_user.default_org:
        payload.pop('organization')
    return payload


def strip_meta_fields(f):
    '''
    Strips the meta fields off the API request as only the system can update them
    '''
    def wrapper(*args, **kwargs):
        for key in ['created_at','updated_at','created_by','updated_by','uuid']:
            if hasattr(args[0].api,'payload') and key in args[0].api.payload:
                args[0].api.payload.pop(key)
        return f(*args, **kwargs)
    wrapper.__doc__ = f.__doc__
    wrapper.__name__ = f.__name__
    return wrapper


def check_org(f):
    '''
    Returns a stripped api payload if the user violates organization guidelines
    '''
    def wrapper(*args, **kwargs):
        if 'current_user' in kwargs:
            current_user = kwargs['current_user']
            if current_user and not hasattr(current_user,'default_org'):
                if len(args) > 0:
                    try:
                        if hasattr(args[0].api,'payload') and 'organization' in args[0].api.payload:
                            args[0].api.payload.pop('organization')
                    except Exception as e:
                        pass
        return f(*args, **kwargs)
    wrapper.__doc__ = f.__doc__
    wrapper.__name__ = f.__name__
    return wrapper  


def ip_approved(f):
    '''
    Returns 401 Unauthorized if the requestors IP is not in the approved IP list
    '''

    def wrapper(*args, **kwargs):

        settings = None
      
        # If the user is current logged in to the system if they are just 
        # load their settings
        if 'current_user' in kwargs:
            current_user = kwargs['current_user']

            # Load the settings for the current user
            settings = Settings.load(organization=current_user.organization)
        else:
            # If this is a logon post, take the users email and split it so that the users
            # organization can be found, and subsequently that organizations Settings
            if len(args) > 0:
                try:
                    if hasattr(args[0].api,'payload') and 'email' in args[0].api.payload:

                        # Calculate the logon domain for the user attempting to login
                        if '@' in args[0].api.payload['email']:
                            logon_domain = args[0].api.payload['email'].split('@')[1]
                        else:
                            abort(401, "Unauthorized")

                        # Get the organization by the logon domain
                        organization = Organization.get_by_logon_domain([logon_domain])

                        # Find the appropriate settings for the user and their organization
                        if organization:
                            settings = Settings.load(organization=organization.uuid)

                        # If there are no settings found reject the user
                        if not settings:
                            abort(401, "Unauthorized")
                except Exception as e:
                        pass

        if settings and hasattr(settings, 'require_approved_ips') and settings.require_approved_ips:

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


def default_org(f):

    def wrapper(*args, **kwargs):
        if 'current_user' in kwargs:
            current_user = kwargs['current_user']
        else:
            current_user = None

        if current_user and hasattr(current_user, 'default_org') and current_user.default_org:
            kwargs['user_in_default_org'] = True
        else:
            kwargs['user_in_default_org'] = False
        
        return f(*args, **kwargs)

    wrapper.__doc__ = f.__doc__
    wrapper.__name__ = f.__name__
    return wrapper


def request_user():
    try:
        return request.current_user
    except AttributeError:
        return None

def user_scope_has(permission: str):
    '''
    Route decorator that takes a permission as a string and determines if the
    current_user has that permission.  If they do return the current route, if
    they do not return 401 Unauthorized
    '''

    def decorator(f):
        def wrapper(*args, **kwargs):

            # Skip the scope check if the SCOPE_BASED_ACCESS is set to False
            if not current_app.config['SCOPE_BASED_ACCESS']:
                return f(*args, **kwargs)

            # Define an empty scope check dictionary to track the scope and
            # permission checks per organization when organization is a list
            # of multiple oranizations
            scope_checks = {}
            
            current_user = None
            organization = None
            
            if 'current_user' in kwargs:
                current_user = kwargs['current_user']

            if 'organization' in request.args:
                organization = request.args.get('organization').split(',')
            
            # If the user is authenticated and on the request object
            if current_user:

                # If the current_user is a pairing token and the route requires add_agent
                # return the route unimpeded
                if isinstance(current_user, dict) and current_user['type'] == 'pairing' and permission == 'add_agent':
                    return f(*args, **kwargs)
                
                if not organization:
                    organization = current_user.get_access_scope_orgs()

                    if current_user.organization not in organization:
                        organization.append(current_user.organization)

                request.current_user = current_user

                if request.method in ['POST', 'PUT', 'PATCH']:
                    payload = request.get_json()
                    if 'organization' in payload:
                        if not current_user.has_org_access(payload['organization']):
                            abort(403, f"You do not have permission to perform this action.  Not scoped for '{payload['organization']}'")
                        
                        if not current_user.has_org_permission(permission, payload['organization']):
                            abort(403, f"You do not have permission to perform this action.  Required permission '{permission}'")
                    return f(*args, **kwargs)

                for org in organization:
                    scope_checks[org] = current_user.has_org_permission(permission, org)
                
                # If any of the scope checks fail, remove the organization from the list of
                # requested organizations
                if False in scope_checks.values():
                    for org in scope_checks:
                        if not scope_checks[org]:
                            organization.remove(org)

                # If any organizations are left in the list, return the route
                if len(organization) > 0:
                    request.current_user.request_org_filter = organization
                    return f(*args, **kwargs)
                else:
                    request.current_user.request_org_filter = [current_user.organization]
                
            abort(403, f"You do not have permission to perform this action.  Required permission '{permission}'")

        wrapper.__doc__ = f.__doc__
        wrapper.__name__ = f.__name__
        return wrapper
    return decorator


def user_has(permission: str):
    '''
    Route decorator that takes a permission as a string and determines if the
    current_user has that permission.  If they do return the current route, if
    they do not return 401 Unauthorized
    '''

    def decorator(f):
        def wrapper(*args, **kwargs):
            if(current_app.config['PERMISSIONS_DISABLED']):
                return f(*args, **kwargs)
                
            current_user = kwargs['current_user']

            # If this is a pairing token and its the add_agent permission
            # bypass the route guard and let the route finish
            if isinstance(current_user, dict) and current_user['type'] == 'pairing' and permission == 'add_agent':
                return f(*args, **kwargs)
            if current_user and not isinstance(current_user, list) and current_user.has_right(permission):
                return f(*args, **kwargs)
            else:
                abort(401, f"You do not have permission to perform this action.  Required permission '{permission}'")

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
        decoded_token = jwt.decode(token, current_app.config['SECRET_KEY'], algorithms=['HS256'])

        try:
            expired = ExpiredToken.search().filter('term', token=token).execute()
            if expired:
                abort(401, 'Token retired.')
        except ConnectionResetError as e:
            current_app.logger.error(f"Error checking for expired token: {e}")

        if 'type' in decoded_token and decoded_token['type'] in ['password_reset','mfa_challenge']:
            user = User.get_by_uuid(uuid=decoded_token['uuid'])
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

            try:
                expired = ExpiredToken.search().filter('term', token=access_token).execute()
                if expired:
                    abort(401, 'Token retired.')
            except ConnectionResetError as e:
                current_app.logger.error(f"Error checking for expired token: {e}")

            try:
                token = jwt.decode(access_token, current_app.config['SECRET_KEY'], algorithms=['HS256'])

                # If this is an agents token pull the agents information and
                # set it to current_user

                if 'type' in token and token['type'] == 'agent':
                    current_user = Agent.get_by_uuid(uuid=token['uuid'])

                # Refresh and Password Reset tokens should not be used to access the API
                # only to refresh an access token or reset the password

                elif 'type' in token and token['type'] in ['refresh','password_reset']:
                    abort(401, 'Unauthorized')
                    
                # Service Accounts are for persistent access and have longer than
                # normal expiration times.  They are not tied to a specific user
                elif 'type' in token and token['type'] == 'service_account':
                    current_user = ServiceAccount.get_by_uuid(uuid=token['uuid'])
                    if not current_user:
                        abort(401, 'Unknown user error.')
                
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
                    if hasattr(current_user,'locked') and current_user.locked:
                        expired = ExpiredToken(token=access_token)
                        expired.save()
                        abort(401, 'Unauthorized')

                if 'default_org' in token and token['default_org']:
                    current_user.default_org = True

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

    if current_app.config['ELASTIC_APM_ENABLED']:

        if isinstance(current_user, (Agent, User)):
            username = None
            email = None
            if isinstance(current_user, Agent):
                username = 'Agent'
                email = 'agent'
            else:
                username = current_user.username
                email = current_user.email
            
            elasticapm.set_user_context(username=username+'-'+current_user.organization, user_id=current_user.uuid, email=email)

    return current_user
