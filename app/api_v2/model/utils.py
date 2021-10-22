import jwt
from flask import request, current_app

from . import user as u

def escape_special_characters(string):
    '''
    Escapes characters in Elasticsearch that might wedge a search
    and return false matches
    '''

    characters = ['.', ' ']
    for character in characters:
        string = string.replace(character, '\\'+character)
    return string

def _current_user_id_or_none():
    try:
        auth_header = request.headers.get('Authorization')

        current_user = None
        if auth_header:
            access_token = auth_header.split(' ')[1]
            token = jwt.decode(
                access_token, current_app.config['SECRET_KEY'], algorithms=['HS256'])
            if 'type' in token and token['type'] == 'agent':
                current_user = None
            elif 'type' in token and token['type'] == 'pairing':
                current_user = None
            else:
                current_user = token['uuid']
        if current_user:
            user = u.User.get_by_uuid(uuid=current_user)
            current_user = {
                'username': user.username,
                'uuid': user.uuid
            }

        return current_user

    except Exception:
        return None
