import re
import base64
import urllib.parse

MUTATORS = (
    'lowercase',
    'uppercase',
    'b64decode',
    'refang',
    'urldecode',
    'count',
    'length',
    'any',
    'all'
)

def mutate_count(value):
    '''
    Returns the number of items in a list
    '''
    if isinstance(value, list):
        return len(value)
    else:
        return 0


def mutate_length(value):
    '''
    Returns the length of a string or a list
    '''
    if isinstance(value, (list,str)):
        return len(value)
    else:
        return 0


def mutate_lowercase(value):
    '''
    Transforms strings and lists of strings to all lowecase
    '''

    if isinstance(value, list):
        value = [v.lower() for v in value if isinstance(v, str)]

    if isinstance(value, str):
        value = value.lower()
    return value


def mutate_uppercase(value):
    '''
    Transforms strings and lists of strings to all uppercase
    '''

    if isinstance(value, list):
        value = [v.upper() for v in value if isinstance(v, str)]

    if isinstance(value, str):
        value = value.upper()
    return value


def mutate_refang(value):
    '''
    Refangs dangerous strings from their defanged state
    '''

    if isinstance(value, list):
        value = [v.replace('hXXp','http').replace('[:]',':').replace('[.]','.') for v in value if isinstance(v, str)]

    if isinstance(value, str):
        value = value.replace('hXXp','http').replace('[:]',':').replace('[.]','.')

    return value

def mutate_b64decode(value):
    '''
    Attempts to base64 decode a string
    '''
    try:
        value = base64.b64decode(value).decode('utf-8')
    except:
        return value
    return value

def mutate_urldecode(value):
    ''' 
    Attempts to decode a URL
    '''
    try:
        value = urllib.parse.unquote(value)
    except:
        return value
    return value


MUTATOR_MAP = {
    'lowercase': mutate_lowercase,
    'uppercase': mutate_uppercase,
    'refang': mutate_refang,
    'count': mutate_count,
    'length': mutate_length,
    'b64decode': mutate_b64decode,
    'urldecode': mutate_urldecode
}