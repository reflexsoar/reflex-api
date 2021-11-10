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
    'all',
    'avg',
    'max',
    'min',
    'sum',
    'extractb64'    
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


def mutate_avg(*value):
    '''
    Computes the average value if given a list of integers or floats
    '''
    try:
        if isinstance(value, list):
            total_items = len(value)
            target_items = [i for i in value if isinstance(i, (int, float))]
            print(total_items)
            print(target_items)
            if len(target_items) == total_items:
                value = sum(target_items)/total_items
                return value
        return value
    except:
        return value


def mutate_max(value):
    '''
    Finds the maximum value in a list of values
    '''
    try:
        if isinstance(value, list):
            _max = max(*value)
            return _max
    except:
        return value


def mutate_min(value):
    '''
    Finds the minimum value in a list of values
    '''
    try:
        if isinstance(value, list):
            _min = min(*value)
            return _min
    except:
        return value


def mutate_sum(value):
    '''
    Sums all the values in a list of values
    '''
    try:
        if isinstance(value, list):
            return sum(value)
    except:
        return value
        

def mutate_extractb64(value):
    '''
    Extracts a base64 string or strings from a input string and decodes them
    so they can be compared down the pipeline
    '''
    try:
        decoded_matches = []
        if isinstance(value, str):
            pattern = re.compile(r'\s+([A-Za-z0-9+/]{20}\S+)')
            matched = pattern.findall(value)
            if len(matched) > 0:
                decoded_matches = [base64.b64decode(match).decode() for match in matched]
                return decoded_matches
        return value
    except:
        return value


MUTATOR_MAP = {
    'lowercase': mutate_lowercase,
    'uppercase': mutate_uppercase,
    'refang': mutate_refang,
    'count': mutate_count,
    'length': mutate_length,
    'extractb64': mutate_extractb64,
    'b64decode': mutate_b64decode,
    'urldecode': mutate_urldecode,
    'avg': mutate_avg,
    'max': mutate_max,
    'min': mutate_min,
    'sum': mutate_sum
}