import re
import base64
import socket
import ipaddress
import urllib.parse
import dns.resolver
from geolite2 import geolite2

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
    'b64extract',
    'split',
    'geo_country',
    'geo_timezone',
    'geo_continent',
    'reverse_lookup',
    'is_ipv6',
    'is_multicast',
    'is_global',
    'is_private',
    'ns_lookup_a',
    'ns_lookup_aaaa',
    'ns_lookup_mx',
    'ns_lookup_ptr',
    'ns_lookup_ns',
    'to_integer',
    'to_string'
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
                for match in matched:
                    decoded = base64.b64decode(match)
                    if '\x00' in decoded:
                        decoded_matches.append(decoded.decode('utf-16'))
                    else:
                        decoded_matches.append(decoded.decode(''))
                
                return decoded_matches
        return value
    except:
        return value

def mutate_split(value, delimeter=' '):
    '''
    Splits a string at a delimeter, default ' ' (space) and returns an array of 
    strings
    '''
    try:
        if isinstance(value, str):
            return value.split(delimeter)
    except:
        return value

def mutate_geo_country(value):
    '''
    Returns the country for an IP
    '''

    reader = geolite2.reader()
    match = reader.get(value)

    if match:
        return match['country']['iso_code']
    else:
        return value

def mutate_geo_timezone(value):
    '''
    Returns the country for an IP
    '''

    reader = geolite2.reader()
    match = reader.get(value)

    if match:
        return match['location']['time_zone']
    else:
        return value

def mutate_geo_continent(value):
    '''
    Returns the continent for an IP
    '''

    reader = geolite2.reader()
    match = reader.get(value)

    if match:
        return match['continent']['code']
    else:
        return value

def mutate_reverse_lookup(value):
    '''
    Returns the reverse lookup value for an IP address
    '''
    names = []
    if isinstance(value, list):
        [names.append(socket.gethostbyaddr(n)[0] for n in value)]
    else:
        names = socket.gethostbyaddr(value)[0]
    return names


def mutate_is_ipv6(value):
    '''
    Returns True if the given value is an IPv6 address
    '''

    ip = ipaddress.ip_address(value)
    return isinstance(ip, ipaddress.IPv6Address)

def mutate_is_multicast(value):
    '''
    Returns True if the given value is a multicast address
    '''

    ip = ipaddress.ip_address(value)
    return ip.is_multicast


def mutate_is_global(value):
    '''
    Returns True if the given value is a global address
    '''

    ip = ipaddress.ip_address(value)
    return ip.is_global


def mutate_is_private(value):
    '''
    Returns True if the given value is a private address
    '''

    ip = ipaddress.ip_address(value)
    return ip.is_private


def resolve_dns(value, record_type):
    '''
    Resolves a hostname record to an IP
    '''
    ips = []
    if isinstance(value, list):
        for name in value:
            ips += [a.to_text() for a in dns.resolver.resolve(name, record_type)]
    else:
        ips = [a.to_text() for a in dns.resolver.resolve(value, record_type)]
    return ips

def to_string(value):
    '''
    Casts a value as a string
    '''
    try:
        return str(value)
    except Exception as e:
        return value

def to_integer(value):
    '''
    Casts a value as an integer
    '''
    try:
        return int(value)
    except Exception as e:
        return value


MUTATOR_MAP = {
    'lowercase': mutate_lowercase,
    'uppercase': mutate_uppercase,
    'refang': mutate_refang,
    'count': mutate_count,
    'length': mutate_length,
    'b64extract': mutate_extractb64,
    'b64decode': mutate_b64decode,
    'urldecode': mutate_urldecode,
    'avg': mutate_avg,
    'max': mutate_max,
    'min': mutate_min,
    'sum': mutate_sum,
    'split': mutate_split,
    'geo_country': mutate_geo_country,
    'geo_timezone': mutate_geo_timezone,
    'geo_continent': mutate_geo_continent,
    'reverse_lookup': mutate_reverse_lookup,
    'is_ipv6': mutate_is_ipv6,
    'is_multicast': mutate_is_multicast,
    'is_global': mutate_is_global,
    'is_private': mutate_is_private,
    'ns_lookup_a': lambda x: resolve_dns(x, 'A'),
    'ns_lookup_aaaa': lambda x: resolve_dns(x, 'AAAA'),
    'ns_lookup_mx': lambda x: resolve_dns(x, 'MX'),
    'ns_lookup_ptr': lambda x: resolve_dns(x, 'PTR'),
    'ns_lookup_ns': lambda x: resolve_dns(x, 'NS'),
    'to_integer': to_integer,
    'to_string': to_string
}