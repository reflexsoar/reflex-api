"""
Provides the models and index settings for configuring the system to collect
log data from multiple sources and ship them to other systems for log 
processing, storing and search.

Classes:

LogSource
LogCollectionPolicy
LogOutput
"""

from . import (
    Keyword,
    Boolean,
    Integer,
    Text,
    base,
    Object,
)

VALID_LOG_TYPES = [
    'file',
    'windows_eventlog'
]

VALID_LOG_OUTPUT_TYPES = [
    'logstash',
    'vector.dev',
    'http',
    'tcp',
    'udp',
    'elasticsearch',
    'opensearch'
]

LOGSTASH_VALID_LOG_FORMAT = [
    'json',
    'json_lines'
]

LOGSTASH_VALID_AUTH_METHODS = [
    'none',
    'basic',
    'certificate'
]

LOGSTASH_VALID_PROTOCOLS = [
    'http',
    'udp',
    'tcp'
]


class LogSource(base.BaseDocument):
    ''' A LogSource object represents a single log source that is configured
    to be consumed by the system.  A LogSource configuration object tells the
    system what type of log it is (file, windows_channel, etc.) so the system
    knows what agent role to assign the log source to.  It also contains the
    settings for the specific log and how it should be collected, what
    additional meta data should be applied to the log events, and where the
    log events should be sent after collection.
    '''

    name = Keyword()  # The name of the log source
    dataset = Keyword()  # The dataset name for the log source
    description = Keyword(fields={'text': Text()})
    enabled = Boolean()  # Is the log source enabled
    log_type = Keyword()  # One of the options from the VALID_LOG_TYPES list
    log_path = Keyword()  # Interchangeable path for file or channel for windows_eventlog
    reverse = Boolean()  # Start reading the log from the end to the beginning
    max_age = Integer()  # Maximum age of the log file in days
    lookback = Integer()  # Number of days to look back for log events on first collection
    include_patterns = Keyword()  # List of regex patterns to filter in log events
    exclude_patterns = Keyword()  # List of regex patterns to filter out log events
    included_event_ids = Keyword()  # List of event IDs to include in windows_eventlog
    excluded_event_ids = Keyword()  # List of event IDs to exclude in windows_eventlog
    include_host_meta = Boolean()  # Include host meta data in log events
    # Include the original log event in the log event
    include_original_event = Boolean()
    ignore_bookmark = Boolean()  # Ignore the bookmark for the log source
    resolve_sids = Boolean()  # Resolve SIDs to usernames
    outputs = Keyword()  # Contains the UUID of the LogOutput objects to send the log events to
    tags = Keyword()  # Tags to apply to the log events
    is_global = Boolean()  # Is this a global log source that can be used by any organization

    class Index:  # pylint: disable=too-few-public-methods
        ''' Defines the index to use '''
        name = 'reflex-log-sources'
        settings = {
            'refresh_interval': '1s'
        }


class LogCollectionPolicy(base.BaseDocument):
    ''' A LogCollectionPolicy object represents a collection of LogSources
    that are configured to be consumed by the system.  A LogCollectionPolicy
    configuration object tells the system in a more manageable way which
    logs are intended for collection.  The policy affords the opportunity to
    override specific log settings, like outputs, tags, etc.
    '''

    name = Keyword()
    description = Keyword(fields={'text': Text()})
    enabled = Boolean()
    log_sources = Keyword()  # Contains the UUID of the LogSource objects to collect
    outputs = Keyword()  # Contains the UUID of the LogOutput objects to send the log events to
    tags = Keyword()  # Tags to apply to the log events
    # Is this a global log collection policy that can be used by any organization
    is_global = Boolean()

    class Index:  # pylint: disable=too-few-public-methods
        ''' Defines the index to use '''
        name = 'reflex-log-collection-policies'
        settings = {
            'refresh_interval': '1s'
        }


class LogstashSettings(base.BaseDocument):
    ''' Defines the settings for a Logstash output '''
    host = Keyword()
    port = Integer()
    auth_method = Keyword()  # One of the options from the LOGSTASH_VALID_AUTH_METHODS list
    credential = Keyword()  # The UUID of the Credential object to use for authentication
    protocol = Keyword()  # One of the options from the LOGSTASH_VALID_PROTOCOLS list
    log_format = Keyword()  # One of the options from the LOGSTASH_VALID_LOG_FORMATS list
    ssl = Boolean()
    ssl_verify = Boolean()
    # Client key file path or PEM-formatted string containing the key
    ssl_client_key = Keyword()
    # Client certificate file path or PEM-formatted string containing the certificate
    ssl_client_cert = Keyword()
    ssl_key_passphrase = Keyword()
    ssl_ca = Keyword()  # PEM-formatted string containing the CA certificate to trust
    ssl_ca_fingerprint = Keyword()  # SHA-1 fingerprint of the CA certificate to trust
    ssl_ca_path = Keyword()  # Path to a directory containing CA certificates to trust
    ssl_ca_password = Keyword()  # Password to decrypt the CA certificate


class LogOutput(base.BaseDocument):
    ''' A LogOutput object represents a single log output that is configured
    to tell the system where to redirect consumed logs.  A LogOutput object
    contains the settings for the specific output, for example if it is a
    logstash, vector.dev, http, tcp, udp, etc. output type.  For each 
    output type it also contains how to connect to the output, retry settings,
    etc.
    '''

    name = Keyword()
    description = Keyword(fields={'text': Text()})
    enabled = Boolean()
    output_type = Keyword()  # One of the options from the VALID_LOG_OUTPUT_TYPES list
    logstash = Object()  # Logstash output settings
    vector = Object()  # Vector output settings
    http = Object()  # HTTP output settings
    tcp = Object()  # TCP output settings
    udp = Object()  # UDP output settings
    elasticsearch = Object()  # Elasticsearch output settings
    opensearch = Object()  # OpenSearch output settings
    tags = Keyword()  # Tags to apply to the log events

    class Index:  # pylint: disable=too-few-public-methods
        ''' Defines the index to use '''
        name = 'reflex-log-outputs'
        settings = {
            'refresh_interval': '1s'
        }
