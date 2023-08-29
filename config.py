import os
from dotenv import load_dotenv
import multiprocessing
basedir = os.path.abspath(os.path.dirname(__file__))

load_dotenv()

def as_bool(value):
    '''
    Returns a string value as a boolean
    if the value is already boolean do a simple comparison and return'''

    if value == True:
        return True

    if value == False:
        return False

    return value.lower() in ['true', '1', 't']

class Config(object):
    DEBUG = False
    SECURITY_PASSWORD_HASH = 'pbkdf2_sha512'
    SECURITY_TRACKABLE = True
    TEMPLATES_AUTO_RELOAD = True
    
    API_TITLE = 'Reflex SOAR'
    API_VERSION = '2.0'
    API_DESCRIPTION = 'A Security Orchestration and Automation Platform'
    WTF_CSRF_ENABLED = False
    PERMISSIONS_DISABLED = False
    SCOPE_BASED_ACCESS = as_bool(os.getenv('REFLEX_SCOPE_BASED_ACCESS')) if os.getenv('REFLEX_SCOPE_BASED_ACCESS') else False

    PLUGIN_DIRECTORY = os.getenv('REFLEX_PLUGINS_DIR') if os.getenv('REFLEX_PLUGINS_DIR') else 'plugins/'
    PLUGIN_EXTENSIONS = ['zip']

    CASE_FILES_DIRECTORY = os.getenv('REFLEX_CASE_FILES_DIR') if os.getenv('REFLEX_CASE_FILES_DIR') else 'uploads/case_files/'
    CASE_FILE_EXTENSIONS = ['txt','doc','docx','zip','xls','xlsx','json','csv']
    MAX_FILE_SIZE = os.getenv('REFLEX_MAX_UPLOAD_SIZE') if os.getenv('REFLEX_MAX_UPLOAD_SIZE') else "51200" # Megabytes
    FILE_OBSERVABLES_DIRECTORY = os.getenv('REFLEX_OBSERVABLE_FILES_DIR') if os.getenv('REFLEX_OBSERVABLE_FILES_DIR') else 'uploads/file_observables/' 
    FILE_OBSERVABLE_PASSWORD = os.getenv('REFLEX_OBSERVABLE_FILES_PASSWORD') if os.getenv('REFLEX_OBSERVABLE_FILES_PASSWORD') else 'infected'

    # ELASTICSEARCH CONFIGURATION
    ELASTICSEARCH_URL = os.getenv('REFLEX_ES_URL') if os.getenv('REFLEX_ES_URL') else ['localhost:9200']
    ELASTICSEARCH_AUTH_SCHEMA = os.getenv('REFLEX_ES_AUTH_SCHEMA') if os.getenv('REFLEX_ES_AUTH_SCHEMA') else "http"
    ELASTICSEARCH_SCHEME = os.getenv('REFLEX_ES_USE_SSL') if os.getenv('REFLEX_ES_USE_SSL') else True
    ELASTICSEARCH_CA = os.getenv('REFLEX_ES_CA') if os.getenv('REFLEX_ES_CA') else None
    ELASTICSEARCH_CERT_VERIFY = as_bool(os.getenv('REFLEX_ES_CERT_VERIFY')) if os.getenv('REFLEX_ES_CERT_VERIFY') else False  # This can equal any value, as long as it is set True
    ELASTICSEARCH_SHOW_SSL_WARN = as_bool(os.getenv('REFLEX_ES_SHOW_SSL_WARN')) if os.getenv('REFLEX_ES_SHOW_SSL_WARN') else False # This can equal any value, as long as it is set True
    ELASTIC_DISTRO = os.getenv('REFLEX_ES_DISTRO') if os.getenv('REFLEX_ES_DISTRO') else 'elastic'
    ELASTICSEARCH_TIMEOUT = int(os.getenv('REFLEX_ES_TIMEOUT')) if os.getenv('REFLEX_ES_TIMEOUT') else 60
    ELASTICSEARCH_USERNAME = os.getenv('REFLEX_ES_USERNAME') if os.getenv('REFLEX_ES_USERNAME') else 'elastic'
    ELASTICSEARCH_PASSWORD = os.getenv('REFLEX_ES_PASSWORD') if os.getenv('REFLEX_ES_PASSWORD') else 'elastic'
    ELASTICSEARCH_MAX_CONNECTIONS = int(os.getenv('REFLEX_ES_MAX_CONNECTIONS')) if os.getenv('REFLEX_ES_MAX_CONNECTIONS') else 25

    # THREAT POLLER CONFIGURATION
    THREAT_POLLER_INTERVAL = int(os.getenv('REFLEX_THREAT_LIST_POLLER_INTERVAL')) if os.getenv('REFLEX_THREAT_LIST_POLLER_INTERVAL') else 5*60
    THREAT_POLLER_DISABLED = as_bool(os.getenv('REFLEX_DISABLE_THREAT_POLLER')) if os.getenv('REFLEX_DISABLE_THREAT_POLLER') else False
    THREAT_POLLER_LOG_LEVEL = os.getenv('REFLEX_THREAT_POLLER_LOG_LEVEL') if os.getenv('REFLEX_THREAT_POLLER_LOG_LEVEL') else 'ERROR'

    THREAT_POLLER_MEMCACHED_ENABLED = as_bool(os.getenv('REFLEX_THREAT_POLLER_MEMCACHED_ENABLED')) if os.getenv('REFLEX_THREAT_POLLER_MEMCACHED_ENABLED') else False
    THREAT_POLLER_MEMCACHED_HOST = os.getenv('REFLEX_THREAT_POLLER_MEMCACHED_HOST') if os.getenv('REFLEX_THREAT_POLLER_MEMCACHED_HOST') else None
    THREAT_POLLER_MEMCACHED_PORT = os.getenv('REFLEX_THREAT_POLLER_MEMCACHED_PORT') if os.getenv('REFLEX_THREAT_POLLER_MEMCACHED_PORT') else None
    MEMCACHED_TIMEOUT = int(os.getenv('REFLEX_MEMCACHED_TIMEOUT')) if os.getenv('REFLEX_MEMCACHED_TIMEOUT') else 5
    THREAT_POLLER_MEMCACHED_TTL = int(os.getenv('REFLEX_THREAT_POLLER_MEMCACHED_TTL')) if os.getenv('REFLEX_THREAT_POLLER_MEMCACHED_HOST') else 60
    MEMCACHED_POOL_SIZE = int(os.getenv('REFLEX_MEMCACHED_POOL_SIZE')) if os.getenv('REFLEX_MEMCACHED_POOL_SIZE') else 4

    # SLA MONITOR CONFIGURATION
    SLAMONITOR_INTERVAL = int(os.getenv('REFLEX_SLAMONITOR_INTERVAL')) if os.getenv('REFLEX_SLAMONITOR_INTERVAL') else 5*50 # Default to every 5 minutes
    SLAMONITOR_DISABLED = as_bool(os.getenv('REFLEX_DISABLE_SLAMONITOR')) if os.getenv('REFLEX_DISABLE_SLAMONITOR') else False
    SLAMONITOR_LOG_LEVEL = os.getenv('REFLEX_SLAMONITOR_LOG_LEVEL') if os.getenv('REFLEX_SLAMONITOR_LOG_LEVEL') else 'ERROR'

    # HOUSEKEEP DEFAULT CONFIGURATIONS
    HOUSEKEEPER_DISABLED = as_bool(os.getenv('REFLEX_HOUSEKEEPER_DISABLED')) if os.getenv('REFLEX_HOUSEKEEPER_DISABLED') else False
    HOUSEKEEPER_LOG_LEVEL = os.getenv('REFLEX_HOUSEKEEPER_LOG_LEVEL') if os.getenv('REFLEX_HOUSEKEEPER_LOG_LEVEL') else 'ERROR'
    AGENT_PRUNE_INTERVAL = int(os.getenv('REFLEX_AGENT_PRUNE_INTERVAL'))*60 if os.getenv('REFLEX_AGENT_PRUNE_INTERVAL') else 15*60 # Default to every 15 minutes
    AGENT_PRUNE_LIFETIME = int(os.getenv('REFLEX_AGENT_PRUNE_LIFETIME')) if os.getenv('REFLEX_AGENT_PRUNE_LIFETIME') else 1440 # Default to 1440 minutes (24 hours)
    AGENT_HEALTH_CHECK_INTERVAL = int(os.getenv('REFLEX_AGENT_HEALTH_CHECK_INTERVAL', 15))*60 # Default to every 15 minutes
    AGENT_HEALTH_LIFETIME = int(os.getenv('REFLEX_AGENT_HEALTH_LIFETIME', 60)) # Defaults to 60 minutes
    AGENT_HEALTH_CHECK_INPUT_TTL = int(os.getenv('REFLEX_AGENT_HEALTH_INPUT_TTL', 30)) # Defaults to 30 minutes
    AGENT_HEALTH_CHECK_INPUT_INTERVAL = int(os.getenv('REFLEX_AGENT_HEALTH_INPUT_INTERVAL', 5))*60 # Defaults to 5 minutes
    TASK_PRUNE_INTERVAL = int(os.getenv('REFLEX_TASK_PRUNE_INTERVAL')) if os.getenv('REFLEX_TASK_PRUNE_INTERVAL') else 3600 # Default to every hour
    TASK_PRUNE_LIFETIME = int(os.getenv('REFLEX_TASK_PRUNE_LIFETIME')) if os.getenv('REFLEX_TASK_PRUNE_LIFETIME') else 30 # Default to 30 days

    # Define Housekeeper settings for Silent Event Rule checks, default to 60 seconds, 7 days, 0 hits
    EVENT_RULE_SILENT_CHECK_ENABLED = as_bool(os.getenv('REFLEX_EVENT_RULE_SILENT_CHECK_ENABLED')) if os.getenv('REFLEX_EVENT_RULE_SILENT_CHECK_ENABLED') else False
    EVENT_RULE_SILENT_INTERVAL = int(os.getenv('REFLEX_EVENT_RULE_SILENT_INTERVAL')) if os.getenv('REFLEX_EVENT_RULE_SILENT_INTERVAL') else 3600 # Default to 60 minutes
    EVENT_RULE_SILENT_DAYS = int(os.getenv('REFLEX_EVENT_RULE_SILENT_DAYS')) if os.getenv('REFLEX_EVENT_RULE_SILENT_DAYS') else 30 # Default to 30 days
    EVENT_RULE_SILENT_HITS = int(os.getenv('REFLEX_EVENT_RULE_SILENT_HITS')) if os.getenv('REFLEX_EVENT_RULE_SILENT_HITS') else 0
    EVENT_RULE_SILENT_ACTIONS = os.getenv('REFLEX_EVENT_RULE_SILENT_ACTIONS') if os.getenv('REFLEX_EVENT_RULE_SILENT_ACTIONS') else ['dismiss']
    if isinstance(EVENT_RULE_SILENT_ACTIONS, str):
        EVENT_RULE_SILENT_ACTIONS = EVENT_RULE_SILENT_ACTIONS.replace(' ', '').split(',')

    # Define Housekeeper settings for High Volume Event Rule checks, default to 60 seconds, 7 days, 10000 hits
    EVENT_RULE_HIGH_VOLUME_CHECK_ENABLED = as_bool(os.getenv('REFLEX_EVENT_RULE_HIGH_VOLUME_CHECK_ENABLED')) if os.getenv('REFLEX_EVENT_RULE_HIGH_VOLUME_CHECK_ENABLED') else False
    EVENT_RULE_HIGH_VOLUME_INTERVAL = int(os.getenv('REFLEX_EVENT_RULE_HIGH_VOLUME_INTERVAL')) if os.getenv('REFLEX_EVENT_RULE_HIGH_VOLUME_INTERVAL') else 3600 # Default to 60 seconds
    EVENT_RULE_HIGH_VOLUME_DAYS = int(os.getenv('REFLEX_EVENT_RULE_HIGH_VOLUME_DAYS')) if os.getenv('REFLEX_EVENT_RULE_HIGH_VOLUME_DAYS') else 30 # Default to 30 days
    EVENT_RULE_HIGH_VOLUME_HITS = int(os.getenv('REFLEX_EVENT_RULE_HIGH_VOLUME_HITS')) if os.getenv('REFLEX_EVENT_RULE_HIGH_VOLUME_HITS') else 10000

    # DETECTION_STATE_REBALANCE_INTERVAL
    DETECTION_STATE_REBALANCE_INTERVAL = int(os.getenv('REFLEX_DETECTION_STATE_REBALANCE_INTERVAL')) if os.getenv('REFLEX_DETECTION_STATE_REBALANCE_INTERVAL') else 10 # Default to 10 seconds
    DETECTION_REPOSITORY_SYNC_CHECK_INTERVAL = int(os.getenv('REFLEX_DETECTION_REPOSITORY_SYNC_CHECK_INTERVAL')) if os.getenv('REFLEX_DETECTION_REPOSITORY_SYNC_CHECK_INTERVAL') else 300 # Default to 5 minutes (300 seconds)

    # EVENT INGEST CONFIGURATION
    EVENT_PROCESSING_THREADS = os.getenv('REFLEX_EVENT_PROCESSING_THREADS') if os.getenv('REFLEX_EVENT_PROCESSING_THREADS') else 1

    # SCHEDULER CONFIG
    SCHEDULER_DISABLED = bool(os.getenv('REFLEX_DISABLE_SCHEDULER')) if os.getenv('REFLEX_DISABLE_SCHEDULER') else False

    # ELASTIC APM CONFIG
    ELASTIC_APM_ENABLED = as_bool(os.getenv('REFLEX_ELASTIC_APM_ENABLED')) if os.getenv('REFLEX_ELASTIC_APM_ENABLED') else False
    ELASTIC_APM_SERVICE_NAME = 'reflex-api'
    ELASTIC_APM_TOKEN = os.getenv('REFLEX_ELASTIC_APM_TOKEN') if os.getenv('REFLEX_ELASTIC_APM_TOKEN') else None
    ELASTIC_APM_HOSTNAME = os.getenv('REFLEX_ELASTIC_APM_HOST') if os.getenv('REFLEX_ELASTIC_APM_HOST') else None
    ELASTIC_APM_ENVIRONMENT = os.getenv('REFLEX_ELASTIC_APM_ENV') if os.getenv('REFLEX_ELASTIC_APM_ENV') else 'dev'

    EVENT_PROCESSOR = {
        'DISABLED': as_bool(os.getenv('REFLEX_EVENT_PROCESSOR_DISABLED')) if os.getenv('REFLEX_EVENT_PROCESSOR_DISABLED') else False,
        'MAX_QUEUE_SIZE': int(os.getenv('REFLEX_EVENT_PROCESSOR_MAX_QUEUE_SIZE')) if os.getenv('REFLEX_EVENT_PROCESSOR_MAX_QUEUE_SIZE') else 0,
        'WORKER_COUNT': int(os.getenv('REFLEX_EVENT_PROCESSOR_WORKER_COUNT')) if os.getenv('REFLEX_EVENT_PROCESSOR_WORKER_COUNT') else (multiprocessing.cpu_count()-1),
        'META_DATA_REFRESH_INTERVAL': int(os.getenv('REFLEX_EVENT_PROCESSOR_META_DATA_REFRESH_INTERVAL')) if os.getenv('REFLEX_EVENT_PROCESSOR_META_DATA_REFRESH_INTERVAL') else 300,
        'ES_BULK_SIZE': int(os.getenv('REFLEX_EVENT_PROCESSOR_ES_BULK_SIZE')) if os.getenv('REFLEX_EVENT_PROCESSOR_ES_BULK_SIZE') else 500,
        'LOG_LEVEL': os.getenv('REFLEX_EVENT_PROCESSOR_LOG_LEVEL') if os.getenv('REFLEX_EVENT_PROCESSOR_LOG_LEVEL') else 'ERROR',
        'WORKER_CHECK_INTERVAL': int(os.getenv('REFLEX_EVENT_PROCESSOR_WORKER_CHECK_INTERVAL')) if os.getenv('REFLEX_EVENT_PROCESSOR_WORKER_CHECK_INTERVAL') else 60,
        'DEDICATED_WORKERS': as_bool(os.getenv('REFLEX_EVENT_PROCESSOR_DEDICATED_WORKERS')) if os.getenv('REFLEX_EVENT_PROCESSOR_DEDICATED_WORKERS') else False,
        'MAX_WORKERS_PER_ORGANIZATION': int(os.getenv('REFLEX_EVENT_PROCESSOR_MAX_WORKERS_PER_ORGANIZATION')) if os.getenv('REFLEX_EVENT_PROCESSOR_MAX_WORKERS_PER_ORGANIZATION') else 5,
        'KAFKA_BOOTSTRAP_SERVERS': os.getenv('REFLEX_EVENT_PROCESSOR_KAFKA_BOOTSTRAP_SERVERS').split(',') if os.getenv('REFLEX_EVENT_PROCESSOR_KAFKA_BOOTSTRAP_SERVERS') else ['localhost:9092'],
        'KAFKA_TOPIC_RETENTION': int(os.getenv('REFLEX_EVENT_PROCESSOR_KAFKA_TOPIC_RETENTION')) if os.getenv('REFLEX_EVENT_PROCESSOR_KAFKA_TOPIC_RETENTION') else 2,
        'MONITOR_WORKERS': as_bool(os.getenv('REFLEX_EVENT_PROCESSOR_MONITOR_WORKERS')) if os.getenv('REFLEX_EVENT_PROCESSOR_MONITOR_WORKERS') else False,
    }

    NOTIFIER = {
        'DISABLED': as_bool(os.getenv('REFLEX_NOTIFIER_DISABLED', False)),
        'LOG_LEVEL': os.getenv('REFLEX_NOTIFIER_LOG_LEVEL', 'ERROR'),
        'MAX_THREADS': int(os.getenv('REFLEX_NOTIFIER_MAX_NOTIFIER_THREADS', 1)),
        'POLL_INTERVAL': int(os.getenv('REFLEX_NOTIFIER_POLL_INTERVAL', 30)),
    }

    NEW_EVENT_PIPELINE = True #as_bool(os.getenv('REFLEX_USE_NEW_EVENT_PROCESSOR')) if os.getenv('REFLEX_USE_NEW_EVENT_PROCESSOR') else False

    MITRE_CONFIG = {
        'JSON_URL': os.getenv('REFLEX_MITRE_ATTACK_JSON_URL') if os.getenv('REFLEX_MITRE_ATTACK_JSON_URL') else 'https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json',
        'POLL_INTERVAL': int(os.getenv('REFLEX_MITRE_ATTACK_POLL_INTERVAL')) if os.getenv('REFLEX_MITRE_ATTACK_POLL_INTERVAL') else 86400 # Once a day
    }

    DISABLE_TELEMETRY = as_bool(os.getenv('REFLEX_DISABLE_TELEMETRY')) if os.getenv('REFLEX_DISABLE_TELEMETRY') else False

    LOG_LEVEL = os.getenv('REFLEX_LOG_LEVEL') if os.getenv('REFLEX_LOG_LEVEL') else "ERROR"

    SHOW_SWAGGER = as_bool(os.getenv('REFLEX_SHOW_SWAGGER')) if os.getenv('REFLEX_SHOW_SWAGGER') else True

    INTEGRATIONS_ENABLED = as_bool(os.getenv('REFLEX_INTEGRATIONS_ENABLED')) if os.getenv('REFLEX_INTEGRATIONS_ENABLED') else False

    SSO_BASE_URL = os.getenv('REFLEX_SSO_BASE_URL') if os.getenv('REFLEX_SSO_BASE_URL') else 'https://localhost'
    if SSO_BASE_URL.endswith('/'):
        SSO_BASE_URL = SSO_BASE_URL[:-1]
    SSO_FORCE_HTTPS = as_bool(os.getenv('REFLEX_SSO_FORCE_HTTPS')) if os.getenv('REFLEX_SSO_FORCE_HTTPS') else False

    X_FORWARDED_FOR = int(as_bool(os.getenv('REFLEX_X_FORWARDED_FOR'))) if os.getenv('REFLEX_X_FORWARDED_FOR') else 0
    X_FORWARDED_PROTO = int(as_bool(os.getenv('REFLEX_X_FORWARDED_PROTO'))) if os.getenv('REFLEX_X_FORWARDED_PROTO') else 0
    X_FORWARDED_HOST = int(as_bool(os.getenv('REFLEX_X_FORWARDED_HOST'))) if os.getenv('REFLEX_X_FORWARDED_HOST') else 0
    X_FORWARDED_PORT = int(as_bool(os.getenv('REFLEX_X_FORWARDED_PORT'))) if os.getenv('REFLEX_X_FORWARDED_PORT') else 0
    X_FORWARDED_PREFIX = int(as_bool(os.getenv('REFLEX_X_FORWARDED_PREFIX'))) if os.getenv('REFLEX_X_FORWARDED_PREFIX') else 0

    FILE_STORAGE_MODE = os.getenv('REFLEX_FILE_STORAGE_MODE') if os.getenv('REFLEX_FILE_STORAGE_MODE') else 'local'
    FILE_STORAGE_LOCAL_PATH = os.getenv('REFLEX_FILE_STORAGE_LOCAL_PATH') if os.getenv('REFLEX_FILE_STORAGE_LOCAL_PATH') else 'uploads/'
    """
    Certain files will exist in sub-folders of the local path, this is a list of those sub-folders
    uploads/case - Contains all attachments related to cases
    uploads/observable - Contains files attached to events
    uploads/agent - Contains agent installers
    uploads/user/<uuid> - Contains user profile images and other user specific files
    """

    FILE_STORAGE_S3_BUCKET = os.getenv('REFLEX_FILE_STORAGE_S3_BUCKET') if os.getenv('REFLEX_FILE_STORAGE_S3_BUCKET') else None
    FILE_STORAGE_S3_KEY = os.getenv('REFLEX_FILE_STORAGE_S3_KEY') if os.getenv('REFLEX_FILE_STORAGE_S3_KEY') else None
    FILE_STORAGE_S3_SECRET = os.getenv('REFLEX_FILE_STORAGE_S3_SECRET') if os.getenv('REFLEX_FILE_STORAGE_S3_SECRET') else None
    FILE_STORAGE_S3_LOCATION = os.getenv('REFLEX_FILE_STORAGE_S3_LOCATION') if os.getenv('REFLEX_FILE_STORAGE_S3_LOCATION') else None


class ProductionConfig(Config):
    ENV = 'production'
    DEBUG = False
    RESTPLUS_MASK_SWAGGER = True
    SHOW_SWAGGER = False

class DevelopmentConfig(Config):
    DEBUG = True
    ENV = 'development'

class TestingConfig(Config):
    ENV = "testing"
    TESTING = True
    DEBUG = False
    PRESERVE_CONTEXT_ON_EXCEPTION = False
    WTF_CSRF_ENABLED = False    

app_config = {
	'development': DevelopmentConfig,
	'production': ProductionConfig,
	'testing': TestingConfig
}