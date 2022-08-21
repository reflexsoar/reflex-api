import os
from dotenv import load_dotenv
from flask_saml2.utils import certificate_from_file, private_key_from_file
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
    
    API_TITLE = 'Reflex SOAR'
    API_VERSION = '2.0'
    API_DESCRIPTION = 'A Security Orchestration and Automation Platform'
    WTF_CSRF_ENABLED = False
    PERMISSIONS_DISABLED = False

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

    # THREAT POLLER CONFIGURATION
    THREAT_POLLER_INTERVAL = int(os.getenv('REFLEX_THREAT_LIST_POLLER_INTERVAL')) if os.getenv('REFLEX_THREAT_LIST_POLLER_INTERVAL') else 5*60
    THREAT_POLLER_DISABLED = as_bool(os.getenv('REFLEX_DISABLE_THREAT_POLLER')) if os.getenv('REFLEX_DISABLE_THREAT_POLLER') else False
    THREAT_POLLER_LOG_LEVEL = os.getenv('REFLEX_THREAT_POLLER_LOG_LEVEL') if os.getenv('REFLEX_THREAT_POLLER_LOG_LEVEL') else 'ERROR'

    THREAT_POLLER_MEMCACHED_ENABLED = as_bool(os.getenv('REFLEX_THREAT_POLLER_MEMCACHED_ENABLED')) if os.getenv('REFLEX_THREAT_POLLER_MEMCACHED_ENABLED') else False
    THREAT_POLLER_MEMCACHED_HOST = os.getenv('REFLEX_THREAT_POLLER_MEMCACHED_HOST') if os.getenv('REFLEX_THREAT_POLLER_MEMCACHED_HOST') else None
    THREAT_POLLER_MEMCACHED_PORT = os.getenv('REFLEX_THREAT_POLLER_MEMCACHED_PORT') if os.getenv('REFLEX_THREAT_POLLER_MEMCACHED_HOST') else None
    THREAT_POLLER_MEMCACHED_TTL = int(os.getenv('REFLEX_THREAT_POLLER_MEMCACHED_TTL')) if os.getenv('REFLEX_THREAT_POLLER_MEMCACHED_HOST') else 60
    MEMCACHED_POOL_SIZE = int(os.getenv('REFLEX_MEMCACHED_POOL_SIZE')) if os.getenv('REFLEX_MEMCACHED_POOL_SIZE') else 4

    # SLA MONITOR CONFIGURATION
    SLAMONITOR_INTERVAL = int(os.getenv('REFLEX_SLAMONITOR_INTERVAL')) if os.getenv('REFLEX_SLAMONITOR_INTERVAL') else 5*50 # Default to every 5 minutes
    SLAMONITOR_DISABLED = as_bool(os.getenv('REFLEX_DISABLE_SLAMONITOR')) if os.getenv('REFLEX_DISABLE_SLAMONITOR') else False
    SLAMONITOR_LOG_LEVEL = os.getenv('REFLEX_SLAMONITOR_LOG_LEVEL') if os.getenv('REFLEX_SLAMONITOR_LOG_LEVEL') else 'ERROR'

    # HOUSEKEEP DEFAULT CONFIGURATIONS
    HOUSEKEEPER_DISABLED = as_bool(os.getenv('REFLEX_HOUSEKEEPER_DISABLED')) if os.getenv('REFLEX_HOUSEKEEPER_DISBALED') else False
    HOUSEKEEPER_LOG_LEVEL = os.getenv('REFLEX_HOUSEKEEPER_LOG_LEVEL') if os.getenv('REFLEX_HOUSEKEEPER_LOG_LEVEL') else 'ERROR'
    AGENT_PRUNE_INTERVAL = int(os.getenv('REFLEX_AGENT_PRUNE_INTERVAL'))*60 if os.getenv('REFLEX_AGENT_PRUNE_INTERVAL') else 15*60 # Default to every 15 minutes
    AGENT_PRUNE_LIFETIME = int(os.getenv('REFLEX_AGENT_PRUNE_LIFETIME')) if os.getenv('REFLEX_AGENT_PRUNE_LIFETIME') else 5
    TASK_PRUNE_INTERVAL = int(os.getenv('REFLEX_TASK_PRUNE_INTERVAL')) if os.getenv('REFLEX_TASK_PRUNE_INTERVAL') else 3600 # Default to every hour
    TASK_PRUNE_LIFETIME = int(os.getenv('REFLEX_TASK_PRUNE_LIFETIME')) if os.getenv('REFLEX_TASK_PRUNE_LIFETIME') else 30 # Default to 30 days
    

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
        'META_DATA_REFRESH_INTERVAL': int(os.getenv('REFLEX_EVENT_PROCESSOR_META_DATA_REFRESH_INTERVAL')) if os.getenv('REFLEX_EVENT_PROCESSOR_META_DATA_REFRESH_INTERVAL') else 30,
        'ES_BULK_SIZE': int(os.getenv('REFLEX_EVENT_PROCESSOR_ES_BULK_SIZE')) if os.getenv('REFLEX_EVENT_PROCESSOR_ES_BULK_SIZE') else 500,
        'LOG_LEVEL': os.getenv('REFLEX_EVENT_PROCESSOR_LOG_LEVEL') if os.getenv('REFLEX_EVENT_PROCESSOR_LOG_LEVEL') else 'ERROR',
        'WORKER_CHECK_INTERVAL': int(os.getenv('REFLEX_EVENT_PROCESSOR_WORKER_CHECK_INTERVAL')) if os.getenv('REFLEX_EVENT_PROCESSOR_WORKER_CHECK_INTERVAL') else 60,
        'DEDICATED_WORKERS': as_bool(os.getenv('REFLEX_EVENT_PROCESSOR_DEDICATED_WORKERS')) if os.getenv('REFLEX_EVENT_PROCESSOR_DEDICATED_WORKERS') else False,
        'MAX_WORKERS_PER_ORGANIZATION': int(os.getenv('REFLEX_EVENT_PROCESSOR_MAX_WORKERS_PER_ORGANIZATION')) if os.getenv('REFLEX_EVENT_PROCESSOR_MAX_WORKERS_PER_ORGANIZATION') else 5,
        'KAFKA_BOOTSTRAP_SERVERS': os.getenv('REFLEX_EVENT_PROCESSOR_KAFKA_BOOTSTRAP_SERVERS') if os.getenv('REFLEX_EVENT_PROCESSOR_KAFKA_BOOTSTRAP_SERVERS') else ['localhost:9092'],
        'KAFKA_TOPIC_RETENTION': int(os.getenv('REFLEX_EVENT_PROCESSOR_KAFKA_TOPIC_RETENTION')) if os.getenv('REFLEX_EVENT_PROCESSOR_KAFKA_TOPIC_RETENTION') else 2,
    }

    NOTIFIER = {
        'DISABLED': as_bool(os.getenv('REFLEX_NOTIFIER_DISABLED', False)),
        'LOG_LEVEL': os.getenv('REFLEX_NOTIFIER_LOG_LEVEL', 'ERROR'),
        'MAX_THREADS': int(os.getenv('REFLEX_NOTIFIER_MAX_NOTIFIER_THREADS', 1)),
        'POLL_INTERVAL': int(os.getenv('REFLEX_NOTIFIER_POLL_INTERVAL', 10)),
    }

    NEW_EVENT_PIPELINE = True #as_bool(os.getenv('REFLEX_USE_NEW_EVENT_PROCESSOR')) if os.getenv('REFLEX_USE_NEW_EVENT_PROCESSOR') else False

    MITRE_CONFIG = {
        'JSON_URL': os.getenv('REFLEX_MITRE_ATTACK_JSON_URL') if os.getenv('REFLEX_MITRE_ATTACK_JSON_URL') else 'https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json',
        'POLL_INTERVAL': os.getenv('REFLEX_MITRE_ATTACK_POLL_INTERVAL') if os.getenv('REFLEX_MITRE_ATTACK_POLL_INTERVAL') else 86400 # Once a day
    }

    DISABLE_TELEMETRY = as_bool(os.getenv('REFLEX_DISABLE_TELEMETRY')) if os.getenv('REFLEX_DISABLE_TELEMETRY') else False

    LOG_LEVEL = os.getenv('REFLEX_LOG_LEVEL') if os.getenv('REFLEX_LOG_LEVEL') else "ERROR"


class ProductionConfig(Config):
    ENV = 'production'
    DEBUG = False
    RESTPLUS_MASK_SWAGGER = True    

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