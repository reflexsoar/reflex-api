import os
from dotenv import load_dotenv
import multiprocessing
basedir = os.path.abspath(os.path.dirname(__file__))

load_dotenv()

def as_bool(value):
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
    ELASTICSEARCH_USERNAME = os.getenv('REFLEX_ES_USERNAME') if os.getenv('REFLEX_ES_USERNAME') else "elastic"
    ELASTICSEARCH_PASSWORD = os.getenv('REFLEX_ES_PASSWORD') if os.getenv('REFLEX_ES_PASSWORD') else "password"
    ELASTICSEARCH_URL = os.getenv('REFLEX_ES_URL') if os.getenv('REFLEX_ES_URL') else ['localhost:9200']
    ELASTICSEARCH_AUTH_SCHEMA = os.getenv('REFLEX_ES_AUTH_SCHEMA') if os.getenv('REFLEX_ES_AUTH_SCHEMA') else "http"
    ELASTICSEARCH_SCHEME = os.getenv('REFLEX_ES_USE_SSL') if os.getenv('REFLEX_ES_USE_SSL') else True
    ELASTICSEARCH_CA = os.getenv('REFLEX_ES_CA') if os.getenv('REFLEX_ES_CA') else None
    ELASTICSEARCH_CERT_VERIFY = True if os.getenv('REFLEX_ES_CERT_VERIFY') else False  # This can equal any value, as long as it is set True
    ELASTICSEARCH_SHOW_SSL_WARN = True if os.getenv('REFLEX_ES_SHOW_SSL_WARN') else False # This can equal any value, as long as it is set True
    ELASTIC_DISTRO = os.getenv('REFLEX_ES_DISTRO') if os.getenv('REFLEX_ES_DISTRO') else 'elastic'
    ELASTICSEARCH_TIMEOUT = int(os.getenv('REFLEX_ES_TIMEOUT')) if os.getenv('REFLEX_ES_TIMEOUT') else 60

    # THREAT POLLER CONFIGURATION
    THREAT_POLLER_INTERVAL = int(os.getenv('REFLEX_THREAT_LIST_POLLER_INTERVAL')) if os.getenv('REFLEX_THREAT_LIST_POLLER_INTERVAL') else 3600
    THREAT_POLLER_DISABLED = True if os.getenv('REFLEX_DISABLE_THREAT_POLLER') else False
    THREAT_POLLER_LOG_LEVEL = os.getenv('REFLEX_THREAT_POLLER_LOG_LEVEL') if os.getenv('REFLEX_THREAT_POLLER_LOG_LEVEL') else 'ERROR'

    THREAT_POLLER_MEMCACHED_ENABLED = as_bool(os.getenv('REFLEX_THREAT_POLLER_MEMCACHED_ENABLED')) if os.getenv('REFLEX_THREAT_POLLER_MEMCACHED_ENABLED') else False
    THREAT_POLLER_MEMCACHED_HOST = os.getenv('REFLEX_THREAT_POLLER_MEMCACHED_HOST') if os.getenv('REFLEX_THREAT_POLLER_MEMCACHED_HOST') else None
    THREAT_POLLER_MEMCACHED_PORT = os.getenv('REFLEX_THREAT_POLLER_MEMCACHED_PORT') if os.getenv('REFLEX_THREAT_POLLER_MEMCACHED_HOST') else None
    THREAT_POLLER_MEMCACHED_TTL = int(os.getenv('REFLEX_THREAT_POLLER_MEMCACHED_TTL')) if os.getenv('REFLEX_THREAT_POLLER_MEMCACHED_HOST') else 60

    # SLA MONITOR CONFIGURATION
    SLAMONITOR_INTERVAL = int(os.getenv('REFLEX_SLAMONITOR_INTERVAL')) if os.getenv('REFLEX_SLAMONITOR_INTERVAL') else 5*50 # Default to every 5 minutes
    SLAMONITOR_DISABLED = True if os.getenv('REFLEX_DISABLE_SLAMONITOR') else False
    SLAMONITOR_LOG_LEVEL = os.getenv('REFLEX_SLAMONITOR_LOG_LEVEL') if os.getenv('REFLEX_SLAMONITOR_LOG_LEVEL') else 'ERROR'

    # HOUSEKEEP DEFAULT CONFIGURATIONS
    HOUSEKEEPER_DISABLED = True if os.getenv('REFLEX_HOUSEKEEPER_DISABLED') else False
    HOUSEKEEPER_LOG_LEVEL = os.getenv('REFLEX_HOUSEKEEPER_LOG_LEVEL') if os.getenv('REFLEX_HOUSEKEEPER_LOG_LEVEL') else 'ERROR'
    AGENT_PRUNE_INTERVAL = int(os.getenv('REFLEX_AGENT_PRUNE_INTERVAL')) if os.getenv('REFLEX_AGENT_PRUNE_INTERVAL') else 15*60 # Default to every 15 minutes
    AGENT_PRUNE_LIFETIME = int(os.getenv('REFLEX_AGENT_PRUNE_LIFETIME')) if os.getenv('REFLEX_AGENT_PRINT_LIFETIME') else 7

    # EVENT INGEST CONFIGURATION
    EVENT_PROCESSING_THREADS = os.getenv('REFLEX_EVENT_PROCESSING_THREADS') if os.getenv('REFLEX_EVENT_PROCESSING_THREADS') else 1


    # SCHEDULER CONFIG
    SCHEDULER_DISABLED = as_bool(os.getenv('REFLEX_DISABLE_SCHEDULER')) if os.getenv('REFLEX_DISABLE_SCHEDULER') else False

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
        'ES_BULK_SIZE': int(os.getenv('REFLEX_EVENT_PROCESSOR_ES_BULK_SIZE')) if os.getenv('REFLEX_EVENT_PROCESSOR_ES_BULK_SIZE') else 500
    }

    NEW_EVENT_PIPELINE = as_bool(os.getenv('REFLEX_USE_NEW_EVENT_PROCESSOR')) if os.getenv('REFLEX_USE_NEW_EVENT_PROCESSOR') else False

    LOG_LEVEL = os.getenv('REFLEX_LOG_LEVEL') if os.getenv('REFLEX_LOG_LEVEL') else "3"

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