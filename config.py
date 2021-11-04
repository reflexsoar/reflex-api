import os
basedir = os.path.abspath(os.path.dirname(__file__))

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
    ELASTICSEARCH_CERT_VERIFY = True if os.getenv('REFLEX_ES_CERT_VERIFY') else False  # This can equal any value, as long as it is set True
    ELASTICSEARCH_SHOW_SSL_WARN = True if os.getenv('REFLEX_ES_SHOW_SSL_WARN') else False # This can equal any value, as long as it is set True
    ELASTIC_DISTRO = os.getenv('REFLEX_ES_DISTRO') if os.getenv('REFLEX_ES_DISTRO') else 'elastic'

    # THREAT POLLER CONFIGURATION
    THREAT_POLLER_INTERVAL = int(os.getenv('REFLEX_THREAT_LIST_POLLER_INTERVAL')) if os.getenv('REFLEX_THREAT_LIST_POLLER_INTERVAL') else 60
    THREAT_POLLER_DISABLED = True if os.getenv('REFLEX_DISABLE_THREAT_POLLER') else False
    THREAT_POLLER_LOG_LEVEL = os.getenv('REFLEX_THREAT_POLLER_LOG_LEVEL') if os.getenv('REFLEX_THREAT_POLLER_LOG_LEVEL') else 'ERROR'

    # HOUSEKEEP DEFAULT CONFIGURATIONS
    HOUSEKEEPER_DISABLED = True if os.getenv('REFLEX_HOUSEKEEPER_DISABLED') else False
    HOUSEKEEPER_LOG_LEVEL = os.getenv('REFLEX_HOUSEKEEPER_LOG_LEVEL') if os.getenv('REFLEX_HOUSEKEEPER_LOG_LEVEL') else 'ERROR'
    AGENT_PRUNE_INTERVAL = os.getenv('REFLEX_AGENT_PRUNE_INTERVAL') if os.getenv('REFLEX_AGENT_PRUNE_INTERVAL') else 15*60 # Default to every 15 minutes

    # EVENT INGEST CONFIGURATION
    EVENT_PROCESSING_THREADS = os.getenv('REFLEX_EVENT_PROCESSING_THREADS') if os.getenv('REFLEX_EVENT_PROCESSING_THREADS') else 5

    # SCHEDULER CONFIG
    SCHEDULER_DISABLED = bool(os.getenv('REFLEX_DISABLE_SCHEDULER')) if os.getenv('REFLEX_DISABLE_SCHEDULER') else False

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