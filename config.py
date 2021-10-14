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
    ELASTICSEARCH_SCHEME = os.getenv('REFLEX_ES_SCHEME') if os.getenv('REFLEX_ES_SCHEME') else "https"
    ELASTICSEARCH_CA = os.getenv('REFLEX_ES_CA') if os.getenv('REFLEX_ES_CA') else None
    ELASTICSEARCH_CERT_VERIFY = os.getenv('REFLEX_ES_CERT_VERIFY') if os.getenv('REFLEX_ES_CERT_VERIFY') else False
    ELASTICSEARCH_SHOW_SSL_WARN = os.getenv('REFLEX_ES_SHOW_SSL_WARN') if os.getenv('REFLEX_ES_SHOW_SSL_WARN') else False

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