import os
basedir = os.path.abspath(os.path.dirname(__file__))

class Config(object):
    DEBUG = False
    SECURITY_PASSWORD_HASH = 'pbkdf2_sha512'
    SECURITY_TRACKABLE = True
    
    API_TITLE = 'Reflex SOAR'
    API_VERSION = '1.0'
    API_DESCRIPTION = 'A Security Orchestration and Automation Platform'
    WTF_CSRF_ENABLED = False
    PERMISSIONS_DISABLED = False

    PLUGIN_DIRECTORY = 'plugins/'
    PLUGIN_EXTENSIONS = ['zip']

    CASE_FILES_DIRECTORY = 'uploads/case_files/'
    CASE_FILE_EXTENSIONS = ['txt','doc','docx','zip','xls','xlsx','json','csv']
    MAX_FILE_SIZE = "51200" # Megabytes
    FILE_OBSERVABLES_DIRECTORY = 'uploads/file_observables/'

    CELERY_BROKER_URL = 'redis://localhost:6379'

    # ELASTICSEARCH CONFIGURATION
    ELASTICSEARCH_URL = ['127.0.0.1:9200']
    ELASTICSEARCH_AUTH_SCHEMA = "http"
    ELASTICSEARCH_SCHEME = 'https'
    ELASTICSEARCH_CA = ''
    ELASTICSEARCH_CERT_VERIFY = "none"

class ProductionConfig(Config):
    DEBUG = False
    RESTPLUS_MASK_SWAGGER = False
    

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