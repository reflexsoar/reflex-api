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

class ProductionConfig(Config):
    DEBUG = False
    RESTPLUS_MASK_SWAGGER = False
    SQLALCHEMY_DATABASE_URI = 'postgres://postgres:password@127.0.0.1:5432/reflex-prod'

class DevelopmentConfig(Config):
    DEBUG = True
    ENV = 'development'
    SQLALCHEMY_DATABASE_URI = 'mysql+pymysql://postgres:password@127.0.0.1:3306/reflex-dev'
    SQLALCHEMY_TRACK_MODIFICATIONS = False

class TestingConfig(Config):
    ENV = "testing"
    TESTING = True
    DEBUG = False
    SQLALCHEMY_DATABASE_URI = 'postgres://postgres:password@127.0.0.1:5432/reflex-test'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    PRESERVE_CONTEXT_ON_EXCEPTION = False
    WTF_CSRF_ENABLED = False
    PRESERVE_CONTEXT_ON_EXCEPTION = False

app_config = {
	'development': DevelopmentConfig,
	'production': ProductionConfig,
	'testing': TestingConfig
}