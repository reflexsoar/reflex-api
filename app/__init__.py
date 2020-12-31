import os
import ssl
from elasticsearch import Elasticsearch
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_cors import CORS
from flask_mail import Mail
from flask_caching import Cache
from config import app_config


FLASK_BCRYPT = Bcrypt()
db = SQLAlchemy()
cors = CORS()
mail = Mail()
cache = Cache(config={'CACHE_TYPE': 'simple'})

def build_es_connection(config):
        '''
        Creates an Elasticsearch connection object that can
        be used to query Elasticsearch
        '''

        if config['ELASTICSEARCH_CA'] != "":
            # TODO: Make this work using base64 encoded certificate file
            raise NotImplementedError
        else:
            context = ssl.create_default_context()
        context.check_hostname = config['ELASTICSEARCH_CHECK_HOSTNAME'] if 'ELASTICSEARCH_CHECK_HOSTNAME' in config else False

        CONTEXT_VERIFY_MODES = {
            "none": ssl.CERT_NONE,
            "optional": ssl.CERT_OPTIONAL,
            "required": ssl.CERT_REQUIRED
        }
        context.verify_mode = CONTEXT_VERIFY_MODES[config['ELASTICSEARCH_CERT_VERIFY']] if 'ELASTICSEARCH_CERT_VERIFY' in config else "none"

        es_config = {
            'scheme': config['ELASTICSEARCH_SCHEME'],
            'ssl_context': context
        }

        if config['ELASTICSEARCH_AUTH_SCHEMA']== 'api_key':
            es_config['api_key'] = (config['ELASTICSEARCH_USERNAME'], config['ELASTICSEARCH_PASSWORD'])
        else:
            es_config['http_auth'] = (config['ELASTICSEARCH_USERNAME'], config['ELASTICSEARCH_PASSWORD'])

        return Elasticsearch(config['ELASTICSEARCH_URL'], **es_config)

def create_app(environment='development'):

    app = Flask(__name__, instance_relative_config=True)
    app.config.from_object(app_config[os.getenv('FLASK_CONFIG', environment)])
    app.config.from_pyfile('application.conf', silent=True)

    app.config['SQLALCHEMY_DATABASE_URI'] = app.config['SQLALCHEMY_DATABASE_URI'].format(
        app.config['DB_USERNAME'],
        app.config['DB_PASSWORD'],
        app.config['DB_HOST'],
        app.config['DB_PORT'],
        app.config['DB_NAME'],
    )

    db.init_app(app)
    cors.init_app(app)
    mail.init_app(app)
    cache.init_app(app)

    authorizations = {"Bearer": {"type": "apiKey", "in": "header", "name":"Authorization"}}

    from app.resources import api, api2
    api.authorizations = authorizations
    api.title = app.config['API_TITLE']
    api.version = app.config['API_VERSION']
    api.description = app.config['API_DESCRIPTION']
    api.default_mediatype='application/json'
    
    api2.authorizations = authorizations
    api2.title = app.config['API_TITLE']
    api2.version = app.config['API_VERSION']
    api2.description = app.config['API_DESCRIPTION']
    api2.default_mediatype='application/json'

    from app.resources import api_v1, api_v2
    app.register_blueprint(api_v1)
    app.register_blueprint(api_v2)

    FLASK_BCRYPT.init_app(app)

    app.elasticsearch = build_es_connection(app.config)

    return app