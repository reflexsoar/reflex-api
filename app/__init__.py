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

    from app.resources import api
    from app.api_v2.resources import api2
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

    from app.resources import api_v1
    from app.api_v2.resources import api_v2
    app.register_blueprint(api_v1)
    app.register_blueprint(api_v2)

    FLASK_BCRYPT.init_app(app)

    from app.api_v2.models import connections
    connections.create_connection(hosts=app.config['ELASTICSEARCH_URL'], http_auth=(app.config['ELASTICSEARCH_USERNAME'], app.config['ELASTICSEARCH_PASSWORD']), verify_certs=False, use_ssl=True)

    return app