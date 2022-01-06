import os
import ssl
import atexit
import logging
from datetime import datetime
from flask import Flask
from app.services import housekeeper
from app.services.threat_list_poller.base import ThreatListPoller
from app.services.housekeeper import HouseKeeper
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_cors import CORS
from flask_mail import Mail
from flask_caching import Cache
from apscheduler.schedulers.background import BackgroundScheduler
from app.api_v2.model import (
    Event,Tag,ExpiredToken,Credential,Agent,ThreatList,EventStatus,EventRule,
        CaseComment,CaseHistory,Case,CaseTask,CaseTemplate,Observable,AgentGroup,
        TaskNote,Plugin,PluginConfig,EventLog,User,Role,DataType,CaseStatus,CloseReason
)

# Elastic or Opensearch
if os.getenv('REFLEX_ES_DISTRO') == 'opensearch':
    from opensearch_dsl import connections
else:
    from elasticsearch_dsl import connections

from config import app_config

FLASK_BCRYPT = Bcrypt()
#db = SQLAlchemy()
cors = CORS()
mail = Mail()
cache = Cache(config={'CACHE_TYPE': 'simple'})
scheduler = BackgroundScheduler()


def migrate(ALIAS, VERSION, move_data=True, update_alias=True):
    '''
    Upgrades all the indices in the system when a new version is released
    that requires a schema change
    '''

    es = connections.get_connection()

    new_index = ALIAS+f"-{VERSION}"

    # Check to make sure the index hasn't already been upgraded
    if not es.indices.exists(index=new_index):

        # Create the new target index
        es.indices.create(index=new_index)

        # Move the data to the new index
        if move_data:
            
                print(f'Upgrading {ALIAS} and moving data to {new_index}')
                es.reindex(
                    body={"source": {"index": ALIAS}, "dest": {"index": new_index}},
                    request_timeout=3600
                )

                es.indices.refresh(index=new_index)

        # Update the index alias
        if update_alias:
            print(f'Updating aliases for {ALIAS}')
            es.indices.update_aliases(
                body={
                    "actions":[
                        {"remove": {"alias": ALIAS, "index": ALIAS+"-*"}},
                        {"add": {"alias": ALIAS, "index": new_index}}
                    ]
                }
            )

def upgrade_indices():

    VERSION = '0.1.0'
    
    models = [
        Event,Tag,ExpiredToken,Credential,Agent,ThreatList,EventStatus,EventRule,
        CaseComment,CaseHistory,Case,CaseTask,CaseTemplate,Observable,AgentGroup,
        TaskNote,Plugin,PluginConfig,EventLog,User,Role,DataType,CaseStatus,CloseReason,
        ]
    for model in models:
        ALIAS = model.Index.name
        PATTERN = ALIAS+f"-{VERSION}"
        index_template = model._index.as_template(ALIAS, PATTERN)
        index_template.save()

        if not model._index.exists():
            migrate(ALIAS, VERSION, move_data=False)
        else:
            migrate(ALIAS, VERSION)

def create_app(environment='development'):

    app = Flask(__name__, instance_relative_config=True)
    app.config.from_object(app_config[os.getenv('FLASK_CONFIG', environment)])
    app.config.from_pyfile('application.conf', silent=True)

    cors.init_app(app)
    mail.init_app(app)
    cache.init_app(app)

    authorizations = {"Bearer": {"type": "apiKey", "in": "header", "name":"Authorization"}}

    if not app.config['SCHEDULER_DISABLED']:
        if not app.config['THREAT_POLLER_DISABLED']:
            threat_list_poller = ThreatListPoller(app, log_level=app.config['THREAT_POLLER_LOG_LEVEL'])
            scheduler.add_job(func=threat_list_poller.run, trigger="interval", seconds=app.config['THREAT_POLLER_INTERVAL'])

        if not app.config['HOUSEKEEPER_DISABLED']:
            housekeeper = HouseKeeper(app, log_level=app.config['HOUSEKEEPER_LOG_LEVEL'])
            scheduler.add_job(func=housekeeper.prune_old_agents, trigger="interval", seconds=app.config['AGENT_PRUNE_INTERVAL'])

        scheduler.start()
        atexit.register(lambda: scheduler.shutdown())      

    #from app.resources import api
    
    #api.authorizations = authorizations
    #api.title = app.config['API_TITLE']
    #api.version = app.config['API_VERSION']
    #api.description = app.config['API_DESCRIPTION']
    #api.default_mediatype='application/json'
    
    from app.api_v2.resources import api2
    api2.authorizations = authorizations
    api2.title = app.config['API_TITLE']
    api2.version = app.config['API_VERSION']
    api2.description = app.config['API_DESCRIPTION']
    api2.default_mediatype='application/json'

    from app.api_v2.model.user import FLASK_BCRYPT as FLASK_V2_BCRYPT
    FLASK_V2_BCRYPT.init_app(app)

    #from app.resources import api_v1
    from app.api_v2.resources import api_v2
    #app.register_blueprint(api_v1)
    app.register_blueprint(api_v2)

    FLASK_BCRYPT.init_app(app)

    elastic_connection = {
        'hosts': app.config['ELASTICSEARCH_URL'],
        'verify_certs': app.config['ELASTICSEARCH_CERT_VERIFY'],
        'use_ssl': app.config['ELASTICSEARCH_SCHEME'],
        'ssl_show_warn': app.config['ELASTICSEARCH_SHOW_SSL_WARN']
    }

    username = app.config['ELASTICSEARCH_USERNAME'] if 'ELASTICSEARCH_USERNAME' in app.config else os.getenv('REFLEX_ES_USERNAME') if os.getenv('REFLEX_ES_USERNAME') else "elastic"
    password = app.config['ELASTICSEARCH_PASSWORD'] if 'ELASTICSEARCH_PASSWORD' in app.config else os.getenv('REFLEX_ES_PASSWORD') if os.getenv('REFLEX_ES_PASSWORD') else "password"
    if app.config['ELASTICSEARCH_AUTH_SCHEMA'] == 'http':
        elastic_connection['http_auth'] = (username,password)

    elif app.config['ELASTICSEARCH_AUTH_SCHEMA'] == 'api':
        elastic_connection['api_key'] = (username,password)

    if app.config['ELASTICSEARCH_CA']:
        elastic_connection['ca_certs'] = app.config['ELASTICSEARCH_CA']

    connections.create_connection(**elastic_connection)

    upgrade_indices()

    return app