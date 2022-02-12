import os
import ssl
import atexit
import logging
from app.api_v2.model.system import Settings
from app.services.sla_monitor.base import SLAMonitor
from flask import Flask
from app.services import housekeeper
from app.services.threat_list_poller.base import ThreatListPoller
from app.services.housekeeper import HouseKeeper
from flask_bcrypt import Bcrypt
from flask_cors import CORS
from flask_mail import Mail
from flask_caching import Cache
from apscheduler.schedulers.background import BackgroundScheduler
from elasticapm.contrib.flask import ElasticAPM

import warnings
warnings.filterwarnings("ignore", category=DeprecationWarning) 

from app.api_v2.model import (
    Event,Tag,ExpiredToken,Credential,Agent,ThreatList,EventStatus,EventRule,
        CaseComment,CaseHistory,Case,CaseTask,CaseTemplate,Observable,AgentGroup,
        TaskNote,Plugin,PluginConfig,EventLog,User,Role,DataType,CaseStatus,CloseReason,
        Settings,Input, Organization
)

from .defaults import (
    create_default_case_status, create_admin_role, create_default_organization, initial_settings, create_agent_role,
    create_default_closure_reasons, create_default_case_templates, create_default_data_types,
    create_default_event_status, create_analyst_role,create_admin_user
)

REFLEX_VERSION = '0.1.0'

# Elastic or Opensearch
if os.getenv('REFLEX_ES_DISTRO') == 'opensearch':
    from opensearch_dsl import connections
else:
    from elasticsearch_dsl import connections

from config import app_config

FLASK_BCRYPT = Bcrypt()
cors = CORS()
mail = Mail()
cache = Cache(config={'CACHE_TYPE': 'simple'})
scheduler = BackgroundScheduler()
apm = ElasticAPM()


def migrate(ALIAS, move_data=True, update_alias=True):
    '''
    Upgrades all the indices in the system when a new version is released
    that requires a schema change
    '''

    es = connections.get_connection()

    new_index = ALIAS+f"-{REFLEX_VERSION}"

    # Check to make sure the index hasn't already been upgraded
    if not es.indices.exists(index=new_index):

        # Create the new target index
        es.indices.create(index=new_index)

        # Move the data to the new index
        if move_data:
                es.reindex(
                    body={"source": {"index": ALIAS}, "dest": {"index": new_index}},
                    request_timeout=3600
                )

                es.indices.refresh(index=new_index)

        # Update the index alias
        if update_alias:
            es.indices.update_aliases(
                body={
                    "actions":[
                        {"remove": {"alias": ALIAS, "index": ALIAS+"-*"}},
                        {"add": {"alias": ALIAS, "index": new_index}}
                    ]
                }
            )

def upgrade_indices():
    '''
    Performs an upgrade on each index and initializes them if they do not
    exist yet (e.g. first time running the software)
    '''
   
    models = [
        Event,Tag,ExpiredToken,Credential,Agent,ThreatList,EventStatus,EventRule,
        CaseComment,CaseHistory,Case,CaseTask,CaseTemplate,Observable,AgentGroup,
        TaskNote,Plugin,PluginConfig,EventLog,User,Role,DataType,CaseStatus,CloseReason,Settings,
        Input,Organization
        ]

    for model in models:
        ALIAS = model.Index.name
        PATTERN = ALIAS+f"-{REFLEX_VERSION}"
        index_template = model._index.as_template(ALIAS, PATTERN)
        index_template.save()

        if not model._index.exists():
            migrate(ALIAS, move_data=False)
        else:
            migrate(ALIAS)


def setup_complete():
    '''
    Checks if setup has been completed in the past
    '''

    es = connections.get_connection()
    return es.indices.exists('reflex-settings')

def setup():
    '''
    Performs initial setup by setting defaults
    '''

    org_id = create_default_organization(Organization)
    admin_id = create_admin_user(User, org_id)
    create_admin_role(Role, admin_id, org_id, org_perms=True)
    create_analyst_role(Role, org_id)
    create_agent_role(Role,org_id)
    create_default_data_types(DataType,org_id)
    create_default_closure_reasons(CloseReason, org_id)
    create_default_case_status(CaseStatus,org_id )
    create_default_event_status(EventStatus,org_id)
    create_default_case_templates(CaseTemplate, org_id)
    initial_settings(Settings, org_id)
    return 


def create_app(environment='development'):

    app = Flask(__name__, instance_relative_config=True)

    #gunicorn_logger = logging.getLogger('gunicorn.error')
    #app.logger.handlers = gunicorn_logger.handlers
    #app.logger.setLevel(gunicorn_logger.level)

    app.config.from_object(app_config[os.getenv('FLASK_CONFIG', environment)])
    app.config.from_pyfile('application.conf', silent=True)

    cors.init_app(app)
    mail.init_app(app)
    cache.init_app(app)

    authorizations = {"Bearer": {"type": "apiKey", "in": "header", "name":"Authorization"}}

    if app.config['ELASTIC_APM_ENABLED']:
        print(app.config['ELASTIC_APM_SERVICE_NAME'],app.config['ELASTIC_APM_TOKEN'],app.config['ELASTIC_APM_HOSTNAME'],app.config['ELASTIC_APM_ENVIRONMENT'])
        app.config['ELASTIC_APM'] = {
            'SERVICE_NAME': app.config['ELASTIC_APM_SERVICE_NAME'],
            'SECRET_TOKEN': app.config['ELASTIC_APM_TOKEN'],
            'DEBUG': True,
            'ENVIRONMENT': app.config['ELASTIC_APM_ENVIRONMENT'],
            'SERVER_URL': app.config['ELASTIC_APM_HOSTNAME']
        }
        apm.init_app(app, logging=True)

    if not app.config['SCHEDULER_DISABLED']:
        if not app.config['THREAT_POLLER_DISABLED']:

            memcached_config = None
            if app.config['THREAT_POLLER_MEMCACHED_HOST'] and app.config['THREAT_POLLER_MEMCACHED_PORT']:
                memcached_config = {
                    'host': app.config['THREAT_POLLER_MEMCACHED_HOST'],
                    'port': app.config['THREAT_POLLER_MEMCACHED_PORT'],
                    'ttl': app.config['THREAT_POLLER_MEMCACHED_TTL']
                }

            threat_list_poller = ThreatListPoller(app, memcached_config=memcached_config, log_level=app.config['THREAT_POLLER_LOG_LEVEL'])
            scheduler.add_job(func=threat_list_poller.run, trigger="interval", seconds=app.config['THREAT_POLLER_INTERVAL'])

        if not app.config['HOUSEKEEPER_DISABLED']:
            housekeeper = HouseKeeper(app, log_level=app.config['HOUSEKEEPER_LOG_LEVEL'])
            scheduler.add_job(
                func=housekeeper.prune_old_agents,
                trigger="interval",
                seconds=app.config['AGENT_PRUNE_INTERVAL']
            )

        if not app.config['SLAMONITOR_DISABLED']:
            sla_monitor = SLAMonitor(app, log_level=app.config['SLAMONITOR_LOG_LEVEL'])
            scheduler.add_job(func=sla_monitor.check_event_slas, trigger="interval", seconds=app.config['SLAMONITOR_INTERVAL'])

        scheduler.start()
        atexit.register(lambda: scheduler.shutdown())      

    from app.api_v2.resources import api2
    api2.authorizations = authorizations
    api2.title = app.config['API_TITLE']
    api2.version = app.config['API_VERSION']
    api2.description = app.config['API_DESCRIPTION']
    api2.default_mediatype='application/json'

    from app.api_v2.model.user import FLASK_BCRYPT as FLASK_V2_BCRYPT
    FLASK_V2_BCRYPT.init_app(app)

    from app.api_v2.resources import api_v2
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

    # If Reflex is in recovery mode, initial setup will be skipped and indices will be 
    # created empty
    recovery_mode = app.config['REFLEX_RECOVERY_MODE'] if 'REFLEX_RECOVERY_MODE' in app.config else os.getenv('REFLEX_RECOVERY_MODE') if os.getenv('REFLEX_RECOVERY_MODE') else False

    if os.getenv('FLASK_CONFIG') != 'testing':
        if setup_complete() != True:
            print("Running setup")
            upgrade_indices()
            if not recovery_mode:
                setup()
        else:
            print("Setup already run")
            upgrade_indices()

    return app