from concurrent.futures import ThreadPoolExecutor
import os
import ssl
import atexit
import logging
import datetime

from app.api_v2.model.system import Settings
from app.services.event_processor.errors import KafkaConnectionFailure
from app.services.sla_monitor.base import SLAMonitor
from app.utils.memcached import MemcachedClient
from flask import Flask
from app.services.threat_list_poller.base import ThreatListPoller
from app.services.housekeeper import HouseKeeper
from app.services.event_processor import EventProcessor
from app.services.mitre import MITREAttack
from app.services.notifier import Notifier
from app.services.action_runner import ActionRunner
from app.tasks.assess_rules import flag_rules_for_periodic_assessment
from app.tasks.case.auto_close import auto_close_cases
from app.tasks.benchmark.load_rules import load_benchmark_rules_from_remote
from app.tasks.node_metrics import store_system_metrics
from app.integrations.base.loader import register_integrations
from flask_bcrypt import Bcrypt
from flask_cors import CORS
from flask_mail import Mail
from flask_caching import Cache
from flask_socketio import SocketIO
from apscheduler.schedulers.background import BackgroundScheduler
from elasticapm.contrib.flask import ElasticAPM
from werkzeug.middleware.proxy_fix import ProxyFix

import warnings
warnings.filterwarnings("ignore", category=DeprecationWarning) 

from app.api_v2.model import (
    Event,Tag,ExpiredToken,Credential,Agent,ThreatList,ThreatValue,EventStatus,EventRule,
        CaseComment,CaseHistory,Case,CaseTask,CaseTemplate,Observable,AgentGroup,AgentPolicy,
        TaskNote,Plugin,PluginConfig,EventLog,User,Role,DataType,CaseStatus,CloseReason,
        Settings,Input,Organization,ObservableHistory,Task,Detection,DetectionLog,MITRETactic,
        MITRETechnique, EventView, NotificationChannel, Notification, FieldMappingTemplate,
        AgentLogMessage, EmailNotificationTemplate, ServiceAccount, Asset, DetectionRepository,
        DetectionRepositoryToken, DetectionRepositorySubscription, DetectionState, RepositorySyncLog,
        Integration, IntegrationConfiguration, IntegrationLog, IntegrationActionQueue, SSOProvider,
        RoleMappingPolicy, Package, DataSourceTemplate, Schedule, FimRule, AgentTag,
        BenchmarkRule, BenchmarkRuleset, BenchmarkException, BenchmarkResultHistory,
        BenchmarkResult, BenchmarkFrameworkRule, EventRelatedObject, SearchProxyJob,
        ApplicationInventory, APINodeMetric
)

from .defaults import (
    create_default_case_status, create_admin_role, create_default_email_templates, create_default_organization, initial_settings, create_agent_role,
    create_default_closure_reasons, create_default_case_templates, create_default_data_types,
    create_default_event_status, create_analyst_role,create_admin_user, set_install_uuid, send_telemetry,
     reset_detection_state
)

from .upgrades import upgrades

REFLEX_VERSION = '0.1.4'

try:
    __ = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'VERSION.txt')
    with open(__) as f:
        BUILD_VERSION = f.read().strip()
except Exception as e:
    print(e)
    BUILD_VERSION = '0.0.0'

# Elastic or Opensearch
if os.getenv('REFLEX_ES_DISTRO') == 'opensearch':
    from opensearch_dsl import connections
    from opensearchpy.exceptions import RequestError
else:
    from elasticsearch_dsl import connections
    from elasticsearch.exceptions import RequestError

from config import app_config

FLASK_BCRYPT = Bcrypt()
cors = CORS()
mail = Mail()
cache = Cache(config={'CACHE_TYPE': 'simple'})
scheduler = BackgroundScheduler()
apm = ElasticAPM()
ep = EventProcessor()
memcached_client = MemcachedClient()
notifier = Notifier()
sock = SocketIO()

def security_headers(response):
    '''
    Set the security headers
    '''
    
    # Add the X-Frames-Options header
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    return response

def migrate(app, ALIAS, move_data=True, update_alias=True, version=None):
    '''
    Upgrades all the indices in the system when a new version is released
    that requires a schema change
    '''

    es = connections.get_connection()    

    if version:
        new_index = ALIAS+f"-{version}"
    else:
        new_index = ALIAS+f"-{REFLEX_VERSION}"

    # Check to make sure the index hasn't already been upgraded
    if not es.indices.exists(index=new_index):

        # Create the new target index
        es.indices.create(index=new_index)

        # Move the data to the new index
        if move_data:
            app.logger.info(f"Migrating data for {ALIAS} to {new_index}")
            try:
                result = es.reindex(
                    body={"source": {"index": ALIAS}, "dest": {"index": new_index}},
                    wait_for_completion = True,
                    request_timeout=3600
                )
            except RequestError as e:
                app.logger.error(f"Failed to migrate {ALIAS} to {new_index}. {e.info['failures']}")

            es.indices.refresh(index=new_index)

        # Update the index alias
        if update_alias:
            app.logger.info(f"Updating alias for {ALIAS} to {new_index}")
            es.indices.update_aliases(
                body={
                    "actions":[
                        {"remove": {"alias": ALIAS, "index": ALIAS+"-*"}},
                        {"add": {"alias": ALIAS, "index": new_index}}
                    ]
                }
            )

def upgrade_indices(app):
    '''
    Performs an upgrade on each index and initializes them if they do not
    exist yet (e.g. first time running the software)
    '''
   
    models = [
        Event,Tag,ExpiredToken,Credential,Agent,ThreatList,ThreatValue,EventStatus,EventRule,
        CaseComment,CaseHistory,Case,CaseTask,CaseTemplate,Observable,AgentGroup,AgentPolicy, 
        TaskNote,Plugin,PluginConfig,EventLog,User,Role,DataType,CaseStatus,CloseReason,Settings,
        Input,Organization,ObservableHistory,Task,Detection,DetectionLog,MITRETactic,MITRETechnique,
        EventView, NotificationChannel, Notification, FieldMappingTemplate, AgentLogMessage,
        EmailNotificationTemplate, ServiceAccount, Asset, DetectionRepository,
        DetectionRepositoryToken, DetectionRepositorySubscription, DetectionState,
        RepositorySyncLog, Integration, IntegrationConfiguration, IntegrationLog,
        IntegrationActionQueue, SSOProvider, RoleMappingPolicy, Package, DataSourceTemplate,
        Schedule, FimRule, AgentTag, BenchmarkRule, BenchmarkRuleset, EventRelatedObject,
        BenchmarkException, BenchmarkResultHistory, BenchmarkResult, BenchmarkFrameworkRule,
        SearchProxyJob, ApplicationInventory, APINodeMetric
    ]
    
    def do_upgrade(model):
        ALIAS = model.Index.name

        index_version = None

        if hasattr(model.Index, 'version'):
            index_version = model.Index.version
        else:
            index_version = REFLEX_VERSION

        PATTERN = ALIAS+f"-{index_version}"

        app.logger.info(f"Updating index template for {ALIAS}")
        index_template = model._index.as_template(ALIAS, PATTERN)
        index_template.save()

        if not model._index.exists():
            app.logger.info(f"Creating index {PATTERN}")
            migrate(app, ALIAS, move_data=False, version=index_version)
        else:
            migrate(app, ALIAS, version=index_version)

    with ThreadPoolExecutor(max_workers=4) as executor:
        executor.map(do_upgrade, models)


def setup_complete():
    '''
    Checks if setup has been completed in the past
    '''

    es = connections.get_connection()
    return es.indices.exists('reflex-settings')

def setup(app, check_for_default=False):
    '''
    Performs initial setup by setting defaults
    '''

    # If check for default is set to true, update the default settings for the system
    if not check_for_default:
        app.logger.info("Creating default organization")
        org_id = create_default_organization(Organization)
        app.logger.info("Creating default admin user")
        admin_id = create_admin_user(User, org_id)
        app.logger.info("Creating default admin role")
        create_admin_role(Role, admin_id, org_id, org_perms=True)
        app.logger.info("Creating default analyst role")
        create_analyst_role(Role, org_id, org_perms=True)
        app.logger.info("Creating default agent role")
        create_agent_role(Role,org_id)
        app.logger.info("Creating default data types")
        create_default_data_types(DataType,org_id)
        app.logger.info("Creating default case and event closure reasons")
        create_default_closure_reasons(CloseReason, org_id)
        app.logger.info("Creating default case statuses")
        create_default_case_status(CaseStatus,org_id )
        app.logger.info("Creating default event statuses")
        create_default_event_status(EventStatus,org_id)
        app.logger.info("Creating default case templates")
        create_default_case_templates(CaseTemplate, org_id)
        app.logger.info("Creating default email templates")
        create_default_email_templates(EmailNotificationTemplate, org_id)      
        app.logger.info("Creating default settings for default organization")        
        initial_settings(Settings, org_id)
    else:
        create_default_closure_reasons(CloseReason, org_id=None, check_for_default=check_for_default)
        create_agent_role(Role, org_id=None, check_for_default=check_for_default)
        create_admin_role(Role, admin_id=None, org_id=None, org_perms=True, check_for_default=check_for_default)
        create_analyst_role(Role, org_id=None, org_perms=True, check_for_default=check_for_default)
        create_default_email_templates(EmailNotificationTemplate, org_id=None, check_for_default=check_for_default)
        initial_settings(Settings, org_id=None, check_for_default=check_for_default)
        create_default_event_status(EventStatus, org_id=None, check_for_default=check_for_default)

    return 


def build_elastic_connection(app):
    elastic_connection = {
        'hosts': app.config['ELASTICSEARCH_URL'],
        'verify_certs': app.config['ELASTICSEARCH_CERT_VERIFY'],
        'use_ssl': app.config['ELASTICSEARCH_SCHEME'],
        'ssl_show_warn': app.config['ELASTICSEARCH_SHOW_SSL_WARN'],
        'timeout': app.config['ELASTICSEARCH_TIMEOUT'],
        'maxsize': app.config['ELASTICSEARCH_MAX_CONNECTIONS'],
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


def create_app(environment='development'):

    app = Flask(__name__, instance_relative_config=True, static_url_path='')   
    app.config.from_object(app_config[os.getenv('FLASK_CONFIG', environment)])
    app.config.from_pyfile('application.conf', silent=True)
    app.config['ERROR_404_HELP'] = False
    app.config['BUILD_VERSION'] = BUILD_VERSION

    node_role = app.config['NODE_ROLE']

    if node_role not in ['primary', 'client']:
        app.logger.error(f"Invalid node role {node_role}. Must be either 'primary' or 'client'")
        exit()

    app.logger.info(f"Starting Reflex version {BUILD_VERSION}.  Base model schema: {REFLEX_VERSION}")
    app.logger.info(f"Running in {environment} mode as a {node_role} node")

    #app.logger.propagate = False
    logging.basicConfig(format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    gunicorn_logger = logging.getLogger('gunicorn.error')
    app.logger.handlers = gunicorn_logger.handlers
    app.logger.setLevel(app.config['LOG_LEVEL'])

    cors.init_app(app)
    mail.init_app(app)
    cache.init_app(app)
    sock.init_app(app, cors_allowed_origins="*")

    try:
        memcached_client.init_app(app)
    except Exception as e:
        app.logger.error(f"Memcached client failed to initialize. {e}")
        exit()

    authorizations = {"Bearer": {"type": "apiKey", "in": "header", "name":"Authorization"}}

    build_elastic_connection(app)

    # If Reflex is in recovery mode, initial setup will be skipped and indices will be 
    # created empty
    recovery_mode = app.config['REFLEX_RECOVERY_MODE'] if 'REFLEX_RECOVERY_MODE' in app.config else os.getenv('REFLEX_RECOVERY_MODE') if os.getenv('REFLEX_RECOVERY_MODE') else False

    if os.getenv('FLASK_CONFIG') != 'testing' and node_role == 'primary':
        if setup_complete() != True:
            app.logger.info("Setup already complete")
            upgrade_indices(app)
            if not recovery_mode:
                setup(app)
        else:
            upgrade_indices(app)
            setup(app, check_for_default=True)

    # Perform any necessary upgrades to the database
    if node_role == 'primary':
        for upgrade in upgrades:
            upgrade(app)

    if not app.config['DISABLE_TELEMETRY']:
        set_install_uuid()
        send_telemetry()

    if node_role == 'primary':
        reset_detection_state()

    if app.config['ELASTIC_APM_ENABLED']:
        app.config['ELASTIC_APM'] = {
            'SERVICE_NAME': app.config['ELASTIC_APM_SERVICE_NAME'],
            'SECRET_TOKEN': app.config['ELASTIC_APM_TOKEN'],
            'DEBUG': True,
            'ENVIRONMENT': app.config['ELASTIC_APM_ENVIRONMENT'],
            'SERVER_URL': app.config['ELASTIC_APM_HOSTNAME']
        }
        apm.init_app(app, logging=True)

    # Disable background services on a non-primary node
    if node_role != 'primary':
        app.config['SCHEDULER_DISABLED'] = True
        app.config['THREAT_POLLER_DISABLED'] = True
        app.config['HOUSEKEEPER_DISABLED'] = True
        app.config['SLAMONITOR_DISABLED'] = True
        app.config['NOTIFIER']['DISABLED'] = True
        app.config['DETECTION_DAILY_ASSESS'] = False

    if app.config['INTEGRATIONS_ENABLED']:
        app.logger.info("Loading integrations")
        # TODO: CHECK THIS
        register_integrations(node_role == 'primary')
        
        # Reload integrations every N minutes
        #scheduler.add_job(func=register_integrations, trigger="interval", seconds=app.config['INTEGRATION_LOADER_INTERVAL']*60)

    # Report node metrics every 60 seconds
    scheduler.add_job(func=store_system_metrics, trigger="interval", seconds=60, args=(app, ep))

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
            scheduler.add_job(func=threat_list_poller.run, trigger="interval", seconds=app.config['THREAT_POLLER_INTERVAL']*60) # Multiply by 60 to convert to minutes

        if not app.config['HOUSEKEEPER_DISABLED']:
            housekeeper = HouseKeeper(app, log_level=app.config['HOUSEKEEPER_LOG_LEVEL'])
            scheduler.add_job(
                func=housekeeper.prune_old_agents,
                trigger="interval",
                seconds=app.config['AGENT_PRUNE_INTERVAL']
            )
            scheduler.add_job(
                func=housekeeper.prune_old_benchmark_results,
                trigger="interval",
                seconds=app.config['BENCHMARK_RESULT_PRUNE_INTERVAL']
            )
            scheduler.add_job(
                func=housekeeper.prune_old_tasks,
                trigger="interval",
                seconds=app.config['TASK_PRUNE_INTERVAL']
            )
            scheduler.add_job(
                func=housekeeper.check_agent_health,
                trigger="interval",
                seconds=app.config['AGENT_HEALTH_CHECK_INTERVAL']
            )

            #scheduler.add_job(
            #    func=housekeeper.check_agent_input_health,
            #    trigger="interval",
            #    seconds=app.config['AGENT_HEALTH_CHECK_INPUT_INTERVAL']
            #)

            scheduler.add_job(
                func=housekeeper.check_expired_event_rules,
                trigger="interval",
                seconds=600
            )

            #scheduler.add_job(
            #    func=housekeeper.check_for_delayed_detections,
            #    trigger="interval",
            #    seconds=300
            #)

            scheduler.add_job(
                func=DetectionRepository.check_detection_repo_subscription_sync,
                trigger="interval",
                seconds=app.config['DETECTION_REPOSITORY_SYNC_CHECK_INTERVAL']
            )

            scheduler.add_job(
                func=DetectionState.check_state,
                trigger="interval",
                seconds=app.config['DETECTION_STATE_REBALANCE_INTERVAL']
            )

            if app.config['EVENT_RULE_SILENT_CHECK_ENABLED']:
                scheduler.add_job(
                    func=housekeeper.check_silent_event_rules,
                    trigger="interval",
                    seconds=app.config['EVENT_RULE_SILENT_INTERVAL']
                )

            if app.config['EVENT_RULE_HIGH_VOLUME_CHECK_ENABLED']:
                scheduler.add_job(
                    func=housekeeper.check_high_volume_event_rules,
                    trigger="interval",
                    seconds=app.config['EVENT_RULE_HIGH_VOLUME_INTERVAL']
                )

        if not app.config['SLAMONITOR_DISABLED']:
            sla_monitor = SLAMonitor(app, log_level=app.config['SLAMONITOR_LOG_LEVEL'])
            scheduler.add_job(func=sla_monitor.check_event_slas, trigger="interval", seconds=app.config['SLAMONITOR_INTERVAL'])

        mattack = MITREAttack(app)
        scheduler.add_job(func=mattack.download_framework, trigger="date", run_date=datetime.datetime.now())
        scheduler.add_job(func=mattack.download_framework, trigger="interval", seconds=app.config['MITRE_CONFIG']['POLL_INTERVAL'])

        scheduler.start()
        atexit.register(lambda: scheduler.shutdown())

    if not app.config['NOTIFIER']['DISABLED']:
        notifier.init_app(app)
        notifier.set_log_level(app.config['NOTIFIER']['LOG_LEVEL'])
        scheduler.add_job(func=notifier.check_notifications, trigger="interval", seconds=app.config['NOTIFIER']['POLL_INTERVAL'])

    if node_role == 'primary':
        action_runner = ActionRunner()
        scheduler.add_job(func=action_runner.run, trigger="date", run_date=datetime.datetime.now())

    # Add scheduled tasks
    if app.config['DETECTION_DAILY_ASSESS']:
        scheduler.add_job(func=flag_rules_for_periodic_assessment, trigger="date", run_date=datetime.datetime.now()) # On System Startup
        scheduler.add_job(func=flag_rules_for_periodic_assessment, trigger="interval", seconds=24*60*60) # Once a day

    if node_role == 'primary':
        scheduler.add_job(func=auto_close_cases, trigger="date", run_date=datetime.datetime.now()) # On System Startup
        scheduler.add_job(func=auto_close_cases, trigger="interval", seconds=24*60*60) # Once a day

        scheduler.add_job(func=load_benchmark_rules_from_remote, trigger="date", run_date=datetime.datetime.now(), args=(app, )) # On System Startup
        scheduler.add_job(func=load_benchmark_rules_from_remote, trigger="interval", seconds=60*60, args=(app, )) # Every hour

    if not app.config['EVENT_PROCESSOR']['DISABLED']:
        try:
            ep.init_app(app)
        except KafkaConnectionFailure as e:
            app.logger.error(f"Kafka connection failed. {e}")
            exit()
        ep.set_log_level(app.config['EVENT_PROCESSOR']['LOG_LEVEL'])
        ep.spawn_workers()

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

    app.after_request(security_headers)

    FLASK_BCRYPT.init_app(app)

    app.wsgi_app = ProxyFix(app.wsgi_app,
                            x_proto=app.config['X_FORWARDED_PROTO'],
                            x_host=app.config['X_FORWARDED_HOST'],
                            x_prefix=app.config['X_FORWARDED_PREFIX'],
                            x_port=app.config['X_FORWARDED_PORT'],
                            x_for=app.config['X_FORWARDED_FOR'])

    return app