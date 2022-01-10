import os
from datetime import datetime
from dotenv import load_dotenv
load_dotenv()


if os.getenv('REFLEX_ES_DISTRO') == 'opensearch':
    from opensearch_dsl import connections
else:
    from elasticsearch_dsl import connections

from app.api_v2.model import (
    User,
    ExpiredToken,
    Role,
    Settings,
    Credential,
    Agent,
    Input,
    ThreatList,
    Event,
    EventRule,
    DataType,
    CaseComment,
    CaseHistory,
    CaseTemplate,
    Case,
    CloseReason,
    CaseStatus,
    CaseTask,
    Tag,
    EventStatus,
    Observable,
    AgentGroup,
    TaskNote,
    Plugin,
    PluginConfig,
    EventLog
)


ES_URL = os.getenv('REFLEX_ES_URL') if os.getenv('REFLEX_ES_URL') else ['localhost:9200']
ES_USERNAME = os.getenv('REFLEX_ES_USERNAME') if os.getenv('REFLEX_ES_USERNAME') else 'admin'
ES_PASSWORD = os.getenv('REFLEX_ES_PASSWORD') if os.getenv('REFLEX_ES_PASSWORD') else 'admin'
ES_AUTH_SCHEME = os.getenv('REFLEX_ES_AUTH_SCHEMA') if os.getenv('REFLEX_ES_AUTH_SCHEMA') else 'http'
ES_CA = os.getenv('REFLEX_ES_CA') if os.getenv('REFLEX_ES_CA') else None
ES_CERT_VERIFY = os.getenv('REFLEX_ES_CERT_VERIFY') if os.getenv('REFLEX_ES_CERT_VERIFY') else False
ES_USE_SSL = os.getenv('REFLEX_ES_USE_SSL') if os.getenv('REFLEX_ES_USE_SSL') else True
ELASTICSEARCH_SHOW_SSL_WARN = True if os.getenv('REFLEX_ES_SHOW_SSL_WARN') else False # This can equal any value, as long as it is set True

elastic_connection = {
    'hosts': ES_URL,
    'verify_certs': ES_CERT_VERIFY,
    'use_ssl': ES_AUTH_SCHEME,
    'ssl_show_warn': ELASTICSEARCH_SHOW_SSL_WARN
}

if ES_AUTH_SCHEME == 'http':
        elastic_connection['http_auth'] = (ES_USERNAME,ES_PASSWORD)

elif ES_AUTH_SCHEME == 'api':
    elastic_connection['api_key'] = (ES_USERNAME,ES_PASSWORD)

if ES_CA:
    elastic_connection['ca_certs'] = ES_CA

connections.create_connection(**elastic_connection)


def check_setup_status():
    '''
    Checks to see if setup has already been run by looking for the 
    Reflex indices in the Elasticsearch cluster
    '''
    try:
        settings = Settings.search().execute()
        if settings:
            print("Setup has already been run.")
            exit(1)
    except Exception as e:
        print("Setup not run, running now...")

def create_admin_role(admin_id):

    #Role.init()

    perms = { 
        'add_user': True,
        'update_user': True,
        'delete_user': True,
        'add_user_to_role': True,
        'remove_user_from_role': True,
        'reset_user_password': True,
        'unlock_user': True,
        'view_users': True,
        'add_role': True,
        'update_role': True,
        'delete_role': True,
        'set_role_permissions': True,
        'view_roles': True,
        "add_tag": True,
        "update_tag": True,
        "delete_tag": True,
        "view_tags": True,
        "add_credential": True,
        "update_credential": True,
        "decrypt_credential": True,
        "delete_credential": True,
        "view_credentials": True ,
        "add_playbook": True,
        "update_playbook": True,
        "delete_playbook": True,
        "view_playbooks": True,
        "add_tag_to_playbook": True,
        "remove_tag_from_playbook": True,
        "add_event": True,
        "view_events": True,
        "update_event": True,
        "delete_event": True,
        "add_tag_to_event": True,
        "remove_tag_from_event": True,
        "add_observable": True,
        "update_observable": True,
        "delete_observable": True,
        "add_tag_to_observable": True,
        "remove_tag_from_observable": True,
        "add_agent": True,
        "view_agents": True,
        "update_agent": True,
        "delete_agent": True,
        "pair_agent": True,
        "add_input": True,
        "view_inputs": True,
        "update_input": True,
        "delete_input": True,
        "create_case": True,
        "view_cases": True,
        "update_case": True,
        "delete_case": True,
        "create_case_comment": True,
        "view_case_comments": True,
        "update_case_comment": True,
        "delete_case_comment": True,
        "view_plugins": True,
        "create_plugin": True,
        "delete_plugin": True,
        "update_plugin": True,
        "create_agent_group": True,
        "view_agent_groups": True,
        "update_agent_group": True,
        "delete_agent_group": True,
        "create_user_group": True,
        "view_user_groups": True,
        "update_user_groups": True,
        "delete_user_group": True,
        "create_case_template": True,
        "view_case_templates": True,
        "update_case_template": True,
        "delete_case_template": True,
        "create_case_task": True,
        "view_case_tasks": True,
        "update_case_task": True,
        "delete_case_task": True,
        "create_case_template_task": True,
        "view_case_template_tasks": True,
        "update_case_template_task": True,
        "delete_case_template_task": True,
        "create_case_status": True,
        "update_case_status": True,
        "delete_case_status": True,
        'update_settings': True,
        'view_settings': True,
        "use_api": True,
        "add_list": True,
        "update_list": True,
        "view_lists": True,
        "delete_list": True,
        "create_data_type": True,
        "update_data_type": True,
        "create_persistent_pairing_token": True,
        "create_event_rule": True,
        "update_event_rule": True,
        "delete_event_rule": True,
        "view_event_rules": True,
        'upload_case_files': True,
        'view_case_files': True,
        'delete_case_files': True,
        "create_close_reason": True,
        "update_close_reason": True,
        "delete_close_reason": True,
        "add_agent_group": True,
        "view_agent_groups": True,
        "update_agent_group": True,
        "delete_agent_group": True
    }

    role_contents = {
        'name': 'Admin',
        'description': 'Super Administrator',
        'permissions': perms,
        'members': [admin_id]
    }

    role = Role(**role_contents)
    role.save()


def create_analyst_role():

    perms = { 
        'view_users': True,
        'view_roles': True,
        "add_tag": True,
        "update_tag": True,
        "delete_tag": True,
        "view_tags": True,
        "add_credential": True,
        "update_credential": True,
        "decrypt_credential": True,
        "delete_credential": True,
        "view_credentials": True ,
        "add_playbook": True,
        "view_playbooks": True,
        "add_tag_to_playbook": True,
        "remove_tag_from_playbook": True,
        "add_event": True,
        "view_events": True,
        "update_event": True,
        "add_tag_to_event": True,
        "remove_tag_from_event": True,
        "add_observable": True,
        "update_observable": True,
        "delete_observable": True,
        "add_tag_to_observable": True,
        "remove_tag_from_observable": True,
        "add_agent": True,
        "view_agents": True,
        "view_inputs": True,
        "create_case": True,
        "view_cases": True,
        "update_case": True,
        "create_case_comment": True,
        "view_case_comments": True,
        "update_case_comment": True,
        "view_plugins": True,
        "view_agent_groups": True,
        "view_user_groups": True,
        "create_case_template": True,
        "view_case_templates": True,
        "update_case_template": True,
        "delete_case_template": True,
        "create_case_task": True,
        "view_case_tasks": True,
        "update_case_task": True,
        "delete_case_task": True,
        'view_settings': True,
        'upload_case_files': True,
        'view_case_files': True,
        'delete_case_files': True,
        "create_event_rule": True,
        "update_event_rule": True,
        "delete_event_rule": True,
        "create_close_reason": False,
        "update_close_reason": False,
        "delete_close_reason": False
    }

    role_contents = {
        'name': 'Analyst',
        'description': 'A normal analyst user',
        'permissions': perms,
        'members': []
    }

    role = Role(**role_contents)
    role.save()


def create_agent_role():

    perms = { 
        "decrypt_credential": True,
        "view_credentials": True ,
        "view_playbooks": True,
        "add_event": True,
        "update_event": True,
        "add_tag_to_event": True,
        "remove_tag_from_event": True,
        "add_observable": True,
        "update_observable": True,
        "delete_observable": True,
        "add_tag_to_observable": True,
        "remove_tag_from_observable": True,
        "view_agents": True,
        "view_plugins": True,
        "add_event": True,
        'view_settings': True
    }

    role_contents = {
        'name': 'Agent',
        'description': 'Reserved for agents',
        'permissions': perms,
        'members': []
    }

    role = Role(**role_contents)
    role.save()


def create_admin_user():
    #User.init()

    user_content = {
        'username': 'Admin',
        'email': 'admin@reflexsoar.com',
        'password': 'reflex',
        'first_name': 'Super',
        'last_name': 'Admin',
        'deleted': False
    }

    user_password = user_content.pop('password')
    user = User(**user_content)
    user.set_password(user_password)
    user.save()

    user.update(first_name='Super')

    return user.uuid


def create_default_data_types():
    #DataType.init()

    data_types = [
        {'name': 'ip', 'description': 'IP Address', 'regex': r'/^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/'},
        {'name': 'domain', 'description': 'A domain name'},
        {'name': 'fqdn', 'description': 'A fully qualified domain name of a host'},
        {'name': 'host', 'description': 'A host name'},
        {'name': 'email', 'description': 'An e-mail address', 'regex': r'/^[a-zA-Z0-9.!#$%&\'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/'},
        {'name': 'email_subject', 'description': 'An e-mail subject'},
        {'name': 'md5hash', 'description': 'A MD5 hash', 'regex': r'/[a-f0-9A-F]{32}/'},
        {'name': 'sha1hash', 'description': 'A SHA1 hash', 'regex': r'/[a-f0-9A-F]{40}/'},
        {'name': 'sha256hash', 'description': 'A SHA256 hash', 'regex': r'/[a-f0-9A-F]{64}/'},
        {'name': 'user', 'description': 'A username'},
        {'name': 'command', 'description': 'A command that was executed'},
        {'name': 'url', 'description': 'An address to a universal resource', 'regex': r'/(http|https)\:\/\/[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,3}(\/\S*)?/'},
        {'name': 'imphash', 'description': 'A hash of a binaries import table'},
        {'name': 'process', 'description': 'A process that was launched on a machine', 'regex':r'^([A-Z]?[:\\\/]).*(\.\w{3,})?$'},
        {'name': 'sid', 'description': 'A Microsoft Security Identifier', 'regex':r'^S(\-\d{1,10}){4,7}$'},
        {'name': 'mac', 'description': 'The hardware address of a network adapter, MAC address', 'regex': r'^([A-Za-z0-9]{2}\:?\-?){6}$'},
        {'name': 'detection_id', 'description': 'The ID of detection rule/signature/policy that was fired'},
        {'name': 'port', 'description': 'Network port', 'regex':r'^\d{1,5}$'},
        {'name': 'pid', 'description': 'Process ID'},
        {'name': 'generic', 'description': 'A generic data type for a data type doesn\'t exist for the specific value'}
    ]
    for d in data_types:
        data_type = DataType(**d)
        data_type.save()


def create_default_case_status():
    #CaseStatus.init()

    statuses = {
        'New': 'A new case.',
        'Closed': 'A cased that has been closed.',
        'Hold': 'A case that has been worked on but is currently not being worked.',
        'In Progress': 'A case that is currently being worked on.'
    }
    for s in statuses:
        status = CaseStatus(name=s, description=statuses[s])
        status.save()
        if s == 'Closed':
            status.closed = True
            status.save()


def create_default_closure_reasons():

    #CloseReason.init()

    reasons = [
        {'title': 'False positive', 'description': 'False positive'},
        {'title': 'No action required', 'description': 'No action required'},
        {'title': 'True positive', 'description': 'True positive'},
        {'title': 'Other', 'description': 'Other'}
    ]

    for r in reasons:
        reason = CloseReason(**r)
        reason.save()


def create_default_event_status():
    #EventStatus.init()

    statuses = {
        'New': 'A new event.',
        'Closed': 'An event that has been closed.',
        'Open': 'An event is open and being worked in a case.',
        'Dismissed': 'An event that has been ignored from some reason.'
    }
    for k in statuses:
        status = EventStatus(name=k, description=statuses[k])
        if k == 'Closed':
            status.closed = True
        status.save()

def create_default_case_templates():
    #CaseTemplate.init()

    templates = [
        {"title":"Phishing Analysis","description":"Use this case template when investigating a Phishing e-mail.","tasks":[{"title":"Fetch original e-mail","description":"Get a copy of the original e-mail so that analysis can be performed on it to determine if it really is a phishing e-mail or not.","group_uuid":None,"owner_uuid":None,"order":"0"},{"title":"Notify users","description":"Send a phishing alert e-mail to all users so they are aware they may have been targeted.  This should buy time until the e-mail is scrubbed from the environment.","group_uuid":None,"owner_uuid":None,"order":"1"},{"title":"Quarantine","description":"Remove the original message from the e-mail environment","group_uuid":None,"owner_uuid":None,"order":"2"},{"title":"Post Mortem","description":"What have we learned from this event that could help in future events?","group_uuid":None,"owner_uuid":None,"order":"3"}],"tlp":2,"severity":2,"tags":["phishing"]}
    ]

    for t in templates:
        template = CaseTemplate(**t)
        template.save()

def initial_settings():

    #Settings.init()

    settings_content = {
        'base_url': 'localhost',
        'required_case_templates': True,
        'allow_comment_deletion': False,
        'playbook_action_timeout': 300,
        'playbook_timeout': 3600,
        'logon_password_attempts': 5,
        'api_key_valid_days': 366,
        'agent_pairing_token_valid_minutes': 15,
        'peristent_pairing_token': None,
        'require_event_dismiss_comment': False,
        'allow_event_deletion': False,
        'require_case_close_comment': False,
        'assign_case_on_create': True,
        'assign_task_on_start': True,
        'allow_comment_editing': False,
        'events_page_refresh': 60,
        'events_per_page': 10,
        'require_approved_ips': False,
        'data_types': ['ip','user','host','fqdn','sha1','md5','sha256','imphash','ssdeep','vthash','network','domain','url','mail','sid','mac']
    }

    settings = Settings(**settings_content)
    settings.save()


def migrate(ALIAS, VERSION, move_data=True, update_alias=True):

    es = connections.get_connection()

    new_index = ALIAS+f"-{VERSION}"

    if not es.indices.exists(index=new_index):
        
        es.indices.create(index=new_index)

        if move_data:
            
            print(f'Upgrading {ALIAS} and moving data to {new_index}')
            es.reindex(
                body={"source": {"index": ALIAS}, "dest": {"index": new_index}},
                request_timeout=3600
            )

            es.indices.refresh(index=new_index)

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

    else:
        print(f'{ALIAS} is already upgraded')

VERSION="0.1.0"

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


admin_id = create_admin_user()
create_admin_role(admin_id)
create_analyst_role()
create_agent_role()
create_default_data_types()
create_default_closure_reasons()
create_default_case_status()
create_default_event_status()
create_default_case_templates()

initial_settings()