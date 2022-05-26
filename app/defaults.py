def create_default_organization(cls):

    data = {
        'name': 'Default Organization',
        'description': 'The first Reflex Organization/Tenant',
        'default_org': True,
        'logon_domains': ['reflexsoar.com']
    }

    org = cls(**data)
    org.save()

    return org.uuid

def create_admin_role(cls, admin_id, org_id, org_perms=False):

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
        "view_case_events": True,
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
        "delete_agent_group": True,
        "add_organization": org_perms,
        "view_organizations": org_perms,
        "update_organization": org_perms,
        "delete_organization": org_perms,
        "create_detection": True,
        "update_detection": True,
        "view_detections": True,
        "delete_detection": True
    }

    role_contents = {
        'name': 'Admin',
        'description': 'Administrator',
        'permissions': perms,
        'system_generated': True,
        'members': [admin_id],
        'organization': org_id
    }

    role = cls(**role_contents)
    role.save()

def create_analyst_role(cls, org_id, org_perms=False):

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
        "view_case_events": True,
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
        "delete_close_reason": False,
        'view_organizations': org_perms,
        'view_event_rules': True,
        "create_detection": True,
        "update_detection": True,
        "view_detections": True,
        "delete_detection": True
    }

    role_contents = {
        'name': 'Analyst',
        'description': 'A normal analyst user',
        'permissions': perms,
        'system_generated': True,
        'members': [],
        'organization': org_id
    }

    role = cls(**role_contents)
    role.save()

def create_agent_role(cls, org_id):

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
        'view_settings': True,
        'view_inputs': True
    }

    role_contents = {
        'name': 'Agent',
        'description': 'Reserved for agents',
        'permissions': perms,
        'system_generated': True,
        'members': [],
        'organization': org_id
    }

    role = cls(**role_contents)
    role.save()

def create_admin_user(cls, org_id):

    user_content = {
        'username': 'Admin',
        'email': 'admin@reflexsoar.com',
        'password': 'reflex',
        'first_name': 'Super',
        'last_name': 'Admin',
        'deleted': False,
        'organization': org_id
    }

    user_password = user_content.pop('password')
    user = cls(**user_content)
    user.set_password(user_password)
    user.save()

    user.update(first_name='Super')

    return user.uuid

def create_default_data_types(cls, org_id):

    data_types = [
        {'name': 'ip', 'description': 'IP Address', 'regex': r'/^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/'},
        {'name': 'domain', 'description': 'A domain name'},
        {'name': 'fqdn', 'description': 'A fully qualified domain name of a host'},
        {'name': 'host', 'description': 'A host name'},
        {'name': 'filepath', 'description': 'The full path to a file'},
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
        data_type = cls(**d, organization=org_id)
        data_type.save()

def create_default_case_status(cls, org_id):

    statuses = {
        'New': 'A new case.',
        'Closed': 'A cased that has been closed.',
        'Hold': 'A case that has been worked on but is currently not being worked.',
        'In Progress': 'A case that is currently being worked on.'
    }
    for s in statuses:
        status = cls(name=s, description=statuses[s], organization=org_id)
        status.save()
        if s == 'Closed':
            status.closed = True
            status.save()

def create_default_closure_reasons(cls, org_id):

    reasons = [
        {'title': 'False positive', 'description': 'False positive'},
        {'title': 'No action required', 'description': 'No action required'},
        {'title': 'True positive', 'description': 'True positive'},
        {'title': 'Other', 'description': 'Other'}
    ]

    for r in reasons:
        reason = cls(**r, organization=org_id)
        reason.save()

def create_default_event_status(cls, org_id):

    statuses = {
        'New': 'A new event.',
        'Closed': 'An event that has been closed.',
        'Open': 'An event is open and being worked in a case.',
        'Dismissed': 'An event that has been ignored from some reason.'
    }
    for k in statuses:
        status = cls(name=k, description=statuses[k], organization=org_id)
        if k == 'Closed':
            status.closed = True
        status.save()

def create_default_case_templates(cls, org_id):

    templates = [
        {"title":"Phishing Analysis","description":"Use this case template when investigating a Phishing e-mail.","tasks":[{"title":"Fetch original e-mail","description":"Get a copy of the original e-mail so that analysis can be performed on it to determine if it really is a phishing e-mail or not.","group_uuid":None,"owner_uuid":None,"order":"0"},{"title":"Notify users","description":"Send a phishing alert e-mail to all users so they are aware they may have been targeted.  This should buy time until the e-mail is scrubbed from the environment.","group_uuid":None,"owner_uuid":None,"order":"1"},{"title":"Quarantine","description":"Remove the original message from the e-mail environment","group_uuid":None,"owner_uuid":None,"order":"2"},{"title":"Post Mortem","description":"What have we learned from this event that could help in future events?","group_uuid":None,"owner_uuid":None,"order":"3"}],"tlp":2,"severity":2,"tags":["phishing"]}
    ]

    for t in templates:
        template = cls(**t, organization=org_id)
        template.save()

def initial_settings(cls, org_id):

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
        'data_types': ['ip','user','host','fqdn','sha1','md5','sha256','imphash','ssdeep','vthash','network','domain','url','mail','sid','mac'],
        'organization': org_id,
        'case_sla_days': 14,
        'event_sla_minutes': 5,
    }

    settings = cls(**settings_content)
    settings.save()