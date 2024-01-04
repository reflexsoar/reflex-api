
from datetime import datetime
from uuid import uuid4

from app.api_v2.model.case import Case
from app.api_v2.model.detection import DetectionState
from app.api_v2.model.event import Event
from app.api_v2.model.user import Organization, User


def reset_detection_state():
    """
    Sets all detection states back to BALANCED on restart
    """

    for detection_state in DetectionState.search().scan():
        detection_state.status = 'BALANCED'
        detection_state.save()

def create_default_email_templates(cls, org_id, check_for_default=False):

    templates = [{
        'name': 'Default Case Created Template',
        'description': 'The default template for a new case being created',
        'subject': 'A New Case Has Been Created (ref: {{ case.uuid }})',
        'template': '''
            <p>A new case has been created in Reflex.</p>

            <p>Case Title: {{ case.title }}</p>
            <p>Case Description: {{ case.description }}</p>
            <p>Case Severity: {{ case.severity }}</p>
            <p>Total Events: {{ case.total_events }}</p>
        ''',
        'internal_id': 'default_case_created',
        'enabled': True
    }]

    # If this is the first setup of the system, we need to create the default closure reasons
    # else we will just update the existing ones and replace those that are missing
    if check_for_default == False:
        for template in templates:
            new_template = cls(**template, organization=org_id)
            new_template.save()
    else:
        orgs = Organization.search().scan()
        for org in orgs:
            existing_templates = cls.search().filter(
                'term', organization=org.uuid).execute()
            for template in templates:
                if template['internal_id'] not in [x.internal_id for x in existing_templates]:
                    new_template = cls(**template, organization=org.uuid)
                    new_template.save()
                    print(
                        f"{template['internal_id']} missing from {org.name} - {new_template}")

    return


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


def create_admin_role(cls, admin_id, org_id, org_perms=False, check_for_default=False):

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
        "view_credentials": True,
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
        "delete_detection": True,
        "create_detection_repository": True,
        "view_detection_repositories": True,
        "update_detection_repository": True,
        "delete_detection_repository": True,
        "share_detection_repository": True,
        "subscribe_detection_repository": True,
        "create_notification_channel": True,
        "view_notification_channels": True,
        "update_notification_channel": True,
        "delete_notification_channel": True,
        "view_notifications": True,
        "create_agent_policy": True,
        "view_agent_policies": True,
        "update_agent_policy": True,
        "delete_agent_policy": True,
        "create_agent_log_message": False,
        "view_agent_logs": True,
        "create_asset": True,
        "view_assets": True,
        "update_asset": True,
        "delete_asset": True,
        "create_integration": True,
        "update_integration": True,
        "delete_integration": True,
        "view_integrations": True,
        "view_integration_configurations": True,
        "create_integration_configuration": True,
        "update_integration_configuration": True,
        "delete_integration_configuration": True,
        "create_sso_provider": True,
        "update_sso_provider": True,
        "delete_sso_provider": True,
        "view_sso_providers": True,
        'create_sso_mapping_policy': True,
        'view_sso_mapping_policies': True,
        'update_sso_mapping_policy': True,
        'delete_sso_mapping_policy': True,
        'view_packages': True,
        'create_package': True,
        'update_package': True,
        'delete_package': True,
        'create_data_source_template': True,
        'view_data_source_templates': True,
        'update_data_source_template': True,
        'delete_data_source_template': True,
        'create_schedule': True,
        'view_schedules': True,
        'update_schedule': True,
        'delete_schedule': True,
        'view_fim_rules': True,
        'create_fim_rule': True,
        'update_fim_rule': True,
        'delete_fim_rule': True,
        'view_benchmarks': True,
        'create_benchmark_rule': True,
        'update_benchmark_rule': True,
        'view_benchmark_rulesets': True,
        'create_benchmark_ruleset': True,
        'update_benchmark_ruleset': True,
        'delete_benchmark_ruleset': True,
        'view_benchmark_exceptions': True,
        'create_benchmark_exclusion': True,
        'update_benchmark_exclusion': True,
        'delete_benchmark_exclusion': True,
        'create_benchmark_result': False,
        'view_agent_tags': True,
        'create_agent_tag': True,
        'update_agent_tag': True,
        'delete_agent_tag': True,
        'sync_local_subscribers': True
    }

    role_contents = {
        'name': 'Admin',
        'description': 'Administrator',
        'permissions': perms,
        'system_generated': True,
        'members': [admin_id],
        'organization': org_id
    }

    # If this is the first setup of the system, we need to create the default closure reasons
    # else we will just update the existing ones and replace those that are missing
    if check_for_default == False:
        role = cls(**role_contents)
        role.save()
    else:
        orgs = Organization.search().scan()
        for org in orgs:
            role = cls.search().filter('term', organization=org.uuid).filter(
                'term', name='Admin').execute()
            if role:
                if org.default_org:
                    perms['view_organizations'] = True
                    perms['add_organization'] = True
                    perms['update_organization'] = True
                    perms['delete_organization'] = True
                    perms['create_service_account'] = True
                    perms['view_service_accounts'] = True
                    perms['update_service_account'] = True
                    perms['delete_service_account'] = True
                    perms["create_detection_repository"] = True
                    perms["view_detection_repositories"] = True
                    perms["update_detection_repository"] = True
                    perms["delete_detection_repository"] = True
                    perms["share_detection_repository"] = True
                    perms["subscribe_detection_repository"] = True
                    perms["create_integration"] =  True
                    perms["update_integration"] = True
                    perms["view_integrations"] = True
                    perms["delete_integration"] = True
                    perms["view_integration_configurations"] = True
                    perms["create_integration_configuration"] = True
                    perms["update_integration_configuration"] = True
                    perms["delete_integration_configuration"] = True
                    perms["sync_local_subscribers"] = True
                else:
                    perms['view_organizations'] = False
                    perms['add_organization'] = False
                    perms['update_organization'] = False
                    perms['delete_organization'] = False
                    perms['create_service_account'] = False
                    perms['view_service_accounts'] = False
                    perms['update_service_account'] = False
                    perms['delete_service_account'] = False
                    perms["create_detection_repository"] = False
                    perms["view_detection_repositories"] = True
                    perms["subscribe_detection_repository"] = True
                    perms["update_detection_repository"] = False
                    perms["delete_detection_repository"] = False
                    perms["share_detection_repository"] = False
                    perms["create_integration"] =  False
                    perms["update_integration"] = False
                    perms["view_integrations"] = False
                    perms["delete_integration"] = False
                    perms["view_integration_configurations"] = False
                    perms["create_integration_configuration"] = False
                    perms["update_integration_configuration"] = False
                    perms["delete_integration_configuration"] = False
                    perms["sync_local_subscribers"] = False
                role = role[0]
                role.permissions = perms
                role.save()


def create_analyst_role(cls, org_id, org_perms=False, check_for_default=False):

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
        "view_credentials": True,
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
        "delete_detection": True,
        "create_detection_repository": False,
        "view_detection_repositories": True,
        "update_detection_repository": False,
        "delete_detection_repository": False,
        "create_notification_channel": False,
        "share_detection_repository": False,
        "subscribe_detection_repository": False,
        "view_notification_channels": True,
        "update_notification_channel": False,
        "delete_notification_channel": False,
        "view_notifications": True,
        "create_agent_policy": False,
        "view_agent_policies": True,
        "update_agent_policy": False,
        "delete_agent_policy": False,
        "create_agent_log_message": False,
        "view_agent_logs": False,
        "create_service_account": False,
        "view_service_accounts": False,
        "update_service_account": False,
        "delete_service_account": False,
        "create_asset": False,
        "view_assets": True,
        "update_asset": False,
        "delete_asset": False,
        "create_sso_provider": False,
        "update_sso_provider": False,
        "delete_sso_provider": False,
        "view_sso_providers": False,
        'create_sso_mapping_policy': False,
        'view_sso_mapping_policies': False,
        'update_sso_mapping_policy': False,
        'delete_sso_mapping_policy': False,
        'view_packages': False,
        'create_package': False,
        'update_package': False,
        'delete_package': False,
        'create_data_source_template': False,
        'view_data_source_templates': False,
        'update_data_source_template': False,
        'delete_data_source_template': False,
        'create_schedule': False,
        'view_schedules': True,
        'update_schedule': False,
        'delete_schedule': False,
        'view_fim_rules': True,
        'create_fim_rule': False,
        'update_fim_rule': False,
        'delete_fim_rule': False,
        'view_benchmarks': True,
        'create_benchmark_rule': False,
        'update_benchmark_rule': False,
        'view_benchmark_rulesets': False,
        'create_benchmark_ruleset': False,
        'update_benchmark_ruleset': False,
        'delete_benchmark_ruleset': False,
        'view_benchmark_exceptions': False,
        'create_benchmark_exclusion': False,
        'update_benchmark_exclusion': False,
        'delete_benchmark_exclusion': False,
        'create_benchmark_result': False,
        'view_agent_tags': True,
        'create_agent_tag': False,
        'update_agent_tag': False,
        'delete_agent_tag': False,
        'view_lists': True,
        'add_list': False,
        'update_list': False,
        'delete_list': False,
        'sync_local_subscribers': False
    }

    role_contents = {
        'name': 'Analyst',
        'description': 'A normal analyst user',
        'permissions': perms,
        'system_generated': True,
        'members': [],
        'organization': org_id
    }

    # If this is the first setup of the system, we need to create the default closure reasons
    # else we will just update the existing ones and replace those that are missing
    if check_for_default == False:
        role = cls(**role_contents)
        role.save()
    else:
        orgs = Organization.search().scan()
        for org in orgs:
            role = cls.search().filter('term', organization=org.uuid).filter(
                'term', name='Analyst').execute()
            if role:
                if org.default_org:
                    perms['view_organizations'] = True
                else:
                    perms['view_organizations'] = False
                role = role[0]
                role.permissions = perms
                role.save()


def create_agent_role(cls, org_id, check_for_default=False):

    perms = {
        "decrypt_credential": True,
        "view_credentials": True,
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
        "view_lists": True,
        'view_settings': True,
        'view_inputs': True,
        'view_detections': True,
        'update_input': True,
        'update_detection': True,
        "view_agent_policies": True,
        "create_agent_log_message": True,
        "view_agent_logs": True,
        "create_service_account": False,
        "view_service_accounts": False,
        "update_service_account": False,
        "delete_service_account": False,
        "view_packages": True,
        "view_data_source_templates": True,
        'view_fim_rules': True,
        'view_benchmarks': True,
        'create_benchmark_result': True
    }

    role_contents = {
        'name': 'Agent',
        'description': 'Reserved for agents',
        'permissions': perms,
        'system_generated': True,
        'members': [],
        'organization': org_id
    }

    # If this is the first setup of the system, we need to create the default closure reasons
    # else we will just update the existing ones and replace those that are missing
    if check_for_default == False:
        role = cls(**role_contents)
        role.save()
    else:
        orgs = Organization.search().scan()
        for org in orgs:
            role = cls.search().filter('term', organization=org.uuid).filter(
                'term', name='Agent').execute()
            if role:
                role = role[0]
                role.permissions = perms
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
        {'name': 'ip', 'description': 'IP Address',
            'regex': r'/^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/'},
        {'name': 'domain', 'description': 'A domain name'},
        {'name': 'fqdn', 'description': 'A fully qualified domain name of a host'},
        {'name': 'host', 'description': 'A host name'},
        {'name': 'filepath', 'description': 'The full path to a file'},
        {'name': 'email', 'description': 'An e-mail address',
            'regex': r'/^[a-zA-Z0-9.!#$%&\'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/'},
        {'name': 'email_subject', 'description': 'An e-mail subject'},
        {'name': 'md5hash', 'description': 'A MD5 hash',
            'regex': r'/[a-f0-9A-F]{32}/'},
        {'name': 'sha1hash', 'description': 'A SHA1 hash',
            'regex': r'/[a-f0-9A-F]{40}/'},
        {'name': 'sha256hash', 'description': 'A SHA256 hash',
            'regex': r'/[a-f0-9A-F]{64}/'},
        {'name': 'user', 'description': 'A username'},
        {'name': 'command', 'description': 'A command that was executed'},
        {'name': 'url', 'description': 'An address to a universal resource',
            'regex': r'/(http|https)\:\/\/[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,3}(\/\S*)?/'},
        {'name': 'imphash', 'description': 'A hash of a binaries import table'},
        {'name': 'process', 'description': 'A process that was launched on a machine',
            'regex': r'^([A-Z]?[:\\\/]).*(\.\w{3,})?$'},
        {'name': 'sid', 'description': 'A Microsoft Security Identifier',
            'regex': r'^S(\-\d{1,10}){4,7}$'},
        {'name': 'mac', 'description': 'The hardware address of a network adapter, MAC address',
            'regex': r'^([A-Za-z0-9]{2}\:?\-?){6}$'},
        {'name': 'detection_id',
            'description': 'The ID of detection rule/signature/policy that was fired'},
        {'name': 'port', 'description': 'Network port', 'regex': r'^\d{1,5}$'},
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


def create_default_closure_reasons(cls, org_id, check_for_default=False):

    reasons = [
        {'title': 'False positive',
            'description': 'Event matched detection rule but is not malicious', 'enabled': True},
        {'title': 'No action required',
            'description': 'No action required', 'enabled': True},
        {'title': 'True positive', 'description': 'Event is malicious', 'enabled': True},
        {'title': 'Other', 'description': 'Any other reason not listed', 'enabled': True},
        {'title': 'Insufficient Information',
            'description': 'Additional enrichment and data is needed for this alert to be actionable.', 'enabled': True},
        {'title': 'Informational Event', 'description': 'Detection provides data that is not normally malicious but should be evaluated to ensure it is expected.', 'enabled': True},
        {'title': 'Rule Defective',
            'description': 'Alert rule is not firing correctly.', 'enabled': True},
        {'title': 'Benign Activity',
            'description': 'Event is not malicious', 'enabled': True},
    ]

    # If this is the first setup of the system, we need to create the default closure reasons
    # else we will just update the existing ones and replace those that are missing
    if check_for_default == False:
        for r in reasons:
            reason = cls(**r, organization=org_id)
            reason.save()
    else:
        orgs = Organization.search().scan()
        for org in orgs:
            existing_reasons = cls.search().filter('term', organization=org.uuid).execute()
            for r in reasons:
                if r['title'] not in [reason.title for reason in existing_reasons]:
                    new_reason = next(
                        (reason for reason in reasons if reason['title'] == r['title']), None)
                    reason = cls(**new_reason, organization=org.uuid)
                    reason.save()
                    print(f"{r['title']} missing from {org.name} - {new_reason}")


def create_default_event_status(cls, org_id, check_for_default=False):

    statuses = {
        'New': 'A new event.',
        'Closed': 'An event that has been closed.',
        'Open': 'An event is open and being worked in a case.',
        'Dismissed': 'An event that has been ignored from some reason.',
        'Acknowledged': 'An event that has been acknowledged by an analyst.'
    }
    if check_for_default is False:
        for k in statuses:
            status = cls(name=k, description=statuses[k], organization=org_id)
            if k == 'Closed':
                status.closed = True
            status.save()
    else:
        orgs = Organization.search().scan()
        for org in orgs:
            existing_statuses = cls.search().filter('term', organization=org.uuid).execute()
            for k in statuses:
                if k not in [status.name for status in existing_statuses]:
                    
                    status = cls(name=k, description=statuses[k], organization=org.uuid)
                    if k == 'Closed':
                        status.closed = True
                    status.save()
                    print(f"Status \"{k}\" missing from {org.uuid} - Adding new status.")


def create_default_case_templates(cls, org_id):

    templates = [
        {"title": "Phishing Analysis", "description": "Use this case template when investigating a Phishing e-mail.", "tasks": [{"title": "Fetch original e-mail", "description": "Get a copy of the original e-mail so that analysis can be performed on it to determine if it really is a phishing e-mail or not.", "group_uuid": None, "owner_uuid": None, "order": "0"}, {"title": "Notify users", "description": "Send a phishing alert e-mail to all users so they are aware they may have been targeted.  This should buy time until the e-mail is scrubbed from the environment.", "group_uuid": None, "owner_uuid": None, "order": "1"}, {
            "title": "Quarantine", "description": "Remove the original message from the e-mail environment", "group_uuid": None, "owner_uuid": None, "order": "2"}, {"title": "Post Mortem", "description": "What have we learned from this event that could help in future events?", "group_uuid": None, "owner_uuid": None, "order": "3"}], "tlp": 2, "severity": 2, "tags": ["phishing"]}
    ]

    for t in templates:
        template = cls(**t, organization=org_id)
        template.save()


def set_install_uuid():
    '''
    Creates an install UUID for the default organization if one does not exist
    '''

    org = Organization.search().filter('term', default_org=True).execute()
    if org:
        org = org[0]
        if not hasattr(org, 'install_uuid') or org.install_uuid == None:
            org.install_uuid = uuid4()
            org.save()


def send_telemetry():
    '''
    Sends telemetry and usage information to telemetry.reflexsoar.com for usage in ReflexSOAR
    product improvements and community support.  No sensitive information about the environment
    is sent to the telemetry server.
    '''

    telemetry_body = {
        'install_uuid': '',
        'org_count': 0,
        'user_count': 0,
        'case_count': 0,
        'event_count': 0,
        'last_restart': datetime.utcnow().isoformat()
    }

    org = Organization.search().filter('term', default_org=True).execute()
    if org:
        org = org[0]
        telemetry_body['install_uuid'] = org.install_uuid

    telemetry_body['user_count'] = User.search().count()
    telemetry_body['case_count'] = Case.search().count()
    telemetry_body['org_count'] = Organization.search().count()
    telemetry_body['event_count'] = Event.search().count()

    # TODO: Add the API call to telemetry.reflexsoar.com using requests
    print(telemetry_body)

def initial_settings(cls, org_id, check_for_default=False):

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
        'reopen_case_on_event_merge': False,
        'allow_comment_editing': False,
        'events_page_refresh': 60,
        'events_per_page': 10,
        'require_approved_ips': False,
        'data_types': ['ip', 'user', 'host', 'fqdn', 'sha1', 'md5', 'sha256', 'imphash', 'ssdeep', 'vthash', 'network', 'domain', 'url', 'mail', 'sid', 'mac'],
        'organization': org_id,
        'case_sla_days': 14,
        'event_sla_minutes': 5,
        'allow_user_registration': False,
        'default_self_registration_role': '',
        'utc_offset': '+00:00',
        'slow_detection_threshold': 5000,
        'high_volume_threshold': 5000,
        'slow_detection_warning_threshold': 1000,
        'high_volume_warning_threshold': 1000,
        'benchmark_history_retention': 365
    }

    if check_for_default == False:
        settings = cls(**settings_content)
        settings.save()
    else:
        orgs = Organization.search().scan()
        for org in orgs:
            existing_settings = cls.search().filter(
                'term', organization=org.uuid).execute()[0]
            for setting in settings_content:
                if setting == 'peristent_pairing_token':
                    continue
                if getattr(existing_settings, setting) == None:
                    print(f"{setting} missing from {org.name}")
                    setattr(existing_settings, setting,
                            settings_content[setting])
            existing_settings.save()

    #settings = cls(**settings_content)
    # settings.save()
