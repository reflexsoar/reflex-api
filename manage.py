import os
import unittest
import coverage
from pybadges import badge
from flask_migrate import Migrate, MigrateCommand
from flask_script import Manager

from app import create_app, db
from app.models import AuthTokenBlacklist, User, Role, Permission, DataType, AlertStatus, AgentRole, CaseStatus

app = create_app()
app.app_context().push()
manager = Manager(app)
migrate = Migrate(app, db)
manager.add_command('db', MigrateCommand)
COV = coverage.coverage(
    branch=True, include='app/*',
    omit=['*/__init__.py','__pycache__'],
    data_file='.coverage',
    config_file='.coveragerc'
)

@manager.command
def run():
    app.run()

@manager.command
def test():
    """Runs the unit tests."""
    tests = unittest.TestLoader().discover('tests', pattern='test*.py')
    result = unittest.TextTestRunner(verbosity=2).run(tests)
    if result.wasSuccessful():
        return 0
    return 1

@manager.command
def coverage(test='*', verbosity=1):
    COV.start()
    suite = unittest.TestLoader().discover('tests', pattern='{}.py'.format(test))
    result = unittest.TextTestRunner(verbosity=int(verbosity)).run(suite)
    COV.stop()
    COV.save()
    print('Coverage Summary:')
    COV.report()
    basedir = os.path.abspath(os.path.dirname(__file__))
    covdir = os.path.join(basedir, 'tmp/coverage')
    COV.html_report(directory=covdir)
    print('HTML Version: file://%s/index.html' % covdir)
    if result.wasSuccessful():
        os.system('coverage-badge -f -o coverage.svg')
        return 0
        
    return 1

@manager.command
def security():
    pipenv_check_results = os.popen('pipenv check').read()
    if 'Passed!' in pipenv_check_results:
        s = badge(left_text='PEP 508', right_text='Passing', right_color='green')
    else:
        s = badge(left_text='PEP 508', right_text='Failing', right_color='red')

    with open('pep508.svg', 'w') as f:
        f.write(s)
        f.close()

    if 'All good!' in pipenv_check_results:
        s = badge(left_text='Vulnerable', right_text='Passing', right_color='green')
    else:
        s = badge(left_text='Vulnerable', right_text='Failing', right_color='red')

    with open('vulnerable.svg', 'w') as f:
        f.write(s)
        f.close()
    

@manager.command
def blacklist_token(token):

    blacklist = AuthTokenBlacklist(auth_token = token)
    blacklist.create()

@manager.command
def setup():

    print("Creating default adminstrator permissions...")

    # Create the Permissions for an administrator
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
        "add_alert": True,
        "view_alerts": True,
        "update_alert": True,
        "delete_alert": True,
        "add_tag_to_alert": True,
        "remove_tag_from_alert": True,
        "add_observable": True,
        "update_observable": True,
        "delete_observable": True,
        "add_tag_to_observable": True,
        "remove_tag_from_observable": True,
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
        "delete_agent_group": True
    }
    permissions = Permission(**perms)
    db.session.add(permissions)
    db.session.commit()

    print("Creating the default administrator role...")

    # Create the administrator role
    details =  {
        'name': 'Admin',
        'description': 'Power overwhelming'
    }
    role = Role(**details)
    db.session.add(role)
    db.session.commit()

    role.permissions = permissions

    role.save()

    print("Creating the administrator account...")

    # Create the default administrator account
    default_admin = {
        'email': 'admin@reflexsoar.com',
        'username': 'reflex',
        'password': 'reflex'
    }
    user = User(**default_admin)
    db.session.add(user)
    db.session.commit()
    print("Username: reflex")
    print("Password: reflex")

    user.role = role
    user.save()

    print("Creating the agent role...")
    # Create the Permissions for an administrator
    perms = { 
        "decrypt_credential": True,
        "view_credentials": True ,
        "view_playbooks": True,
        "add_alert": True,
        "update_alert": True,
        "add_tag_to_alert": True,
        "remove_tag_from_alert": True,
        "add_observable": True,
        "update_observable": True,
        "delete_observable": True,
        "add_tag_to_observable": True,
        "remove_tag_from_observable": True,
        "view_agents": True,
        "view_plugins": True,
        "add_alert": True
    }
    permissions = Permission(**perms)
    db.session.add(permissions)
    db.session.commit()

    # Create the administrator role
    details =  {
        'name': 'Agent',
        'description': 'Reserved for agents'
    }
    role = Role(**details)
    db.session.add(role)
    db.session.commit()
    role.permissions = permissions
    role.save()


    print("Creating default Observable Types")
    dataTypes = {
        'ip': 'IP Address',
        'domain': 'A domain name',
        'fqdn': 'The fully qualified domain name of a host',
        'host': 'The hosts name',
        'mail': 'An e-mail address',
        'hash': 'A hash value',
        'user': 'A username'
    }
    for k in dataTypes:
        dt = DataType(name=k, description=dataTypes[k])
        db.session.add(dt)
        db.session.commit()

    print("Creating default alert statuses")
    statuses = {
        'New': 'A new alert.',
        'Closed': 'An alert that has been closed.',
        'Dismissed': 'An alert that has been ignored from some reason.'
    }
    for k in statuses:
        status = AlertStatus(name=k, description=statuses[k])
        db.session.add(status)
        db.session.commit()
        if k == 'Closed':
            status.closed = True
            status.save()

    print("Creating default case statuses")
    statuses = {
        'New': 'A new case.',
        'Closed': 'An cased that has been closed.',
        'In Progress': 'A case that is currently being worked on.'
    }
    for k in statuses:
        status = CaseStatus(name=k, description=statuses[k])
        db.session.add(status)
        db.session.commit()
        if k == 'Closed':
            status.closed = True
            status.save()
    
    print("Creating default agent types")
    agent_types = {
        'poller': 'Runs input jobs to push data to Reflex',
        'runner': 'Runs playbook actions'
    }
    for k in agent_types:
        agent_type = AgentRole(name=k, description=agent_types[k])
        agent_type.create()
    

    return 0

if __name__ == '__main__':
    manager.run()