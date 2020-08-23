import os
import unittest
import coverage
from pybadges import badge
from flask_migrate import Migrate, MigrateCommand
from flask_script import Manager

from app import create_app, db
from app.models import AuthTokenBlacklist, User, Role, Permission

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
        "remove_tag_from_playbook": True
    }
    permissions = Permission(**perms)
    db.session.add(permissions)
    db.session.commit()

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

    # Create the default administrator account
    default_admin = {
        'email': 'admin@reflexsoar.com',
        'username': 'reflex',
        'password': 'reflex'
    }
    user = User(**default_admin)
    db.session.add(user)
    db.session.commit()

    user.role = role
    user.save()
    
    return 0

if __name__ == '__main__':
    manager.run()