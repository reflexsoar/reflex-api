import os
import unittest
import coverage
from pybadges import badge

from flask_migrate import Migrate, MigrateCommand
from flask_script import Manager

from app import create_app, db

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
    
    return 0

if __name__ == '__main__':
    manager.run()