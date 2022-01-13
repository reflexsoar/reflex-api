import os
import coverage
import unittest
import argparse

if __name__ == "__main__":

    os.environ['REFLEX_DISABLE_SCHEDULER'] = 'true'
    os.environ['FLASK_CONFIG'] = 'testing'

    COV = coverage.coverage(
        branch=True, include='app/*',
        omit=['*/__init__.py','__pycache__'],
        data_file='.coverage',
        config_file='.coveragerc'
    )

    parser = argparse.ArgumentParser()
    parser.add_argument('--test', help="The collection of tests to run", default="*", required=False)
    parser.add_argument('--no-coverage', help="Run coverage checks", action="store_true", required=False, default=False)
    args = parser.parse_args()

    if not args.no_coverage:
        COV.start()

    tests = unittest.TestLoader().discover('tests', pattern=f'test_{args.test}.py')
    result = unittest.TextTestRunner(verbosity=2).run(tests)

    if not args.no_coverage:
        COV.stop()
        COV.save()
        COV.report()
        basedir = os.path.abspath(os.path.dirname(__file__))
        covdir = os.path.join(basedir, 'tmp/coverage')
        COV.html_report(directory=covdir)

    if result.wasSuccessful():
        if not args.no_coverage:
            os.system('coverage-badge -f -o coverage.svg')