import pathlib
import yaml
from concurrent.futures import ThreadPoolExecutor


from app.api_v2.model import ( 
    BenchmarkRule
)

def load_benchmark_rules(app):
    '''
    Converts all the rules from the benchmark_rules folder into BenchmarkRules
    '''

    # Find all the yml files in the benchmarks_rules folder and load each one
    # as a JSON object
    rules = []
    app.logger.info('Loading benchmark rules')
    for rule in pathlib.Path('app/benchmark_rules').glob('**/*.yml'):
        with open(rule, 'r') as f:
            try:
                rules.append(yaml.load(f, Loader=yaml.FullLoader))
            except Exception as e:
                app.logger.error(f'Failed to load {rule} - {e}')
                continue

    def import_rule(rule):
        existing_rule = BenchmarkRule.search().filter('term', rule_id=rule['rule_id']).filter('term', current=True).execute()
        if existing_rule:
            existing_rule = existing_rule[0]
            if existing_rule.version < rule['version']:
                app.logger.info(f'Marking rule {rule["rule_id"]} version {rule["version"]} as inactive and creating new version')
                existing_rule.update(current=False)
            elif existing_rule.version == rule['version']:
                return  # Rule already exists and is the same version

        app.logger.info(f'Creating rule {rule["rule_id"]} version {rule["version"]}')
        new_rule = BenchmarkRule(**rule,
                                 system_managed=True,
                                 organization=None,
                                 current=True)
        new_rule.save()

    # Create a BenchmarkRule object for each rule and save it to the database
    with ThreadPoolExecutor(max_workers=10) as executor:
        executor.map(import_rule, rules)
