import pathlib
from concurrent.futures import ThreadPoolExecutor

import requests
import yaml

from app.api_v2.model import BenchmarkRule


def fetch_rule_config(rule_id: str, url: str) -> dict:
    ''' Fetches the rule config from the remote source
    :param rule_id: The rule id to fetch
    :param url: The url to fetch the rule from
    :return: The rule config as a dict
    '''

    headers = {
        'Accept': 'application/json',
        'Content-Type': 'application/json'
    }

    try:

        response = requests.get(f"{url}/rules/{rule_id}.json", headers=headers)
        response.raise_for_status()
        return response.json()
    except Exception as e:
        print(f'Failed to fetch rule config from {url} - {e}')
        return None


def load_benchmark_rules_from_remote(app: object) -> None:
    ''' Load benchmark rules from a remote source
    :param app: The flask app
    :return: None
    '''

    # Get the remote source from the config
    url = app.config.get('BENCHMARK_RULES_URL')

    # Get the rules from the remote source
    app.logger.info(f'Loading benchmark rules from {url}')
    try:
        response = requests.get(f"{url}/rules/rules.json")
        response.raise_for_status()
    except Exception as e:
        app.logger.error(f'Failed to load benchmark rules from {url} - {e}')
        return

    # Convert the response to a JSON object
    rules = response.json()['rules']

    # Get each rule from the remote source and save it to the database
    with ThreadPoolExecutor(max_workers=10) as executor:
        rule_data = [executor.submit(
            fetch_rule_config, rule, url) for rule in rules]

    def import_rule(rule):
        existing_rule = BenchmarkRule.search().filter(
            'term', rule_id=rule['rule_id']).filter('term', current=True).execute()
        
        if existing_rule:
            existing_rule = existing_rule[0]
            if existing_rule.version < rule['version']:
                # Mark the existing rule as inactive and create a new one
                existing_rule.update(current=False)
            elif existing_rule.version == rule['version']:
                return  # Rule already exists and is the same version

        new_rule = BenchmarkRule(**rule,
                                 system_managed=True,
                                 organization=None,
                                 current=True)
        new_rule.save()

    for rule in rule_data:
        _rule = rule.result()
        if _rule is not None and isinstance(_rule, dict):
            import_rule(_rule)
