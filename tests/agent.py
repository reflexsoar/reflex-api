import os
import time
import socket
import requests
import ssl
import json
import logging
import urllib3
from dotenv import load_dotenv
from optparse import OptionParser as op
from elasticsearch import Elasticsearch

logging.basicConfig(format='%(asctime)s - %(message)s', level=logging.INFO)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def get_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # doesn't even have to be reachable
        s.connect(('10.255.255.255', 1))
        IP = s.getsockname()[0]
    except Exception:
        IP = '127.0.0.1'
    finally:
        s.close()
    return IP

def pair(options):
    errors = []
    if not options.token:
        errors.append('Missing argument --token')
    
    if not options.console:
        errors.append('Missing argument --console')

    
    if not options.roles:
        errors.append('Missing argument --roles')

    if len(errors) > 0:
        logging.info('\n'.join(errors))
        exit(1)

    roles = options.roles.split(',')
    token = options.token
    console = options.console

    headers = {
        'Authorization': 'Bearer {}'.format(token),
        'Content-Type': 'application/json'
    }

    agent_data = {
        "name": socket.gethostname(),
        "ip_address": get_ip(),
        "roles": roles
    }

    request = {
        'url': '{}/agent'.format(console),
        'json': agent_data,
        'headers': headers,
    }
    
    if options.proxy:
        proxies = {
            'http': options.proxy,
            'https': options.proxy
        }
        request['proxies'] = proxies

    response = requests.post(**request)
    if response.status_code == 200:
        data = response.json()
        env_file = """CONSOLE_URL='{}'
ACCESS_TOKEN='{}'
AGENT_UUID='{}'""".format(console, data['token'], data['uuid'])

        with open('.env', 'w+') as f:
            f.write(env_file)
    elif response.status_code == 409:
        logging.info('Agent already paired with console.')
        return True
    else:
        logging.info('Failed to pair the agent.')
        return False

def get_agent_config():

    headers = {
        'Authorization': 'Bearer {}'.format(os.getenv('ACCESS_TOKEN')),
        'Content-Type': 'application/json'
    }

    response = requests.get('{}/agent/{}'.format(os.getenv('CONSOLE_URL'), os.getenv('AGENT_UUID')), headers=headers)
    if response.status_code == 200:
        return response.json()

def heartbeat():
    headers = {
        'Authorization': 'Bearer {}'.format(os.getenv('ACCESS_TOKEN')),
        'Content-Type': 'application/json'
    }

    response = requests.get('{}/agent/heartbeat/{}'.format(os.getenv('CONSOLE_URL'), os.getenv('AGENT_UUID')), headers=headers)
    if response.status_code == 200:
        return response.json()

if __name__ == "__main__":
    parser = op(description='Reflex Worker Agent')
    parser.add_option('--pair', dest='pair', action='store_true')
    parser.add_option('--token', dest='token', type=str, action="store", help='Token used to pair the agent with the console')
    parser.add_option('--console', dest='console', type=str, action="store", help='FQDN name of the Reflex console')
    parser.add_option('--roles', dest='roles', type=str, action="store", help='The roles that this worker will perform')
    parser.add_option('--proxy', dest='proxy', type=str, action="store", help='If the agent is running behind a proxy you may need to set this')
    (options,args) = parser.parse_args()


    if options.pair:
        if not pair(options):
            exit(1)
    else:

        load_dotenv()

        API_URL = os.getenv('CONSOLE_URL')

        while True:
            logging.info('Running agent')
            config = get_agent_config()
            heartbeat()

            for i in config['inputs']:

                headers = {
                    'Authorization': 'Bearer {}'.format(os.getenv('ACCESS_TOKEN')),
                    'Content-Type': 'application/json'
                }

                logging.info('Running input %s' % (i['name']))

                # Fetch the credentials for the input
                if 'credential' in i:
                
                    # Fetch the credential details
                    logging.info("Fetching credentials for %s" % (i['name']))
                    response = requests.get('%s/credential/%s' % (API_URL, i['credential']['uuid']), headers=headers)
                    if response.status_code == 200:
                        cred_details = response.json()

                    # Decrypt the secret
                    response = requests.get('%s/credential/decrypt/%s' % (API_URL, i['credential']['uuid']), headers=headers)        
                    if response.status_code == 200:
                        cred_data = response.json()
                        secret = response.json()['secret']

                if i['plugin'] == "Elasticsearch":
                    context = ssl.create_default_context()

                    config = i['config']
                    if config['cafile'] != "":
                        # NEED TO FIGURE OUT WHERE TO STORE THE CAFILE, maybe as DER format in the input?
                        pass
                    else:
                        context = ssl.create_default_context()

                    CONTEXT_VERIFY_MODES = {
                        "none": ssl.CERT_NONE,
                        "optional": ssl.CERT_OPTIONAL,
                        "required": ssl.CERT_REQUIRED
                    }
                
                    context.check_hostname = config['check_hostname']
                    context.verify_mode = CONTEXT_VERIFY_MODES[config['cert_verification']]

                    es_config = {
                        "scheme": config['scheme'],
                        "ssl_context": context
                    }

                    
                    logging.info('RUNNING ELASTICSEARCH PLUGIN')
                    if config['auth_method'] == 'http_auth':
                        es_config['http_auth'] = (cred_details['username'], secret)
                    else:
                        es_config['api_key'] = (cred_details['username'], secret)

                    es = Elasticsearch(config['hosts'], **es_config)
                    body = {'query': {'range': {"@timestamp": {"gt": "now-{}".format("12d")}}}, 'size':200}
                    response = es.search(index=config['index'], body=body)
                    if response['hits']['total']['value'] > 0:
                        alerts = []
                        for record in response['hits']['hits']:
                            source = record['_source']
                            alert = {
                                'title': source['signal']['rule']['name'],
                                'description': source['signal']['rule']['description'],
                                'reference': source['signal']['parent']['id'],
                                'raw_log': source
                            }
                            alerts.append(alert)
                    headers = {
                        'content-type': 'application/json'
                    }
                  
                    response = requests.post('%s/alert/_bulk' % (API_URL), headers=headers, json={'alerts': alerts})
                    if response.status_code == 200:
                        logging.info(response.content)
            time.sleep(5)