import os
import socket
import requests
import ssl
import json
from dotenv import load_dotenv
from optparse import OptionParser as op
from elasticsearch import Elasticsearch

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
        print('\n'.join(errors))
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
        print('Agent already paired with console.')
        return True
    else:
        print('Failed to pair the agent.')
        return False

def get_agent_config():

    headers = {
        'Authorization': 'Bearer {}'.format(os.getenv('ACCESS_TOKEN')),
        'Content-Type': 'application/json'
    }

    response = requests.get('{}/agent/{}'.format(os.getenv('CONSOLE_URL'), os.getenv('AGENT_UUID')))
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
        print('Running agent')

        load_dotenv()

        agent_config = get_agent_config()
        print(agent_config)
        print(os.getenv('CONSOLE_URL'))