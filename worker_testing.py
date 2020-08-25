import ssl
import requests
from elasticsearch import Elasticsearch

response = requests.get('http://localhost:5000/input')
if response.status_code == 200:
    inputs = response.json()
    for i in inputs:
        # Fetch the credentials for the input
        if 'credential' in i:
            
            # Fetch the credential details
            print("FETCHING CRED DETAILS")
            response = requests.get('http://localhost:5000/credential/%s' % (i['credential']['uuid']))
            if response.status_code == 200:
                cred_details = response.json()

            print("FETCHING CRED SECRET")
            # Decrypt the secret
            response = requests.get('http://localhost:5000/credential/decrypt/%s' % (i['credential']['uuid']))        
            if response.status_code == 200:
                cred_data = response.json()
                secret = response.json()['secret']



        # ALL THIS CODE NEEDS TO BE AN INPUT PLUGIN
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

        
        print('RUNNING ELASTICSEARCH PLUGIN')
        if config['auth_method'] == 'http_auth':
            es_config['http_auth'] = (cred_details['username'], secret)
        else:
            es_config['api_key'] = (cred_details['username'], secret)

        es = Elasticsearch(config['hosts'], **es_config)
        body = {'query': {'range': {"@timestamp": {"gt": "now-{}".format("12d")}}}, 'size':200}
        response = es.search(index=config['index'], body=body)
        print(response)
        


        
