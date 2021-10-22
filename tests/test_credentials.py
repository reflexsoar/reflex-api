import time
import json
import datetime
from base_test import BaseTest, API_VERSION

class ThreatListTests(BaseTest):

    suffix = datetime.datetime.utcnow().timestamp()

    def test_create_credential(self):

        credential = {
            'username': 'foo',
            'secret': 'bar',
            'name': f'Foobar {self.suffix}',
            'description': 'Test Credential'
        }

        rv = self.client.post(self.api_base_url+'credential/encrypt', data=json.dumps(credential), headers=self.auth_header)
        self.assertEqual(rv.status_code, 200)
        self.assertEqual(rv.json['name'], f'Foobar {self.suffix}')

        """ Test missing fields """
        fields = ['username', 'secret', 'name', 'description']
        for field in fields:

            payload = {
                'username': 'foo',
                'secret': 'bar',
                'name': f'Foobar {field} {self.suffix}',
                'description': f'Test Credential missing {field}'
            }   
            
            del payload[field]

            rv = self.client.post(self.api_base_url+'credential/encrypt', data=json.dumps(payload), headers=self.auth_header)
            self.assertEqual(rv.status_code, 400)


    def test_decrypt_credential(self):

        time.sleep(1)
        
        rv = self.client.get(self.api_base_url+'credential', headers=self.auth_header)
        credential = next((credential['uuid'] for credential in rv.json if credential['name'] == f'Foobar {self.suffix}'))

        rv = self.client.get(self.api_base_url+f'credential/decrypt/{credential}', headers=self.auth_header)
        self.assertEqual(rv.status_code, 200)
        self.assertEqual(rv.json['secret'], 'bar')

        return

    def test_get_credential_details(self):
        return

    def test_update_credential(self):
        return

    def test_delete_credential(self):
        return