import time
import json
import datetime
from base_test import BaseTest, API_VERSION

class ThreatListTests(BaseTest):

    suffix = datetime.datetime.utcnow().timestamp()
    cred_uuid = None

    def get_credential(self):

        rv = self.client.get(self.api_base_url+'credential', headers=self.auth_header)
        cred = next((cred['uuid'] for cred in rv.json if cred['name'] == f'Foobar {self.suffix}'))
        return cred

    def test_0_credential_empty_list(self):

        rv = self.client.get(self.api_base_url+'credential?name=f00b@r', headers=self.auth_header)
        self.assertEqual(rv.status_code, 200)
        self.assertEqual(len(rv.json), 0)

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

        self.cred_uuid = rv.json['uuid']

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

    def test_decrypt_unknown_credential(self):

        rv = self.client.get(self.api_base_url+f'credential/decrypt/f00bar', headers=self.auth_header)
        self.assertEqual(rv.status_code, 404)

    def test_get_credential_details(self):

        cred = self.get_credential()
        rv = self.client.get(self.api_base_url+f'credential/{cred}', headers=self.auth_header)
        self.assertEqual(rv.status_code, 200)
        self.assertEqual(rv.json['name'], f'Foobar {self.suffix}')

    def test_get_unknown_credential_details(self):

        cred = self.get_credential()
        rv = self.client.get(self.api_base_url+f'credential/f00b@r', headers=self.auth_header)
        self.assertEqual(rv.status_code, 404)

    def test_update_credential(self):

        cred = self.get_credential()
        rv = self.client.put(self.api_base_url+f'credential/{cred}', data=json.dumps({'secret': 'bar2'}), headers=self.auth_header)
        self.assertEqual(rv.status_code, 200)

        time.sleep(1)

        rv = self.client.get(self.api_base_url+f'credential/decrypt/{cred}', headers=self.auth_header)
        self.assertEqual(rv.status_code, 200)
        self.assertEqual(rv.json['secret'], 'bar2')


    def test_z_delete_credential(self):

        cred = self.get_credential()
        rv = self.client.delete(self.api_base_url+f'credential/{cred}', headers=self.auth_header)

        time.sleep(1)

        rv = self.client.get(self.api_base_url+f'credential/{cred}', headers=self.auth_header)
        self.assertEqual(rv.status_code, 404)