import time
import json
import datetime
from base_test import BaseTest, API_VERSION

class UserTests(BaseTest):

    current_timestamp = datetime.datetime.utcnow().timestamp()

    def get_test_user(self, auth_headers):
        rv = self.client.get(f'/api/{API_VERSION}/user', headers=auth_headers)
        user = next((user for user in rv.json if user['username'] == f'test-user-{self.current_timestamp}'))
        user_uuid = user['uuid']
        return user_uuid

    def test_1_create_new_user(self):

        auth_headers = self.auth_headers(self.login())

        # Fetch the role to put the user in to
        roles = self.client.get(f'/api/{API_VERSION}/role', headers=auth_headers)
        role = next((role['uuid'] for role in roles.json if role['name'] == 'Admin'))

        user = {
            "username": f"test-user-{self.current_timestamp}",
            "email": f"{self.current_timestamp}@reflexsoar.com",
            "password": f"test-user",
            "first_name": "Test",
            "last_name": f"{self.current_timestamp}",
            "locked": False,
            "role_uuid": role
        }
        rv = self.client.post('/api/'+API_VERSION+'/user', data=json.dumps(user), headers=auth_headers)
        self.assertEqual(rv.status_code, 200)
        self.assertEqual(rv.json['user']['email'], f'{self.current_timestamp}@reflexsoar.com')

    def test_2_list_users(self):

        auth_headers = self.auth_headers(self.login())

        rv = self.client.get(f'/api/{API_VERSION}/user', headers=auth_headers)
        self.assertGreaterEqual(len(rv.json), 2)

    def test_3_generate_user_api_key(self):

        auth_headers = self.auth_headers(self.login())

        rv = self.client.get(f'/api/{API_VERSION}/user/generate_api_key', headers=auth_headers)
        self.assertRegex(rv.json['api_key'], r'^eyJ.*$')


    def test_4_lock_user(self):

        auth_headers = self.auth_headers(self.login())
     
        user_uuid = self.get_test_user(auth_headers)

        rv = self.client.put(f'/api/{API_VERSION}/user/{user_uuid}', data=json.dumps({'locked': True}), headers=auth_headers)
        self.assertEqual(rv.status_code, 200)
        self.assertEqual(rv.json['locked'], True)

    
    def test_5_unlock_user(self):

        auth_headers = self.auth_headers(self.login())

        user_uuid = self.get_test_user(auth_headers)

        rv = self.client.put(f'/api/{API_VERSION}/user/{user_uuid}', data=json.dumps({'locked': False}), headers=auth_headers)
        self.assertEqual(rv.status_code, 200)
        self.assertEqual(rv.json['locked'], False)

    
    def test_6_unlock_user_via_unlock_endpoint(self):

        auth_headers = self.auth_headers(self.login())

        user_uuid = self.get_test_user(auth_headers)

        rv = self.client.put(f'/api/{API_VERSION}/user/{user_uuid}/unlock', headers=auth_headers)
        self.assertEqual(rv.status_code, 200)
        self.assertEqual(rv.json['locked'], False)

    def test_7_change_user_password(self):

        auth_headers = self.auth_headers(self.login())

        user_uuid = self.get_test_user(auth_headers)

        user_data = {
            'password': 'foobar'
        }

        rv = self.client.put(f'/api/{API_VERSION}/user/{user_uuid}', data=json.dumps(user_data), headers=auth_headers)
        self.assertEqual(rv.status_code, 200)
        
        user_auth = {
            'username': f'test-user-{self.current_timestamp}',
            'password': 'foobar'
        }

        time.sleep(1)

        rv = self.client.post(f'/api/{API_VERSION}/auth/login', data=json.dumps(user_auth))
        self.assertEqual(rv.status_code, 200)

    def test_99_delete_test_user(self):

        auth_headers = self.auth_headers(self.login())

        rv = self.client.get(f'/api/{API_VERSION}/user', headers=auth_headers)
        
        user_uuid = next((user['uuid'] for user in rv.json if user['username'] == f'test-user-{self.current_timestamp}'))
        
        rv = self.client.delete(f'/api/{API_VERSION}/user/{user_uuid}', headers=auth_headers)
        self.assertEqual(rv.status_code, 200)
        