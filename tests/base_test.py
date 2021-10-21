import json
import unittest
from flask.testing import FlaskClient

from app import create_app
#from app.api_v2.model import *

API_VERSION = 'v2.0'

class RESTClient(FlaskClient):
    def open(self, *args, **kwargs):
        kwargs.setdefault('content_type', 'application/json')
        return super().open(*args, **kwargs)


class BaseTest(unittest.TestCase):

    auth_header = {}
    api_base_url = f'/api/{API_VERSION}/'

    def setUp(self):
        self.app = create_app('development')
        self.app.test_client_class = RESTClient
        self.client = self.app.test_client()
        self.login()

    def login(self, username='admin', password='reflex'):

        body = {
            'username': username,
            'password': password
        }
        rv = self.client.post('/api/'+API_VERSION+'/auth/login', data=json.dumps(body))
        if rv.status_code == 200:
            self.auth_header = {'Authorization': f'Bearer {rv.json["access_token"]}'}
        return rv

    def logout(self, headers):
        return self.client.get('/api/'+API_VERSION+'/auth/logout', headers=headers)

    def auth_headers(self, data):
        return {'Authorization': 'Bearer {}'.format(data.json['access_token'])}

    def bad_headers(self, token=True):
        if token:
            return {'Authorization': 'Bearer FOOBAR'}
        else:
            return {}        