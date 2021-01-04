import json
import unittest
from flask.testing import FlaskClient

from app import create_app, db
from app.models import *

API_VERSION = 'v2.0'

class RESTClient(FlaskClient):
    def open(self, *args, **kwargs):
        kwargs.setdefault('content_type', 'application/json')
        return super().open(*args, **kwargs)


class BaseTest(unittest.TestCase):

    def setUp(self):
        self.app = create_app('development')
        self.app.test_client_class = RESTClient
        self.client = self.app.test_client()

    def login(self, username='admin', password='reflex'):

        body = {
            'username': username,
            'password': password
        }
        return self.client.post('/api/'+API_VERSION+'/auth/login', data=json.dumps(body))

    def logout(self, headers):
        return self.client.get('/api/'+API_VERSION+'/auth/logout', headers=headers)

    def auth_headers(self, data):
        return {'Authorization': 'Bearer {}'.format(data.json['access_token'])}

    def bad_headers(self, token=True):
        if token:
            return {'Authorization': 'Bearer FOOBAR'}
        else:
            return {}        