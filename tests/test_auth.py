import json
import unittest
from flask.testing import FlaskClient

from app import create_app, db
from app.models import *

class RESTClient(FlaskClient):
    def open(self, *args, **kwargs):
        kwargs.setdefault('content_type', 'application/json')
        return super().open(*args, **kwargs)



class AuthenticationTests(unittest.TestCase):

    def setUp(self):
        self.app = create_app('development')
        self.app.test_client_class = RESTClient
        self.client = self.app.test_client()
        ctx = self.app.app_context()
        ctx.push()

    def test_auth(self):
        body = {
            'username': 'admin@reflexsoar.com',
            'password': 'test22'
        }
        rv = self.client.post('/api/v1.0/auth/login', data=json.dumps(body))

        self.assertEqual(rv.status_code, 200)
