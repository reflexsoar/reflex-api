import time
import json
import datetime
from base_test import BaseTest, API_VERSION

class ThreatListTests(BaseTest):

    list_suffix = datetime.datetime.utcnow().timestamp()

    def test_create_threat_list(self):

        rv = self.client.get(self.api_base_url+'data_type', headers=self.auth_header)
        dt_uuid = next((dt['uuid'] for dt in rv.json if dt['name'] == 'domain'))

        threat_list = {
            "name": f"Test List {self.list_suffix}",
            "list_type": "values",
            "tag_on_match": False,
            "data_type_uuid": dt_uuid,
            "values": "a\nb\nc"
        }

        rv = self.client.post(f'/api/{API_VERSION}/list', data=json.dumps(threat_list), headers=self.auth_header)
        self.assertEqual(rv.status_code, 200)

    def test_create_threat_list_name_already_exists(self):

        rv = self.client.get(self.api_base_url+'data_type', headers=self.auth_header)
        dt_uuid = next((dt['uuid'] for dt in rv.json if dt['name'] == 'domain'))

        threat_list = {
            "name": f"Test List {self.list_suffix}",
            "list_type": "values",
            "tag_on_match": False,
            "data_type_uuid": dt_uuid,
            "values": "a\nb\nc"
        }

        rv = self.client.post(f'/api/{API_VERSION}/list', data=json.dumps(threat_list), headers=self.auth_header)
        self.assertEqual(rv.status_code, 409)

    def test_create_threat_list_with_url_missing_polling_interval(self):

        rv = self.client.get(self.api_base_url+'data_type', headers=self.auth_header)
        dt_uuid = next((dt['uuid'] for dt in rv.json if dt['name'] == 'domain'))

        threat_list = {
            "name": f"Test List Polling Interval Test {self.list_suffix}",
            "list_type": "values",
            "tag_on_match": False,
            "data_type_uuid": dt_uuid,
            "url": "https://www.spamhaus.org/drop/edrop.txt",
            "values": "a\nb\nc"
        }

        rv = self.client.post(f'/api/{API_VERSION}/list', data=json.dumps(threat_list), headers=self.auth_header)
        self.assertEqual(rv.status_code, 400)
        self.assertEqual(rv.json['message'], 'Missing polling_interval')

        threat_list = {
            "name": f"Test List Polling Interval Test {self.list_suffix}",
            "list_type": "values",
            "tag_on_match": False,
            "data_type_uuid": dt_uuid,
            "url": "https://www.spamhaus.org/drop/edrop.txt",
            "polling_interval": 59,
            "values": "a\nb\nc"
        }

        rv = self.client.post(f'/api/{API_VERSION}/list', data=json.dumps(threat_list), headers=self.auth_header)
        self.assertEqual(rv.status_code, 400)
        self.assertEqual(rv.json['message'], 'Invalid polling interval, must be greater than or equal to 60')
        
    
    def test_threat_list_listing(self):

        rv = self.client.get(self.api_base_url+'list', headers=self.auth_header)
        self.assertGreaterEqual(len(rv.json), 1)