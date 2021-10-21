import time
import json
import datetime
from base_test import BaseTest, API_VERSION

class ThreatListTests(BaseTest):

    def test_create_threat_list(self):

        rv = self.client.get(self.api_base_url+'data_type', headers=self.auth_header)
        dt_uuid = next((dt['uuid'] for dt in rv.json if dt['name'] == 'domain'))

        threat_list = {
            "name": f"Test List {datetime.datetime.utcnow().timestamp()}",
            "list_type": "values",
            "tag_on_match": False,
            "data_type_uuid": dt_uuid,
            "values": "a\nb\nc"
        }

        rv = self.client.post(f'/api/{API_VERSION}/list', data=json.dumps(threat_list), headers=self.auth_header)
        self.assertEqual(rv.status_code, 200)
    
    def test_threat_list_listing(self):

        rv = self.client.get(self.api_base_url+'list', headers=self.auth_header)
        self.assertGreaterEqual(len(rv.json), 1)