import time
import json
import datetime
from base_test import BaseTest, API_VERSION

class CaseTests(BaseTest):

    case_suffix = datetime.datetime.utcnow().timestamp()
    test_user = None

    # Test creating a case
    def test_create_case(self):

        rv = self.client.get(self.api_base_url+'user', headers=self.auth_header)
        self.test_user = next((user['uuid'] for user in rv.json if user['username'] == 'Admin'))

        case_payload = {
            "title": f"Test Case {self.case_suffix}",
            "owner_uuid": self.test_user,
            "description": "A test case",
            "tags": [
                "test-case"
            ],
            "tlp": 0,
            "severity": 0,
            "observables": [],
            "events": []
        }

        rv = self.client.post(self.api_base_url+'case', data=json.dumps(case_payload), headers=self.auth_header)
        self.assertEqual(rv.status_code, 200)

    # Test listing cases

    def test_case_listing(self):

        rv = self.client.get(self.api_base_url+'case', headers=self.auth_header)
        self.assertEqual(rv.status_code, 200)
        cases = rv.json['cases']
        self.assertGreaterEqual(len(cases), 1)

    # Test paging cases

    # Test creating a case with a template

    def test_create_case_with_case_template(self):

        #rv = self.client.get(self.api_base_url+'user', headers=self.auth_header)
        #self.test_user = next((user['uuid'] for user in rv.json if user['username'] == 'Admin'))

        rv = self.client.get(self.api_base_url+'case_template', headers=self.auth_header)
        template = next((template['uuid'] for template in rv.json if template['title'] == 'Phishing Analysis'))

        case_payload = {
            "title": f"Test Case with Template {self.case_suffix}",
            "owner_uuid": self.test_user,
            "description": "A test case",
            "tags": [
                "test-case"
            ],
            "tlp": 5,
            "severity": 5,
            "observables": [],
            "events": [],
            "case_template_uuid": template
        }

        rv = self.client.post(self.api_base_url+'case', data=json.dumps(case_payload), headers=self.auth_header)
        self.assertEqual(rv.status_code, 200)

    # Test creating a case comment
    
    # Test creating a case task

    # Test commenting on a case task

    # Test starting a case task

    # Test closing a case task

    # Test adding an observable