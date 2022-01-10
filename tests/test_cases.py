import time
import json
import datetime
from base_test import BaseTest, API_VERSION

class CaseTests(BaseTest):

    case_suffix = datetime.datetime.utcnow().timestamp()
    test_user = None

    def get_case(self):
        rv = self.client.get(self.api_base_url+f'case?title=Test%20Case%20{self.case_suffix}', headers=self.auth_header)
        cases = rv.json['cases']
        case = next((case['uuid'] for case in cases if case['title'] == f'Test Case {self.case_suffix}'))
        return case

    # Test creating a case
    def test_1_create_case(self):

        rv = self.client.get(self.api_base_url+'user', headers=self.auth_header)
        self.test_user = next((user['uuid'] for user in rv.json if user['username'] == 'Admin'))

        case_payload = {
            "title": f"Test Case {self.case_suffix}",
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

    # Test updating a case
    def test_2_case_update_details(self):

        time.sleep(1)

        case = self.get_case()

        # Test case doesn't exist
        rv = self.client.put(self.api_base_url+f'case/f00b@r', data=json.dumps({'title': f'Test Case Updated {self.case_suffix}'}), headers=self.auth_header)
        self.assertEqual(rv.status_code, 404)

        test_url = self.api_base_url+f'case/{case}'

        rv = self.client.put(test_url, data=json.dumps({'title': f'Test Case Updated {self.case_suffix}'}), headers=self.auth_header)
        self.assertEqual(rv.status_code, 200)
        self.assertEqual(rv.json['title'], f'Test Case Updated {self.case_suffix}')

        rv = self.client.put(test_url, data=json.dumps({'title': f'Test Case {self.case_suffix}'}), headers=self.auth_header)
        self.assertEqual(rv.status_code, 200)
        self.assertEqual(rv.json['title'], f'Test Case {self.case_suffix}')

        rv = self.client.put(test_url, data=json.dumps({'severity': 5}), headers=self.auth_header)
        self.assertEqual(rv.status_code, 200)
        self.assertEqual(rv.json['severity'], 4)

        rv = self.client.put(test_url, data=json.dumps({'severity': 4}), headers=self.auth_header)
        self.assertEqual(rv.status_code, 200)
        self.assertEqual(rv.json['severity'], 4)

        rv = self.client.put(test_url, data=json.dumps({'severity': 0}), headers=self.auth_header)
        self.assertEqual(rv.status_code, 200)
        self.assertEqual(rv.json['severity'], 1)
        
        rv = self.client.put(test_url, data=json.dumps({'severity': 1}), headers=self.auth_header)
        self.assertEqual(rv.status_code, 200)
        self.assertEqual(rv.json['severity'], 1)

        rv = self.client.put(test_url, data=json.dumps({'description': 'Foobar'}), headers=self.auth_header)
        self.assertEqual(rv.status_code, 200)
        self.assertEqual(rv.json['description'], 'Foobar')

        rv = self.client.put(test_url, data=json.dumps({'tags': ['foo','bar']}), headers=self.auth_header)
        self.assertEqual(rv.status_code, 200)
        self.assertEqual(rv.json['tags'], [{'name':'foo'},{'name':'bar'}])

        # Test setting the case to In Progress
        rv = self.client.get(self.api_base_url+'case_status?name=In%20Progress', headers=self.auth_header)
        case_status = rv.json[0]['uuid']

        rv = self.client.put(test_url, data=json.dumps({'status_uuid': case_status}), headers=self.auth_header)
        self.assertEqual(rv.status_code, 200)
        self.assertEqual(rv.json['status']['name'], 'In Progress')

        # Test setting the case to Closed
        rv = self.client.get(self.api_base_url+'case_status?name=Closed', headers=self.auth_header)
        case_status = rv.json[0]['uuid']

        rv = self.client.get(self.api_base_url+'close_reason?title=False%20positive', headers=self.auth_header)
        reason = rv.json[0]['uuid']

        rv = self.client.put(test_url, data=json.dumps({'status_uuid': case_status, 'close_reason_uuid': reason}), headers=self.auth_header)
        self.assertEqual(rv.status_code, 200)
        self.assertEqual(rv.json['status']['name'], 'Closed')

        # Test assigning the case
        admin_user = self.get_admin_user()
        owner_uuid = admin_user[0]['uuid']

        rv = self.client.put(test_url, data=json.dumps({'owner': {'uuid': owner_uuid}}), headers=self.auth_header)
        self.assertEqual(rv.status_code, 200)
        self.assertEqual(rv.json['owner']['uuid'], owner_uuid)

        time.sleep(0.5)

        # Test unassigning the case
        rv = self.client.put(test_url, data=json.dumps({'owner': {}}), headers=self.auth_header)
        self.assertEqual(rv.status_code, 200)


    # Test listing cases
    def test_3_case_listing(self):

        rv = self.client.get(self.api_base_url+'case', headers=self.auth_header)
        self.assertEqual(rv.status_code, 200)
        cases = rv.json['cases']
        self.assertGreaterEqual(len(cases), 1)

    # Test case details
    def test_z_case_viewing_case_details(self):

        time.sleep(0.5)

        rv = self.client.get(self.api_base_url+f'case?title=Test%20Case%20{self.case_suffix}', headers=self.auth_header)
        cases = rv.json['cases']
        case = next((case['uuid'] for case in cases if case['title'] == f'Test Case {self.case_suffix}'))

        rv = self.client.get(self.api_base_url+f'case/{case}', headers=self.auth_header)
        self.assertEqual(rv.status_code, 200)
        self.assertEqual(rv.json['title'], f"Test Case {self.case_suffix}")

    # Test paging cases

    # Test creating a case with a template
    def test_create_case_with_case_template(self):

        rv = self.client.get(self.api_base_url+'user', headers=self.auth_header)
        self.test_user = next((user['uuid'] for user in rv.json if user['username'] == 'Admin'))

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
    def test_create_case_comment(self):

        time.sleep(0.5)

        rv = self.client.get(self.api_base_url+f'case?title=Test%20Case%20{self.case_suffix}', headers=self.auth_header)
        cases = rv.json['cases']
        case = next((case['uuid'] for case in cases if case['title'] == f'Test Case {self.case_suffix}'))


        """ Test creating a comment missing the comment """
        comment_bad_payload = {
            'case_uuid': case
        }

        rv = self.client.post(self.api_base_url+'case_comment', data=json.dumps(comment_bad_payload), headers=self.auth_header)
        self.assertEqual(rv.status_code, 400)

        """ Test creating a comment without the case associated """
        comment_bad_payload = {
            'message': 'test'
        }

        rv = self.client.post(self.api_base_url+'case_comment', data=json.dumps(comment_bad_payload), headers=self.auth_header)
        self.assertEqual(rv.status_code, 400)

        comment_payload = {
            'case_uuid': case,
            'message': 'Test comment'
        }
        
        rv = self.client.post(self.api_base_url+'case_comment', data=json.dumps(comment_payload), headers=self.auth_header)
        self.assertEqual(rv.status_code, 200)
        
        comment_details = rv.json
        self.assertEqual(comment_details['created_by']['username'], 'Admin')
        self.assertEqual(comment_details['message'], 'Test comment')

        time.sleep(1)

        """ List the comments to make sure it made it """
        rv = self.client.get(self.api_base_url+f'case_comment?case_uuid={case}', headers=self.auth_header)
        comments = rv.json
        self.assertEqual(rv.status_code, 200)
        self.assertGreaterEqual(len(comments), 1)

        """ Try to fetch comments for a case that doens't exist """
        rv = self.client.get(self.api_base_url+f'case_comment?case_uuid=foobar', headers=self.auth_header)
        comments = rv.json
        self.assertEqual(rv.status_code, 200)
        self.assertEqual(len(comments), 0)
    
    # Test fetching case history
    def test_list_case_history(self):

        rv = self.client.get(self.api_base_url+f'case?title=Test%20Case%20{self.case_suffix}', headers=self.auth_header)
        cases = rv.json['cases']
        case = next((case['uuid'] for case in cases if case['title'] == f'Test Case {self.case_suffix}'))

        rv = self.client.get(self.api_base_url+f'case_history?case_uuid={case}', headers=self.auth_header)
        self.assertEqual(rv.status_code, 200)
        self.assertGreaterEqual(len(rv.json), 0)

        """ Test fetching history for a case that doesn't exist """
        rv = self.client.get(self.api_base_url+f'case_history?case_uuid=foobar', headers=self.auth_header)
        self.assertEqual(rv.status_code, 200)
        self.assertEqual(len(rv.json), 0)
    
    # Test creating a case task
    def test_case_task_create(self):

        case = self.get_case()

        rv = self.client.post(self.api_base_url+f'/case_')

    # Test commenting on a case task

    # Test starting a case task

    # Test closing a case task

    # Test adding an observable