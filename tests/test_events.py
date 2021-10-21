import datetime
import json
from base_test import BaseTest, API_VERSION

class EventTests(BaseTest):

    def test_create_event(self):

        event_details = {
            "title": "API Test Event",
            "reference": f"api-test-{datetime.datetime.utcnow().timestamp()}",
            "description": "A test from the API",
            "tags": [
                "api-test"
            ],
            "tlp": 1,
            "severity": 2,
            "source": "unittests",
            "observables": [
                {
                "value": "tester",
                "ioc": False,
                "tlp": 0,
                "spotted": False,
                "safe": True,
                "data_type": "user",
                "tags": [
                    "test-user"
                ]
                }
            ],
            "raw_log": "Something something dark side"
        }

        rv = self.client.post(self.api_base_url+'event', data=json.dumps(event_details), headers=self.auth_header)
        self.assertEqual(rv.status_code, 200)


    def test_create_events_bulk(self):

        event_details = { 'events': [{
            "title": "API Test Event A",
            "reference": f"api-test-a-{datetime.datetime.utcnow().timestamp()}",
            "description": "A test from the API via BULK",
            "tags": [
                "api-test"
            ],
            "tlp": 1,
            "severity": 2,
            "source": "unittests",
            "observables": [
                {
                "value": "tester",
                "ioc": False,
                "tlp": 0,
                "spotted": False,
                "safe": True,
                "data_type": "user",
                "tags": [
                    "test-user"
                ]
                }
            ],
            "raw_log": "Something something dark side"
        },{
            "title": "API Test Event B",
            "reference": f"api-test-b-{datetime.datetime.utcnow().timestamp()}",
            "description": "A test from the API via BULK",
            "tags": [
                "api-test"
            ],
            "tlp": 1,
            "severity": 2,
            "source": "unittests",
            "observables": [
                {
                "value": "tester",
                "ioc": False,
                "tlp": 0,
                "spotted": False,
                "safe": True,
                "data_type": "user",
                "tags": [
                    "test-user"
                ]
                }
            ],
            "raw_log": "Something something dark side"
        }]}

        rv = self.client.post(self.api_base_url+'event/_bulk', data=json.dumps(event_details), headers=self.auth_header)
        self.assertEqual(rv.status_code, 200)
    
    def test_event_list(self):

        rv = self.login()
        rv = self.client.get('/api/'+API_VERSION+'/event', headers=self.auth_headers(rv))
        self.assertEqual(rv.status_code, 200)
        self.assertGreaterEqual(len(rv.json['events']), 1)


    def test_event_dismiss(self):

        rv = self.client.get(self.api_base_url+'event?title=API Test Event B', headers=self.auth_header)
        self.assertEqual(rv.status_code, 200)
        event = next((event for event in rv.json['events'] if event['title'] == 'API Test Event B'))
        

        rv = self.client.get(self.api_base_url+'close_reason', headers=self.auth_header)
        self.assertEqual(rv.status_code, 200)
        reason = next((reason['uuid'] for reason in rv.json if reason['title'] == 'False positive'))

        # With comment
        payload = {
            'dismiss_reason_uuid': reason,
            'dismiss_comment': 'Closed via Unit Testing'
        }

        rv = self.client.put(self.api_base_url+f'event/{event["uuid"]}', data=json.dumps(payload), headers=self.auth_header)
        self.assertEqual(rv.status_code, 200)

        # Without comment
        payload = {
            'dismiss_reason_uuid': reason
        }

        rv = self.client.put(self.api_base_url+f'event/{event["uuid"]}', data=json.dumps(payload), headers=self.auth_header)
        self.assertEqual(rv.status_code, 200)

    def test_event_details(self):

        rv = self.login()
        auth_response = rv

        rv = self.client.get('/api/'+API_VERSION+'/event', headers=self.auth_headers(auth_response))

        event_uuid = rv.json['events'][0]['uuid']
        rv = self.client.get('/api/'+API_VERSION+'/event/{}'.format(event_uuid), headers=self.auth_headers(auth_response))

        self.assertEqual(rv.status_code, 200)
        self.assertEqual(rv.json['uuid'], event_uuid)

        