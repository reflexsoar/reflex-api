from base_test import BaseTest

class AuthenticationTests(BaseTest):

    def test_event_list(self):

        rv = self.login()
        rv = self.client.get('/api/v1.0/event', headers=self.auth_headers(rv))
        self.assertEqual(rv.status_code, 200)
        self.assertGreater(len(rv.json['events']), 1)

    def test_event_details(self):

        rv = self.login()
        auth_response = rv

        rv = self.client.get('/api/v1.0/event', headers=self.auth_headers(auth_response))

        event_uuid = rv.json['events'][0]['uuid']
        rv = self.client.get('/api/v1.0/event/{}'.format(event_uuid), headers=self.auth_headers(auth_response))

        self.assertEqual(rv.status_code, 200)
        self.assertEqual(rv.json['uuid'], event_uuid)

        