from base_test import BaseTest, API_VERSION

class EventTests(BaseTest):

    def test_event_list(self):

        rv = self.login()
        rv = self.client.get('/api/'+API_VERSION+'/event', headers=self.auth_headers(rv))
        self.assertEqual(rv.status_code, 200)
        self.assertGreaterEqual(len(rv.json['events']), 1)

    def test_event_details(self):

        rv = self.login()
        auth_response = rv

        rv = self.client.get('/api/'+API_VERSION+'/event', headers=self.auth_headers(auth_response))

        event_uuid = rv.json['events'][0]['uuid']
        rv = self.client.get('/api/'+API_VERSION+'/event/{}'.format(event_uuid), headers=self.auth_headers(auth_response))

        self.assertEqual(rv.status_code, 200)
        self.assertEqual(rv.json['uuid'], event_uuid)

        