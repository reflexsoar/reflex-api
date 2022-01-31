from base_test import BaseTest, API_VERSION


class AuthenticationTests(BaseTest):

    def test_auth(self):
        
        rv = self.login()
        self.assertEqual(rv.status_code, 200)

    def test_auth_bad_password(self):

        rv = self.login(password='foobar')
        self.assertNotEqual(rv.status_code, 200)
        self.assertEqual(rv.json['message'], 'Incorrect username or password')

    def test_auth_bad_username(self):

        rv = self.login(email='foobar@reflexsoar.com')
        self.assertNotEqual(rv.status_code, 200)
        self.assertEqual(rv.json['message'], 'Incorrect username or password')

    def test_whoami(self):

        rv = self.login()
        rv = self.client.get('/api/'+API_VERSION+'/user/me', headers=self.auth_headers(rv))
        self.assertEqual(rv.status_code, 200)
        self.assertEqual(rv.json['email'], 'admin@reflexsoar.com')

    def test_bad_token(self):

        rv = self.client.get('/api/'+API_VERSION+'/user/me', headers=self.bad_headers())
        self.assertEqual(rv.status_code, 401)
        self.assertEqual(rv.json['message'], 'Invalid access token.')

    def test_no_auth_token(self):

        rv = self.client.get('/api/'+API_VERSION+'/user/me', headers=self.bad_headers(token=False))
        self.assertEqual(rv.status_code, 403)
        self.assertEqual(rv.json['message'], 'Access token required.')

    def test_logout(self):

        rv = self.login()
        headers = self.auth_headers(rv)
        rv = self.logout(headers)
        self.assertEqual(rv.status_code, 200)
        self.assertEqual(rv.json['message'], 'Successfully logged out.')

