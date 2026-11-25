import json
import secrets
import time
import unittest
from http.client import HTTPConnection
from threading import Thread
from urllib.parse import urlencode

from benchmark import summarize
from server import Lab, TARGET, make_server, totp_code


class ReplayTests(unittest.TestCase):
    def test_graph_distinguishes_matching_marginal_counts(self):
        spray = summarize('spray', True)
        control = summarize('control', True)
        self.assertEqual(spray['failures'], control['failures'])
        for result in (spray, control):
            self.assertFalse(result['ip_alert'])
            self.assertFalse(result['account_alert'])
        self.assertEqual(spray['first_graph_alert_at'], 8)
        self.assertIsNone(control['first_graph_alert_at'])
        self.assertTrue(summarize('single', True)['ip_alert'])


class HttpPolicyTests(unittest.TestCase):
    def setUp(self):
        self.password = secrets.token_urlsafe(24)
        self.lab = Lab(password=self.password)
        for ip in ('192.0.2.10', '192.0.2.11', '192.0.2.12'):
            for account in (TARGET, 'user02', 'user03'):
                self.lab.detector.record_failure(ip, account, 'web' if ip.endswith('0') else 'api')
        self.server = make_server(self.lab)
        self.worker = Thread(target=self.server.serve_forever, daemon=True)
        self.worker.start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.worker.join, 3)
        self.addCleanup(self.server.shutdown)

    def request(self, path, fields=None, *, form=False, token=None):
        headers = {'Authorization': f'Bearer {token}'} if token else {}
        body = None
        if fields is not None:
            headers['Content-Type'] = 'application/x-www-form-urlencoded' if form else 'application/json'
            body = urlencode(fields) if form else json.dumps(fields)
        conn = HTTPConnection('127.0.0.1', self.server.server_port, timeout=5)
        try:
            conn.request('GET' if fields is None else 'POST', path, body, headers)
            response = conn.getresponse()
            return response.status, response.read()
        finally:
            conn.close()

    def test_web_and_api_require_totp_before_issuing_a_session(self):
        credentials = {'username': TARGET, 'password': self.password}
        for path, form in (('/web/login', True), ('/api/login', False)):
            status, body = self.request(path, credentials, form=form)
            self.assertEqual(status, 202)
            challenge = json.loads(body)
            self.assertNotIn('session_token', challenge)
            self.assertEqual(self.request('/profile', token=challenge['challenge_id'])[0], 401)

        secret = self.lab.users[TARGET].totp_secret
        counter = int(time.time()) // 30
        nearby = {totp_code(secret, counter + offset) for offset in (-1, 0, 1)}
        invalid = next(f'{value:06d}' for value in range(4) if f'{value:06d}' not in nearby)
        fields = {'challenge_id': challenge['challenge_id'], 'code': invalid}
        self.assertEqual(self.request('/auth/otp', fields)[0], 401)
        fields['code'] = totp_code(secret, int(time.time()) // 30)
        status, body = self.request('/auth/otp', fields)
        self.assertEqual(status, 200)
        session = json.loads(body)['session_token']
        self.assertEqual(self.request('/profile', token=session)[0], 200)
        self.assertEqual(self.request('/auth/otp', fields)[0], 401)

    def test_ips_off_allows_normal_session(self):
        self.lab.enforce = False
        status, body = self.request('/api/login', {'username': TARGET, 'password': self.password})
        self.assertEqual(status, 200)
        self.assertEqual(self.request('/profile', token=json.loads(body)['session_token'])[0], 200)
