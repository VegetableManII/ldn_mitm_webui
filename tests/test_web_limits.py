import http.client
import json
import threading
import unittest
from unittest.mock import patch

from app import AdminServer, Monitor
from http.server import ThreadingHTTPServer


class WebLimitsTests(unittest.TestCase):
    def setUp(self):
        self.env = patch.dict('os.environ', {
            'TRUST_LOOPBACK_PROXY': '1', 'COOKIE_SECURE': '1',
            'WEB_MAX_CONNECTIONS': '2'})
        self.env.start()
        self.server = AdminServer(('127.0.0.1', 0), Monitor(), 11544, 'test-password-long')
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(2)
        self.env.stop()

    def request(self, path, ip=None, password='bad'):
        conn = http.client.HTTPConnection(*self.server.server_address, timeout=2)
        headers = {'Content-Type': 'application/json'}
        if ip is not None:
            headers['X-Real-IP'] = ip
        try:
            conn.request('POST', path, json.dumps({'password': password}), headers)
            response = conn.getresponse()
            response.read()
            return response.status, dict(response.getheaders())
        finally:
            conn.close()

    def test_proxy_validation_and_separate_login_budgets(self):
        self.assertEqual(self.request('/api/login')[0], 400)
        self.assertEqual(self.request('/api/login', 'bad,address')[0], 400)
        for _ in range(8):
            self.assertEqual(self.request('/api/login', '192.0.2.1')[0], 401)
        self.assertEqual(self.request('/api/login', '192.0.2.1')[0], 429)
        self.assertEqual(self.request('/api/login', '192.0.2.2')[0], 401)

    def test_secure_login_and_logout(self):
        code, headers = self.request('/api/login', '192.0.2.3', 'test-password-long')
        self.assertEqual(code, 200)
        self.assertIn('; Secure', headers['Set-Cookie'])
        code, headers = self.request('/api/logout', '192.0.2.3')
        self.assertEqual(code, 200)
        self.assertIn('; Secure', headers['Set-Cookie'])

    def test_admission_and_failed_thread_start(self):
        slots = self.server.connection_slots
        self.assertTrue(slots.acquire(False))
        self.assertTrue(slots.acquire(False))
        with patch.object(self.server, 'shutdown_request') as close, patch.object(
                ThreadingHTTPServer, 'process_request') as dispatch:
            self.server.process_request(object(), ('127.0.0.1', 1))
            close.assert_called_once()
            dispatch.assert_not_called()
        slots.release()
        slots.release()
        with patch.object(ThreadingHTTPServer, 'process_request', side_effect=RuntimeError):
            with self.assertRaises(RuntimeError):
                self.server.process_request(object(), ('127.0.0.1', 1))
        self.assertTrue(slots.acquire(False))
        self.assertTrue(slots.acquire(False))
        self.assertFalse(slots.acquire(False))
        slots.release()
        slots.release()

    def test_worker_failure_releases_slot(self):
        self.server.connection_slots.acquire()
        with patch.object(ThreadingHTTPServer, 'process_request_thread', side_effect=RuntimeError):
            with self.assertRaises(RuntimeError):
                self.server.process_request_thread(object(), ('127.0.0.1', 1))
        self.assertTrue(self.server.connection_slots.acquire(False))
        self.assertTrue(self.server.connection_slots.acquire(False))
        self.server.connection_slots.release()
        self.server.connection_slots.release()
