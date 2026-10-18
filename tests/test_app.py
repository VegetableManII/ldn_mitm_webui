import http.client
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import sys
import time
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app import Monitor


def free_port(kind):
    with socket.socket(socket.AF_INET, kind) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class MonitorTests(unittest.TestCase):
    def test_allowlist_and_expiry(self):
        m = Monitor("192.0.2.0/24,127.0.0.1/32")
        self.assertTrue(m.permits("192.0.2.7"))
        self.assertFalse(m.permits("198.51.100.2"))
        m.received(b"\x00", ("192.0.2.7", 4000))
        self.assertEqual(len(m.snapshot(11544)["clients"]), 1)
        m.clients["192.0.2.7:4000"]["last_seen"] -= 61
        self.assertEqual(m.snapshot(11544)["clients"], [])

    def test_invalid_packet_does_not_register_client(self):
        m = Monitor()
        m.received(b"junk", ("127.0.0.1", 4000))
        self.assertEqual(m.snapshot(11544)["clients"], [])
        self.assertEqual(m.packets_rx, 1)


class IntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.web_port = free_port(socket.SOCK_STREAM)
        cls.udp_port = free_port(socket.SOCK_DGRAM)
        cls.password = secrets.token_urlsafe(24)
        env = dict(os.environ, ADMIN_PASSWORD=cls.password, WEB_PORT=str(cls.web_port),
                   RELAY_PORT=str(cls.udp_port), WEB_BIND="127.0.0.1", ALLOWED_CLIENTS="127.0.0.1/32")
        cls.process = subprocess.Popen([sys.executable, "-u", "app.py"],
                                       cwd=Path(__file__).resolve().parents[1], env=env,
                                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for _ in range(100):
            try:
                code, _, _ = cls.request("GET", "/healthz")
                if code == 200:
                    return
            except OSError:
                pass
            time.sleep(.05)
        cls.process.terminate()
        cls.process.wait(timeout=5)
        raise RuntimeError("Test service failed to start")

    @classmethod
    def tearDownClass(cls):
        cls.process.terminate()
        cls.process.wait(timeout=5)

    @classmethod
    def request(cls, method, path, body=None, headers=None):
        connection = http.client.HTTPConnection("127.0.0.1", cls.web_port, timeout=3)
        try:
            connection.request(method, path, json.dumps(body) if body is not None else None,
                               {"Content-Type": "application/json", **(headers or {})})
            response = connection.getresponse()
            return response.status, dict(response.getheaders()), response.read()
        finally:
            connection.close()

    def login(self):
        code, headers, _ = self.request("POST", "/api/login", {"password": self.password})
        self.assertEqual(code, 200)
        return headers["Set-Cookie"].split(";")[0]

    def test_auth_and_logout(self):
        self.assertEqual(self.request("GET", "/api/status")[0], 401)
        self.assertEqual(self.request("POST", "/api/login", {"password": "wrong"})[0], 401)
        cookie = self.login()
        self.assertEqual(self.request("GET", "/api/status", headers={"Cookie": cookie})[0], 200)
        self.request("POST", "/api/logout", {}, {"Cookie": cookie})
        self.assertEqual(self.request("GET", "/api/status", headers={"Cookie": cookie})[0], 401)

    def test_origin_and_static_paths(self):
        self.assertEqual(self.request("POST", "/api/login", {"password": self.password},
                                      {"Origin": "https://other.example"})[0], 403)
        self.assertEqual(self.request("GET", "/../app.py")[0], 404)
        code, headers, body = self.request("GET", "/")
        self.assertEqual(code, 200)
        self.assertIn("Content-Security-Policy", headers)
        self.assertIn(b"LDN RELAY", body)

    def test_udp_discovery_and_scope(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as a, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as b:
            a.bind(("127.0.0.1", 0)); b.bind(("127.0.0.1", 0))
            a.settimeout(2); b.settimeout(2)
            address = ("127.0.0.1", self.udp_port)
            def packet(ip):
                header = bytearray(20)
                header[0] = 0x45; header[9] = 17
                header[12:16] = socket.inet_aton(ip)
                header[16:20] = b"\xff\xff\xff\xff"
                return b"\x01" + header + b"\x10\x00\x2c\xbc" + b"discovery"
            # Learn both mappings, then verify actual forwarding, not just HTTP counters.
            a.sendto(packet("10.13.1.1"), address)
            b.sendto(packet("10.13.1.2"), address)
            self.assertEqual(a.recvfrom(4096)[0], packet("10.13.1.2"))
            a.sendto(b"\x20\x00\x00\x00\x2a", address)
            a.sendto(packet("10.13.1.1"), address)
            self.assertEqual(b.recvfrom(4096)[0], packet("10.13.1.1"))
            cookie = self.login()
            status = json.loads(self.request("GET", "/api/status", headers={"Cookie": cookie})[2])
            self.assertGreaterEqual(status["packets_tx"], 2)
            self.assertTrue(any(c["virtual_ip"] == "10.13.1.1" and c["scope"] == "42" for c in status["clients"]))


if __name__ == "__main__":
    unittest.main()
