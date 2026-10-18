import socket
import threading
import time
import unittest

from app import Monitor, TrackedSocket
from test_rooms import advertisement


class ObserverTests(unittest.TestCase):
    def test_bounded_queue_and_game_filter(self):
        monitor = Monitor()
        addr = ("127.0.0.1", 12345)
        monitor.enqueue_observation(b"\x00", addr, time.time())
        game = bytearray(advertisement())
        game[23:25] = b"\x12\x34"  # wrapped UDP destination != 11452
        monitor.enqueue_observation(bytes(game), addr, time.time())
        self.assertEqual(monitor.observations.qsize(), 0)
        for _ in range(140):
            monitor.enqueue_observation(advertisement(), addr, time.time())
        self.assertEqual(monitor.observations.qsize(), 128)
        self.assertEqual(monitor.observation_dropped, 12)

    def test_blocked_parser_does_not_hold_forwarding(self):
        monitor = Monitor()
        entered, release = threading.Event(), threading.Event()
        original = monitor.discovery.observe
        def slow(*args):
            entered.set()
            release.wait(3)
            return original(*args)
        monitor.discovery.observe = slow
        monitor.start_observer()
        tracked = TrackedSocket(monitor, socket.AF_INET, socket.SOCK_DGRAM)
        tracked.bind(("127.0.0.1", 0))
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as receiver:
                sender.bind(("127.0.0.1", 0)); receiver.bind(("127.0.0.1", 0))
                receiver.settimeout(1)
                tracked.sock.settimeout(1)
                sender.sendto(advertisement(), tracked.sock.getsockname())
                packet, _ = tracked.recvfrom(4096)
                self.assertEqual(monitor.observations.qsize(), 0)
                tracked.sendto(packet, receiver.getsockname())
                self.assertEqual(receiver.recvfrom(4096)[0], packet)
                sender.sendto(b"\x00", tracked.sock.getsockname())
                tracked.recvfrom(4096)  # Previous packet has already been forwarded.
                self.assertTrue(entered.wait(1))
                tracked.sendto(b"game-traffic", receiver.getsockname())
                self.assertEqual(receiver.recvfrom(4096)[0], b"game-traffic")
                self.assertFalse(release.is_set())
                self.assertTrue(monitor.snapshot(11544)["running"])
        finally:
            release.set()
            monitor.observer_stop.set()
            monitor.observer.join(timeout=2)
            tracked.sock.close()

    def test_observer_exception_isolated(self):
        monitor = Monitor()
        def fail(*args):
            raise ValueError("bad sample")
        monitor.discovery.observe = fail
        monitor.start_observer()
        try:
            monitor.enqueue_observation(advertisement(), ("127.0.0.1", 1234), time.time())
            monitor.observations.join()
            self.assertEqual(monitor.observation_errors, 1)
            self.assertTrue(monitor.observer.is_alive())
        finally:
            monitor.observer_stop.set()
            monitor.observer.join(timeout=2)
