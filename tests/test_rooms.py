import ctypes
import json
from pathlib import Path
import socket
import struct
import tempfile
import unittest

from rooms import Rooms, expand_zeros


def compress(data):
    out = bytearray()
    i = 0
    while i < len(data):
        byte = data[i]
        i += 1
        out.append(byte)
        if byte == 0:
            count = 0
            while i < len(data) and data[i] == 0 and count < 255:
                count += 1
                i += 1
            out.append(count)
    return bytes(out)


def advertisement(current=2, maximum=8, seq=1, compressed=False, kind=1):
    body = bytearray(0x480)
    struct.pack_into("<Q", body, 0, 0x1020304050607080)
    body[16:32] = bytes(range(1, 17))
    body[32:38] = bytes(range(6))
    body[38] = 3
    body[39:42] = b"ldn"
    body[0x66:0x68] = bytes([maximum, current])
    for i in range(min(current, 8)):
        offset = 0x68 + i * 0x40
        struct.pack_into("<I", body, offset, 0xc0a80101 + i)
        body[offset + 10:offset + 12] = bytes([i, 1])
        name = ("房主" if i == 0 else "女朋友").encode()
        body[offset + 12:offset + 12 + len(name)] = name
    raw = compress(body) if compressed else bytes(body)
    lan = struct.pack("<IBBHHH", 0x11451400, kind, compressed, len(raw), len(body) if compressed else 0, seq) + raw
    header = bytearray(20)
    header[0] = 0x45
    header[9] = 17
    struct.pack_into(">H", header, 2, 28 + len(lan))
    header[12:16] = socket.inet_aton("10.13.1.1")
    header[16:20] = socket.inet_aton("10.13.255.255")
    udp = struct.pack(">HHHH", 11452, 11452, 8 + len(lan), 0)
    return b"\x01" + header + udp + lan


class RoomTests(unittest.TestCase):
    def test_layout_matches_cpp_alignment(self):
        class Node(ctypes.LittleEndianStructure):
            _fields_ = [("ip", ctypes.c_uint32), ("mac", ctypes.c_ubyte * 6),
                        ("id", ctypes.c_int8), ("connected", ctypes.c_int8),
                        ("name", ctypes.c_char * 33), ("unk", ctypes.c_uint8),
                        ("version", ctypes.c_int16), ("padding", ctypes.c_uint8 * 16)]
        self.assertEqual(ctypes.sizeof(Node), 64)
        self.assertEqual(Node.name.offset, 12)

    def test_counts_members_updates_and_out_of_order(self):
        rooms = Rooms()
        rooms.observe(advertisement(), "host:1", 100)
        room = rooms.snapshot(101)[0]
        self.assertEqual((room["current_nodes"], room["max_nodes"], room["joined_nodes"]), (2, 8, 1))
        self.assertEqual(room["players"][1]["name"], "女朋友")
        self.assertEqual(room["host_name"], "房主")
        self.assertTrue(room["membership_consistent"])
        rooms.observe(advertisement(current=1, seq=2, kind=3), "host:1", 102)
        rooms.observe(advertisement(current=2, seq=1), "host:1", 103)
        self.assertEqual(rooms.snapshot(104)[0]["current_nodes"], 1)
        # An unrelated endpoint cannot overwrite the live host snapshot.
        rooms.observe(advertisement(current=4, seq=3), "other:2", 104)
        self.assertEqual(rooms.snapshot(105)[0]["current_nodes"], 1)

    def test_compression_bounds_and_bad_frames(self):
        rooms = Rooms()
        rooms.observe(advertisement(compressed=True), "host:1", 100)
        self.assertEqual(rooms.snapshot(101)[0]["current_nodes"], 2)
        for data, length in [(b"\0", 2), (b"\0\xff", 1), (b"a", 2), (b"", 2049)]:
            with self.assertRaises(ValueError):
                expand_zeros(data, length)
        for data in [b"", b"\x01", advertisement()[:-1], advertisement(current=9), b"\x03" + bytes(16)]:
            rooms.observe(data, "bad:1", 101)
        self.assertEqual(rooms.advertisements, 1)

    def test_fragment_reassembly_reversed_and_bounded(self):
        raw = advertisement()[1:]
        parts = [raw[i:i + 600] for i in range(0, len(raw), 600)]
        frames = [b"\x03" + raw[12:20] + struct.pack(">HBBHH", 5, i, len(parts), len(part), 600) + part
                  for i, part in enumerate(parts)]
        rooms = Rooms()
        for frame in reversed(frames):
            rooms.observe(frame, "host:1", 100)
        self.assertEqual(rooms.snapshot(101)[0]["current_nodes"], 2)
        self.assertEqual(len(rooms.fragments), 0)
        rooms.observe(frames[0], "host:2", 110)
        rooms.observe(frames[1], "host:2", 116)
        self.assertEqual(rooms.advertisements, 1)

    def test_expiry_and_persistent_game_names(self):
        with tempfile.TemporaryDirectory() as path:
            names = Path(path) / "game_names.json"
            rooms = Rooms(names)
            rooms.set_name("1020304050607080", "测试游戏")
            rooms.observe(advertisement(), "host:1", 100)
            self.assertEqual(rooms.snapshot(101)[0]["game_name"], "测试游戏")
            self.assertEqual(rooms.snapshot(130)[0]["status"], "online")
            self.assertEqual(rooms.snapshot(131), [])
            self.assertEqual(rooms.snapshot(221), [])
            self.assertEqual(Rooms(names).names["1020304050607080"], "测试游戏")
            rooms.set_name("1020304050607080", "")
            self.assertEqual(json.loads(names.read_text()), {})
            with self.assertRaises(ValueError):
                rooms.set_name("invalid", "bad")


if __name__ == "__main__":
    unittest.main()
