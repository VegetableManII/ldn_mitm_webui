"""Bounded observer for dogty LANDiscovery frames; never modifies relay traffic.

Layouts: ldn_types.hpp (NetworkInfo 0x480, NodeInfo 0x40), lan_protocol.hpp
(12-byte LE header), relay_client.cpp (BE IPv4 fragment wrapper).
"""
import json
import os
from pathlib import Path
import re
import socket
import struct
import tempfile
import time

ROOM_TIMEOUT = 30
ROOM_RETENTION = ROOM_TIMEOUT
MAX_PACKET = 4096


def expand_zeros(data, expected):
    if expected > 2048:
        raise ValueError("decompressed packet too large")
    out = bytearray()
    i = 0
    while i < len(data):
        value = data[i]
        i += 1
        if value == 0:
            if i == len(data):
                raise ValueError("truncated zero run")
            count = data[i] + 1
            i += 1
            out.extend(bytes(count))
        else:
            out.append(value)
        if len(out) > expected:
            raise ValueError("zero run overflow")
    if len(out) != expected:
        raise ValueError("wrong decompressed size")
    return bytes(out)


class Rooms:
    def __init__(self, names_file=None):
        self.rooms = {}
        self.fragments = {}
        self.names_file = Path(names_file) if names_file else None
        self.names = {}
        self.advertisements = 0
        if self.names_file and self.names_file.exists():
            if self.names_file.stat().st_size > 262144:
                raise ValueError("game name file too large")
            values = json.loads(self.names_file.read_text(encoding="utf-8"))
            if not isinstance(values, dict):
                raise ValueError("game names must be a JSON object")
            for key, value in values.items():
                key = str(key).lower()
                if key.startswith("0x"):
                    key = key[2:]
                if re.fullmatch(r"[0-9a-f]{16}", key) and isinstance(value, str):
                    self.names[key] = value[:100]

    def set_name(self, lcid, name):
        lcid = str(lcid).lower()
        if lcid.startswith("0x"):
            lcid = lcid[2:]
        if not re.fullmatch(r"[0-9a-f]{16}", lcid) or not isinstance(name, str) or len(name) > 100:
            raise ValueError("游戏标识需要 16 位十六进制，名称最多 100 个字符")
        updated = dict(self.names)
        if name.strip():
            updated[lcid] = name.strip()
        else:
            updated.pop(lcid, None)
        if len(updated) > 1000:
            raise ValueError("游戏名称数量已达上限")
        if self.names_file:
            self.names_file.parent.mkdir(parents=True, exist_ok=True)
            temp = None
            try:
                with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=self.names_file.parent,
                                                 delete=False) as out:
                    temp = out.name
                    json.dump(updated, out, ensure_ascii=False, indent=2)
                os.replace(temp, self.names_file)
            finally:
                if temp and os.path.exists(temp):
                    os.unlink(temp)
        self.names = updated

    def _ipv4(self, data, endpoint, now):
        if not data:
            return None
        if data[0] == 1:
            return data[1:]
        if data[0] != 3 or len(data) < 17:
            return None
        header = data[1:17]
        part, total = header[10:12]
        length, mtu = struct.unpack_from(">HH", header, 12)
        if not (1 <= total <= 8 and part < total and 1 <= mtu <= MAX_PACKET
                and 0 < length <= mtu and len(data) == 17 + length
                and part * mtu + length <= MAX_PACKET
                and (part == total - 1 or length == mtu)):
            return None
        key = (endpoint, header[:10])
        self.fragments = {k: v for k, v in self.fragments.items() if now - v["time"] < 5}
        if key not in self.fragments:
            if len(self.fragments) >= 64:
                self.fragments.pop(next(iter(self.fragments)))
            self.fragments[key] = {"time": now, "total": total, "mtu": mtu, "parts": {}}
        slot = self.fragments[key]
        if slot["total"] != total or slot["mtu"] != mtu:
            del self.fragments[key]
            return None
        slot["parts"][part] = data[17:]
        if len(slot["parts"]) != total:
            return None
        del self.fragments[key]
        packet = b"".join(slot["parts"][i] for i in range(total))
        if len(packet) < 20 or packet[12:20] != header[:8]:
            return None
        return packet

    def observe(self, data, endpoint, now=None):
        now = time.time() if now is None else now
        packet = self._ipv4(data, endpoint, now)
        if not packet or len(packet) < 28 or len(packet) > MAX_PACKET or packet[0] >> 4 != 4:
            return
        ihl = (packet[0] & 15) * 4
        size = struct.unpack_from(">H", packet, 2)[0]
        # Only complete IPv4 UDP packets; native IP fragments are not inferred.
        if ihl < 20 or size != len(packet) or packet[9] != 17 or ihl + 8 > size:
            return
        if struct.unpack_from(">H", packet, 6)[0] & 0x3fff:
            return
        _, dport, udp_size = struct.unpack_from(">HHH", packet, ihl)
        if dport != 11452 or udp_size < 20 or ihl + udp_size != size:
            return
        payload = packet[ihl + 8:]
        magic, kind, compressed, length, expanded, seq = struct.unpack_from("<IBBHHH", payload)
        if magic != 0x11451400 or kind not in (1, 3) or compressed not in (0, 1):
            return
        if length != len(payload) - 12 or length > 2048:
            return
        body = payload[12:]
        if compressed:
            try:
                body = expand_zeros(body, expanded)
            except ValueError:
                return
        if len(body) != 0x480:
            return
        maximum, current = body[0x66:0x68]
        if not 1 <= current <= maximum <= 8 or body[38] > 32:
            return
        lcid = f"{struct.unpack_from('<Q', body)[0]:016x}"
        session = body[16:32].hex()
        bssid = body[32:38].hex()
        key = f"{lcid}:{session}:{bssid}"
        players = []
        for i in range(8):
            offset = 0x68 + i * 0x40
            if not body[offset + 11]:
                continue
            raw_name = body[offset + 12:offset + 45].split(b"\0", 1)[0]
            name = raw_name.decode("utf-8", errors="replace")
            name = "".join(c for c in name if c.isprintable())[:32]
            address = struct.unpack_from("<I", body, offset)[0]
            players.append({"node_id": body[offset + 10], "name": name or "未命名玩家",
                            "host": i == 0, "address": socket.inet_ntoa(struct.pack(">I", address))})
        old = self.rooms.get(key)
        # ScanResp is host-originated; SyncNetwork may be received from legacy peers.
        # Do not replace a live host's record with a different endpoint's snapshot.
        if old and old["host_endpoint"] != endpoint and now - old["last_seen"] < ROOM_TIMEOUT:
            return
        if old and old["sequence"] and seq:
            delta = (seq - old["sequence"]) & 0xffff
            if not 0 < delta < 0x8000 and now - old["last_seen"] < ROOM_TIMEOUT:
                return
        for stale in [k for k, v in self.rooms.items() if now - v["last_seen"] > ROOM_RETENTION]:
            del self.rooms[stale]
        if key not in self.rooms and len(self.rooms) >= 256:
            oldest = min(self.rooms, key=lambda k: self.rooms[k]["last_seen"])
            del self.rooms[oldest]
        self.rooms[key] = {"id": key, "lcid": lcid, "session": session, "bssid": bssid,
                           "host_endpoint": endpoint, "host_name": next((p["name"] for p in players if p["host"]), "未知房主"),
                           "current_nodes": current, "max_nodes": maximum, "joined_nodes": current - 1,
                           "players": players, "membership_consistent": len(players) == current,
                           "last_seen": now, "sequence": seq}
        self.advertisements += 1

    def snapshot(self, now=None):
        now = time.time() if now is None else now
        self.rooms = {k: v for k, v in self.rooms.items() if now - v["last_seen"] <= ROOM_RETENTION}
        result = []
        for room in self.rooms.values():
            age = max(0, now - room["last_seen"])
            result.append(dict(room, game_name=self.names.get(room["lcid"], "未知游戏"),
                               game_name_known=room["lcid"] in self.names,
                               status="online" if age <= ROOM_TIMEOUT else "stale", age_seconds=round(age, 1)))
        return sorted(result, key=lambda room: (room["status"] != "online", -room["last_seen"]))
