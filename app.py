"""Private web dashboard for the dogty ldn_mitm UDP relay. Python 3.8+."""
import collections
import hashlib
import hmac
import importlib.util
import ipaddress
import json
import logging
import os
import queue
from pathlib import Path
import secrets
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from http.cookies import SimpleCookie
from types import SimpleNamespace
from urllib.parse import urlsplit
from rooms import Rooms, ROOM_TIMEOUT

ROOT = Path(__file__).resolve().parent
LOG = logging.getLogger("relay")


def game_names_path():
    explicit = os.getenv("GAME_NAMES_FILE")
    if explicit:
        return explicit
    state = os.getenv("STATE_DIRECTORY", "").split(":")[0]
    return str(Path(state) / "game_names.json") if state else str(ROOT / "data/game_names.json")


class Monitor(logging.Handler):
    def __init__(self, allowed="", names_file=None):
        super().__init__()
        self.lock = threading.RLock()
        self.started = time.time()
        self.clients = {}
        self.events = collections.deque(maxlen=150)
        self.history = collections.deque(maxlen=60)
        self.networks = [ipaddress.ip_network(s.strip()) for s in allowed.split(",") if s.strip()]
        self.rx = self.tx = self.packets_rx = self.packets_tx = self.rejected = 0
        self.running = False
        self.error = None
        self.discovery = Rooms(names_file)
        self.discovery_lock = threading.RLock()
        self.observations = queue.Queue(maxsize=128)
        self.observation_dropped = 0
        self.observation_errors = 0
        self.observer_stop = threading.Event()
        self.observer = None
        self.room_cache = []
        self.advertisement_cache = 0

    def start_observer(self):
        if self.observer is None:
            self.observer = threading.Thread(target=self._observe, name="room-observer", daemon=True)
            self.observer.start()

    def _observe(self):
        while not self.observer_stop.is_set():
            try:
                data, endpoint, received_at = self.observations.get(timeout=.2)
            except queue.Empty:
                continue
            try:
                # Old UI updates are expendable; never revive an expired room.
                if time.time() - received_at <= 5:
                    with self.discovery_lock:
                        self.discovery.observe(data, endpoint, received_at)
                else:
                    self.observation_dropped += 1
            except Exception:
                self.observation_errors += 1
            finally:
                self.observations.task_done()

    def enqueue_observation(self, data, addr, received_at):
        # Header-only filter. Never decode, decompress or wait here.
        if not data or data[0] not in (1, 3):
            return
        if data[0] == 1:
            if len(data) < 29 or data[1] >> 4 != 4 or data[10] != 17:
                return
            udp = 1 + (data[1] & 15) * 4
            if udp < 21 or len(data) < udp + 8 or data[udp + 2:udp + 4] != b"\x2c\xbc":
                return
        try:
            self.observations.put_nowait((data, f"{addr[0]}:{addr[1]}", received_at))
        except queue.Full:
            self.observation_dropped += 1

    def permits(self, ip):
        return not self.networks or any(ipaddress.ip_address(ip) in n for n in self.networks)

    def emit(self, record):
        self.event(record.getMessage(), record.levelname.lower())

    def event(self, message, level="info"):
        with self.lock:
            self.events.append({"time": time.time(), "level": level, "message": message[:400]})

    def received(self, data, addr):
        now = time.time()
        with self.lock:
            self.rx += len(data)
            self.packets_rx += 1
            # Same protocol types understood by the bundled relay.
            valid = bool(data) and (data[0] in (0, 2) or (data[0] == 0x20 and len(data) >= 5)
                                    or (data[0] == 1 and len(data) >= 21)
                                    or (data[0] == 3 and len(data) >= 17))
            if not valid:
                return
            for key in list(self.clients):
                if now - self.clients[key]["last_seen"] > 60:
                    del self.clients[key]
            key = f"{addr[0]}:{addr[1]}"
            if key not in self.clients:
                if len(self.clients) >= 256:
                    oldest = min(self.clients, key=lambda k: self.clients[k]["last_seen"])
                    del self.clients[oldest]
                self.event(f"客户端接入 {key}")
                self.clients[key] = {"endpoint": key, "ip": addr[0], "last_seen": now,
                                     "bytes_rx": 0, "bytes_tx": 0, "virtual_ip": "", "scope": "0"}
            client = self.clients[key]
            client["last_seen"] = now
            client["bytes_rx"] += len(data)
            if data[0] == 0x20:
                client["scope"] = str(int.from_bytes(data[1:5], "big"))
            elif data[0] == 1:
                client["virtual_ip"] = socket.inet_ntoa(data[13:17])
            elif data[0] == 3:
                client["virtual_ip"] = socket.inet_ntoa(data[1:5])

    def sent(self, count, addr):
        with self.lock:
            self.tx += count
            self.packets_tx += 1
            client = self.clients.get(f"{addr[0]}:{addr[1]}")
            if client:
                client["bytes_tx"] += count

    def snapshot(self, port):
        now = time.time()
        # Mapping-file IO and room parsing cannot hold up the relay's stats lock.
        # If the observer is busy, use the last UI snapshot and retry next refresh.
        if self.discovery_lock.acquire(blocking=False):
            try:
                self.room_cache = self.discovery.snapshot(now)
                self.advertisement_cache = self.discovery.advertisements
            finally:
                self.discovery_lock.release()
        with self.lock:
            clients = [dict(c, idle_seconds=round(now - c["last_seen"], 1))
                       for c in self.clients.values() if now - c["last_seen"] <= 60]
            scopes = collections.Counter(c["scope"] for c in clients if c["scope"] != "0")
            return {"running": self.running, "error": self.error, "port": port,
                    "uptime": int(now - self.started), "clients": clients,
                    "scopes": [{"token": k, "clients": v} for k, v in scopes.items()],
                    "bytes_rx": self.rx, "bytes_tx": self.tx,
                    "packets_rx": self.packets_rx, "packets_tx": self.packets_tx,
                    "rejected": self.rejected, "allowlist_enabled": bool(self.networks),
                    "events": list(self.events), "history": list(self.history),
                    "rooms": [dict(room, age_seconds=round(max(0, now - room["last_seen"]), 1))
                              for room in self.room_cache if now - room["last_seen"] <= ROOM_TIMEOUT],
                    "room_advertisements": self.advertisement_cache,
                    "room_observer": {"queued": self.observations.qsize(),
                                      "dropped": self.observation_dropped,
                                      "errors": self.observation_errors}}


class TrackedSocket:
    def __init__(self, monitor, *args, **kwargs):
        self.monitor = monitor
        self.sock = socket.socket(*args, **kwargs)
        self.pending_observation = None

    def __getattr__(self, key):
        return getattr(self.sock, key)

    def bind(self, addr):
        self.sock.bind(addr)
        self.monitor.running = True
        self.monitor.event(f"中继监听 UDP {addr[0]}:{addr[1]}")

    def recvfrom(self, size):
        # Upstream calls recvfrom only after it finishes routing the previous
        # datagram. Hand that immutable byte buffer to the UI worker now.
        if self.pending_observation is not None:
            self.monitor.enqueue_observation(*self.pending_observation)
            self.pending_observation = None
        while True:
            data, addr = self.sock.recvfrom(size)
            if not self.monitor.permits(addr[0]):
                with self.monitor.lock:
                    self.monitor.rejected += 1
                continue
            self.monitor.received(data, addr)
            self.pending_observation = (data, addr, time.time())
            return data, addr

    def sendto(self, data, addr):
        count = self.sock.sendto(data, addr)
        self.monitor.sent(count, addr)
        return count


def start_relay(monitor, port):
    monitor.start_observer()
    spec = importlib.util.spec_from_file_location("upstream_relay", ROOT / "vendor/relay_server.py")
    relay = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(relay)
    # Replace only this module's socket namespace, not Python's global socket module.
    relay.socket = SimpleNamespace(**{k: getattr(socket, k) for k in dir(socket) if k != "socket"},
                                   socket=lambda *a, **kw: TrackedSocket(monitor, *a, **kw))
    def relay_print(*values, **kwargs):
        message = " ".join(map(str, values))
        # Packet counters are collected at the socket; avoid unbounded packet logs.
        if "new client" not in message:
            LOG.info(message)
    relay.print = relay_print
    try:
        relay.main(["--port", str(port)])
    except Exception as exc:
        monitor.error = str(exc)
        LOG.exception("中继服务退出")
    finally:
        monitor.running = False


class AdminServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address, monitor, port, password):
        self.monitor, self.relay_port = monitor, port
        self.password_hash = hashlib.sha256(password.encode()).digest()
        self.sessions = {}
        self.attempts = {}
        self.auth_lock = threading.Lock()
        self.trust_loopback_proxy = os.getenv("TRUST_LOOPBACK_PROXY", "0") == "1"
        self.max_web_connections = int(os.getenv("WEB_MAX_CONNECTIONS", "32"))
        if not 1 <= self.max_web_connections <= 128:
            raise ValueError("WEB_MAX_CONNECTIONS must be between 1 and 128")
        self.connection_slots = threading.BoundedSemaphore(self.max_web_connections)
        super().__init__(address, Handler)

    def process_request(self, request, client_address):
        if not self.connection_slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self.connection_slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.connection_slots.release()


class Handler(BaseHTTPRequestHandler):
    server_version = "RelayAdmin"

    def setup(self):
        super().setup()
        self.connection.settimeout(10)

    def log_message(self, fmt, *args):
        pass

    def reply(self, status, data, kind="application/json; charset=utf-8", cookie=None):
        content = data if isinstance(data, bytes) else json.dumps(data, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header("Content-Type", kind)
        self.send_header("Content-Length", str(len(content)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.end_headers()
        self.wfile.write(content)

    def session(self):
        cookie = SimpleCookie()
        try:
            cookie.load(self.headers.get("Cookie", ""))
            token = cookie["relay_session"].value if "relay_session" in cookie else ""
        except Exception:
            return False
        with self.server.auth_lock:
            return self.server.sessions.get(token, 0) > time.time()

    def do_GET(self):
        path = urlsplit(self.path).path
        if path == "/healthz":
            self.reply(200 if self.server.monitor.running else 503, {"ok": self.server.monitor.running})
        elif path == "/api/status":
            if not self.session():
                self.reply(401, {"error": "请先登录"})
            else:
                self.reply(200, self.server.monitor.snapshot(self.server.relay_port))
        elif path in ("/", "/app.js", "/style.css"):
            name, kind = {"/": ("index.html", "text/html; charset=utf-8"),
                          "/app.js": ("app.js", "text/javascript; charset=utf-8"),
                          "/style.css": ("style.css", "text/css; charset=utf-8")}[path]
            self.reply(200, (ROOT / "static" / name).read_bytes(), kind)
        else:
            self.reply(404, {"error": "不存在"})

    def do_POST(self):
        path = urlsplit(self.path).path
        origin = self.headers.get("Origin")
        if origin and urlsplit(origin).netloc != self.headers.get("Host"):
            return self.reply(403, {"error": "请求来源不匹配"})
        if self.headers.get("Content-Type", "").split(";")[0] != "application/json":
            return self.reply(415, {"error": "需要 JSON 请求"})
        if path == "/api/game-name":
            if not self.session():
                return self.reply(401, {"error": "请先登录"})
            try:
                length = int(self.headers.get("Content-Length", 0))
                if not 1 <= length <= 2048:
                    raise ValueError("请求大小无效")
                data = json.loads(self.rfile.read(length))
                with self.server.monitor.discovery_lock:
                    self.server.monitor.discovery.set_name(data.get("lcid", ""), data.get("name", ""))
            except (ValueError, AttributeError) as exc:
                return self.reply(400, {"error": str(exc)})
            except OSError:
                LOG.exception("无法保存游戏名称")
                return self.reply(500, {"error": "游戏名称目录不可写。systemd 部署请更新 service 文件、执行 daemon-reload 并重启；名称应保存到 /var/lib/ldn-relay-admin，而不是 /opt。不要关闭 ProtectSystem。"})
            return self.reply(200, {"ok": True})
        if path == "/api/login":
            ip = self.client_address[0]
            if self.server.trust_loopback_proxy and ip == "127.0.0.1":
                forwarded = self.headers.get_all("X-Real-IP", [])
                if len(forwarded) != 1:
                    return self.reply(400, {"error": "Invalid proxy address"})
                try:
                    ip = str(ipaddress.ip_address(forwarded[0]))
                except ValueError:
                    return self.reply(400, {"error": "Invalid proxy address"})
            now = time.time()
            with self.server.auth_lock:
                self.server.attempts = {k: v for k, v in self.server.attempts.items() if now - v[0] < 300}
                started, count = self.server.attempts.get(ip, (now, 0))
                if count >= 8:
                    return self.reply(429, {"error": "尝试过多，请五分钟后重试"})
                if len(self.server.attempts) >= 2048 and ip not in self.server.attempts:
                    return self.reply(429, {"error": "请稍后重试"})
                self.server.attempts[ip] = (started, count + 1)
            try:
                length = int(self.headers.get("Content-Length", 0))
                if length < 1 or length > 2048:
                    raise ValueError()
                password = json.loads(self.rfile.read(length)).get("password", "")
                valid = isinstance(password, str) and hmac.compare_digest(
                    hashlib.sha256(password.encode()).digest(), self.server.password_hash)
            except (ValueError, AttributeError):
                return self.reply(400, {"error": "请求无效"})
            if not valid:
                return self.reply(401, {"error": "密码不正确"})
            token = secrets.token_urlsafe(32)
            with self.server.auth_lock:
                self.server.sessions = {k: v for k, v in self.server.sessions.items() if v > now}
                if len(self.server.sessions) >= 100:
                    self.server.sessions.pop(next(iter(self.server.sessions)))
                self.server.sessions[token] = now + 43200
                self.server.attempts.pop(ip, None)
            secure = "; Secure" if os.getenv("COOKIE_SECURE", "0") == "1" else ""
            self.reply(200, {"ok": True}, cookie="relay_session=" + token + "; Path=/; HttpOnly; SameSite=Strict; Max-Age=43200" + secure)
        elif path == "/api/logout":
            cookie = SimpleCookie(self.headers.get("Cookie", ""))
            with self.server.auth_lock:
                if "relay_session" in cookie:
                    self.server.sessions.pop(cookie["relay_session"].value, None)
            self.reply(200, {"ok": True}, cookie="relay_session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0" + ("; Secure" if os.getenv("COOKIE_SECURE", "0") == "1" else ""))
        else:
            self.reply(404, {"error": "不存在"})


def main():
    password = os.getenv("ADMIN_PASSWORD", "")
    if len(password) < 12:
        raise SystemExit("请设置至少 12 位的 ADMIN_PASSWORD，勿将密码提交到仓库。")
    port = int(os.getenv("RELAY_PORT", "11544"))
    web_port = int(os.getenv("WEB_PORT", "8080"))
    if not 1 <= port <= 65535 or not 1 <= web_port <= 65535:
        raise SystemExit("端口必须在 1–65535 之间")
    monitor = Monitor(os.getenv("ALLOWED_CLIENTS", ""), game_names_path())
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
    LOG.addHandler(monitor)
    server = AdminServer((os.getenv("WEB_BIND", "0.0.0.0"), web_port), monitor, port, password)
    threading.Thread(target=start_relay, args=(monitor, port), daemon=True).start()
    def sample():
        while True:
            with monitor.lock:
                monitor.history.append({"time": time.time(), "rx": monitor.rx, "tx": monitor.tx})
            time.sleep(2)
    threading.Thread(target=sample, daemon=True).start()
    LOG.info("管理页面监听 %s:%s", *server.server_address)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        monitor.observer_stop.set()


if __name__ == "__main__":
    main()
