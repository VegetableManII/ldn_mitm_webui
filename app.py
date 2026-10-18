"""Private web dashboard for the dogty ldn_mitm UDP relay. Python 3.10+."""
import collections
import hashlib
import hmac
import importlib.util
import ipaddress
import json
import logging
import os
from pathlib import Path
import secrets
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from http.cookies import SimpleCookie
from types import SimpleNamespace
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parent
LOG = logging.getLogger("relay")


class Monitor(logging.Handler):
    def __init__(self, allowed=""):
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
                    "events": list(self.events), "history": list(self.history)}


class TrackedSocket:
    def __init__(self, monitor, *args, **kwargs):
        self.monitor = monitor
        self.sock = socket.socket(*args, **kwargs)

    def __getattr__(self, key):
        return getattr(self.sock, key)

    def bind(self, addr):
        self.sock.bind(addr)
        self.monitor.running = True
        self.monitor.event(f"中继监听 UDP {addr[0]}:{addr[1]}")

    def recvfrom(self, size):
        while True:
            data, addr = self.sock.recvfrom(size)
            if not self.monitor.permits(addr[0]):
                with self.monitor.lock:
                    self.monitor.rejected += 1
                continue
            self.monitor.received(data, addr)
            return data, addr

    def sendto(self, data, addr):
        count = self.sock.sendto(data, addr)
        self.monitor.sent(count, addr)
        return count


def start_relay(monitor, port):
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
        super().__init__(address, Handler)


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
        if path == "/api/login":
            ip = self.client_address[0]
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
            self.reply(200, {"ok": True}, cookie="relay_session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0")
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
    monitor = Monitor(os.getenv("ALLOWED_CLIENTS", ""))
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
    LOG.addHandler(monitor)
    server = AdminServer((os.getenv("WEB_BIND", "127.0.0.1"), web_port), monitor, port, password)
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


if __name__ == "__main__":
    main()
