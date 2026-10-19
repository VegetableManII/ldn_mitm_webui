#!/bin/bash
# Run as root from the checked-out repository. Existing HTTPS deployment only.
set -eu
umask 077
repo=$(cd -- "$(dirname -- "$0")/.." && pwd)
test "$(id -u)" = 0
test -f "$repo/app.py"
test -f "$repo/vendor/relay_server.py"
test -f /etc/ldn-relay-admin.env
test -f /opt/ldn-relay-admin/app.py

backup=$(mktemp -d /root/ldn-web-hardening.XXXXXXXX)
cp -a /etc/ldn-relay-admin.env "$backup/env"
cp -a /opt/ldn-relay-admin/app.py "$backup/app.py"
cp -a /opt/ldn-relay-admin/vendor/relay_server.py "$backup/relay_server.py"
echo "Backup: $backup"

# Validate before replacing any files. Do not print credentials.
python3 - "$repo" <<'PY'
import ast, re, sys
from pathlib import Path
repo = Path(sys.argv[1])
for name in ('app.py', 'vendor/relay_server.py'):
    ast.parse((repo / name).read_text(encoding='utf-8'))
env = Path('/etc/ldn-relay-admin.env').read_text()
for key, expected in [('WEB_BIND', '127.0.0.1'), ('WEB_PORT', '53242'), ('COOKIE_SECURE', '1')]:
    if re.findall(r'^' + key + r'=(.*)$', env, re.M) != [expected]:
        raise SystemExit('HTTPS environment mismatch: ' + key)
for key, value in [('TRUST_LOOPBACK_PROXY', '1'), ('WEB_MAX_CONNECTIONS', '32')]:
    env = re.sub(r'^' + key + r'=.*(?:\n|$)', '', env, flags=re.M)
    env = env.rstrip('\n') + '\n' + key + '=' + value + '\n'
Path('/etc/ldn-relay-admin.env').write_text(env)
PY

rollback() {
    echo 'Restoring previous code and environment'
    cp -a "$backup/env" /etc/ldn-relay-admin.env
    cp -a "$backup/app.py" /opt/ldn-relay-admin/app.py
    cp -a "$backup/relay_server.py" /opt/ldn-relay-admin/vendor/relay_server.py
    systemctl restart ldn-relay-admin
}
trap rollback ERR
install -o root -g root -m 644 "$repo/app.py" /opt/ldn-relay-admin/app.py
install -o root -g root -m 644 "$repo/vendor/relay_server.py" /opt/ldn-relay-admin/vendor/relay_server.py
systemctl restart ldn-relay-admin
ready=0
for attempt in 1 2 3 4 5; do
    if curl --noproxy '*' -fsS --max-time 2 http://127.0.0.1:53242/healthz >/dev/null 2>&1; then
        ready=1
        break
    fi
    sleep 1
done
test "$ready" = 1
curl --noproxy '*' -fsS --max-time 10 https://115.190.159.134:53241/healthz
echo
status=$(curl --noproxy '*' -sS -o /dev/null -w '%{http_code}' --max-time 10 https://115.190.159.134:53241/api/status)
test "$status" = 401
trap - ERR
systemctl is-active ldn-relay-admin nginx
echo 'Unauthenticated status: 401'
echo 'Web connection limit: 32; trusted loopback proxy: enabled'
echo 'Please verify browser login, game names and Switch connectivity.'
