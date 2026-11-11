#!/bin/bash
# End-to-end test in real sudo: installs a mock-authority build of the module
# into /etc/pam.d/sudo, then runs sudo as an unprivileged user whose
# environment tries to make the module write an SSLKEYLOGFILE as root and use
# a proxy. Run as root in a disposable container; it changes the system.
#
#   test/sudo_integration.sh [sudo binary] [extra sudo flags]
set -euo pipefail

SUDO=${1:-/usr/bin/sudo}
FLAGS=${2:-}
SRC=$(cd "$(dirname "$0")/.." && pwd)
WORK=$(mktemp -d)

cp -r "$SRC/src" "$SRC/Makefile" "$WORK/"
# A package build may have left objects for the real authority in src/.
make -s -C "$WORK" clean
make -s -C "$WORK" CPPFLAGS='-DENTRA_AUTHORITY=\"http://localhost:8042\"'
make -s -C "$WORK" install

cat > /etc/pam_entra_sudo.json <<'JSON'
{
  "tenant_id": "11111111-2222-3333-4444-555555555555",
  "client_id": "66666666-7777-8888-9999-000000000000",
  "max_auth_age": 120,
  "required_amr": ["fido"],
  "users": { "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee": ["alice"] }
}
JSON
chmod 0600 /etc/pam_entra_sudo.json
cat > /etc/pam.d/sudo <<'PAM'
auth     [success=done abort=die default=ignore] pam_entra_sudo.so /etc/pam_entra_sudo.json
auth     requisite  pam_deny.so
@include common-account
@include common-session-noninteractive
PAM
id alice >/dev/null 2>&1 || useradd -m -G sudo alice

python3 "$SRC/test/mock_server.py" >/dev/null 2>&1 &
MOCK=$!
trap 'kill $MOCK 2>/dev/null || true' EXIT
sleep 1

TRAP=$(mktemp -d)
chmod 0777 "$TRAP"
OUT=$(su alice -c "umask 000; cd /tmp; \
  SSLKEYLOGFILE=$TRAP/keylog http_proxy=http://127.0.0.1:9 \
  https_proxy=http://127.0.0.1:9 ALL_PROXY=http://127.0.0.1:9 \
  OPENSSL_CONF=$TRAP/openssl.cnf \
  script -qec '$SUDO $FLAGS id -u' /dev/null" 2>&1 || true)

echo "$OUT"
status=0
# The terminal echoes a stray NUL as the two characters "^@".
if ! tr -d '\r' <<<"$OUT" | sed 's/\^@//g' | grep -qx 0; then
  echo "FAIL: sudo did not succeed through the mock (proxy honoured?)"
  status=1
fi
if [ -e "$TRAP/keylog" ]; then
  echo "FAIL: $TRAP/keylog was created: $(stat -c '%U %a' "$TRAP/keylog")"
  status=1
fi
# Ctrl-C while waiting for a sign-in that never comes must end sudo within
# seconds, not after the 5-minute sign-in timeout.
sed -i 's/11111111-2222-3333-4444-555555555555/99999999-0000-0000-0000-000000000003/' \
  /etc/pam_entra_sudo.json
su alice -c "cd /tmp; script -qec '$SUDO $FLAGS true' /dev/null" >/dev/null 2>&1 &
for _ in $(seq 50); do pgrep -u alice -x script >/dev/null && sleep 3 && break; sleep 0.1; done
start=$(date +%s)
pkill -INT -f "^$SUDO $FLAGS *true" || pkill -INT -x sudo || true
for _ in $(seq 100); do pgrep -f "$SUDO $FLAGS *true" >/dev/null || break; sleep 0.1; done
if pgrep -f "$SUDO $FLAGS *true" >/dev/null; then
  echo "FAIL: sudo still waiting 10 s after SIGINT"
  pkill -KILL -f "$SUDO $FLAGS *true" || true
  status=1
else
  echo "Ctrl-C ended sudo after $(( $(date +%s) - start )) s"
fi

[ $status -eq 0 ] && echo "PASS: $SUDO $FLAGS"
exit $status
