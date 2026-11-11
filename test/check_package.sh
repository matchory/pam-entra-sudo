#!/bin/bash
# Checks a built pam-entra-sudo .deb: the production authority is compiled in
# (not a test one), the module exports only the PAM entry points and does not
# link libcurl, nothing is setuid, and both binaries are fully hardened.
#
#   test/check_package.sh pam-entra-sudo_X_amd64.deb
set -euo pipefail

DEB=$1
ROOT=$(mktemp -d)
trap 'rm -rf "$ROOT"' EXIT
dpkg-deb -x "$DEB" "$ROOT"

MODULE=$(find "$ROOT" -name pam_entra_sudo.so)
HELPER="$ROOT/usr/libexec/pam-entra-sudo/fetch"
fail() { echo "FAIL: $*"; exit 1; }

[ -f "$MODULE" ] || fail "no pam_entra_sudo.so in $DEB"
[ -x "$HELPER" ] || fail "no executable helper in $DEB"

grep -aq 'https://login.microsoftonline.com' "$HELPER" ||
  fail "helper lacks the Entra authority"
if grep -aqE 'localhost|127\.0\.0\.1' "$HELPER" "$MODULE"; then
  fail "a test authority is compiled in"
fi

exports=$(nm -D --defined-only "$MODULE" | awk '$2 == "T" {print $3}' | sort | tr '\n' ' ')
[ "$exports" = "pam_sm_authenticate pam_sm_setcred " ] ||
  fail "module exports more than the PAM entry points: $exports"
if readelf -d "$MODULE" | grep -q 'libcurl'; then
  fail "module links libcurl; HTTP belongs in the helper"
fi

if [ -n "$(find "$ROOT" -perm /6000)" ]; then
  fail "setuid or setgid files: $(find "$ROOT" -perm /6000)"
fi

for binary in "$MODULE" "$HELPER"; do
  readelf -d "$binary" | grep -q 'BIND_NOW\|FLAGS.*NOW' || fail "$binary lacks BIND_NOW"
  readelf -lW "$binary" | grep -q GNU_RELRO || fail "$binary lacks RELRO"
done

echo "PASS: $(basename "$DEB")"
