#!/usr/bin/env python3
"""Stand-in for Entra's device-code and token endpoints, for the unit tests.

The first token poll for a device code answers authorization_pending, the
second returns an ID token. Device codes ending in "-declined" are refused,
"-broken" always get an HTML error page, and "-flaky" get one HTML error
before behaving normally.
"""

import base64
import json
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs

PORT = 8042
TENANT = "11111111-2222-3333-4444-555555555555"
CLIENT = "66666666-7777-8888-9999-000000000000"
OID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
# Characters that must be URL-escaped on the way back.
DEVICE_CODE = "abc+def/ghi="
# Tenants whose device-code endpoint misbehaves.
HUGE_TENANT = "99999999-0000-0000-0000-000000000001"
SLOW_TENANT = "99999999-0000-0000-0000-000000000002"
# A tenant whose sign-ins never complete.
PENDING_TENANT = "99999999-0000-0000-0000-000000000003"

polls = {}


def b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def id_token():
    now = int(time.time())
    claims = {
        "iss": "http://localhost:{}/{}/v2.0".format(PORT, TENANT),
        "tid": TENANT,
        "aud": CLIENT,
        "exp": now + 3600,
        "auth_time": now,
        "amr": ["fido", "mfa"],
        "oid": OID,
    }
    header = b64url(json.dumps({"alg": "none"}).encode())
    return header + "." + b64url(json.dumps(claims).encode()) + ".sig"


class Handler(BaseHTTPRequestHandler):
    def reply(self, status, data):
        self.send_response(status)
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())

    def send_html_error(self):
        self.send_response(502)
        self.end_headers()
        self.wfile.write(b"<html>Bad gateway</html>")

    def do_POST(self):
        length = int(self.headers["Content-Length"])
        form = {k: v[0] for k, v in parse_qs(self.rfile.read(length).decode()).items()}
        if "Authorization" in self.headers:
            return self.reply(400, {"error": "invalid_client"})
        if form.get("client_id") != CLIENT:
            return self.reply(400, {"error": "unauthorized_client"})

        if self.path == "/{}/oauth2/v2.0/devicecode".format(HUGE_TENANT):
            return self.reply(200, {"padding": "x" * 100000})
        if self.path == "/{}/oauth2/v2.0/devicecode".format(SLOW_TENANT):
            return self.reply(200, {
                "device_code": DEVICE_CODE,
                "user_code": "QWERTY",
                "verification_uri": "https://login.microsoft.com/device",
                "expires_in": 900,
                "interval": 999,
            })

        if self.path == "/{}/oauth2/v2.0/devicecode".format(PENDING_TENANT):
            return self.reply(200, {
                "device_code": "never-pending",
                "user_code": "WAITING",
                "verification_uri": "https://login.microsoft.com/device",
                "expires_in": 900,
                "interval": 1,
            })
        if self.path == "/{}/oauth2/v2.0/token".format(PENDING_TENANT):
            return self.reply(400, {"error": "authorization_pending"})

        if self.path == "/{}/oauth2/v2.0/devicecode".format(TENANT):
            if (form.get("scope") != "openid profile"
                    or form.get("prompt") != "login"
                    or form.get("max_age") != "0"):
                return self.reply(400, {"error": "invalid_request"})
            return self.reply(200, {
                "device_code": DEVICE_CODE,
                "user_code": "QWERTY\x1b[2J",
                "verification_uri": "https://login.microsoft.com/device",
                "expires_in": 900,
                "interval": 1,
            })

        if self.path == "/{}/oauth2/v2.0/token".format(TENANT):
            code = form.get("device_code", "")
            if code.endswith("-declined"):
                return self.reply(400, {"error": "authorization_declined"})
            if code.endswith("-broken"):
                return self.send_html_error()
            if code.endswith("-flaky"):
                polls[code] = polls.get(code, 0) + 1
                if polls[code] % 3 == 1:
                    return self.send_html_error()
                if polls[code] % 3 == 2:
                    return self.reply(400, {"error": "authorization_pending"})
                return self.reply(200, {"id_token": id_token(), "token_type": "Bearer"})
            if code != DEVICE_CODE:
                return self.reply(400, {"error": "invalid_grant"})
            polls[code] = polls.get(code, 0) + 1
            if polls[code] % 2:
                return self.reply(400, {"error": "authorization_pending"})
            return self.reply(200, {"id_token": id_token(), "token_type": "Bearer"})

        self.reply(404, {"error": "not_found"})

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    HTTPServer(("localhost", PORT), Handler).serve_forever()
