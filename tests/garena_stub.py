"""Stub Garena backend for offline tests (OAuth, inspect, MajorLogin)."""

import threading
import time
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

import jwt as pyjwt
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

import jwt_maker  # AES constants, wire encoders and the schema-free parser

STATE = {
    "release_version": "OB55",
    "region": "BD",
    "bad_passwords": {"wrong-password"},
    "major_status": None,      # force an HTTP status on MajorLogin
    "major_body": b"",
    "counts": {"oauth": 0, "inspect": 0, "major": 0},
    "major_headers": [],       # every MajorLogin request's header snapshot
    "last_login_fields": None, # fields decoded from the last GameData request
}


def reset_state(**overrides):
    STATE.update({
        "release_version": "OB55",
        "region": "BD",
        "bad_passwords": {"wrong-password"},
        "major_status": None,
        "major_body": b"",
        "counts": {"oauth": 0, "inspect": 0, "major": 0},
        "major_headers": [],
        "last_login_fields": None,
    })
    STATE.update(overrides)


def make_game_jwt(uid, release_version=None, region=None):
    """A game JWT shaped like the real thing (HS256, test secret)."""
    now = int(time.time())
    return pyjwt.encode(
        {
            "account_id": 10800000000 + int(uid),
            "noti_region": region or STATE["region"],
            "lock_region": region or STATE["region"],
            "release_version": release_version or STATE["release_version"],
            "client_version": "1.132.2",
            "iat": now,
            "exp": now + 25200,
        },
        "stub-secret",
        algorithm="HS256",
    )


def _fget(fields, number, kind=None):
    for k, value in fields.get(number, []):
        if kind is None or k == kind:
            return value
    return None


class GarenaHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def _reply(self, status, payload=None, raw=None):
        body = raw if raw is not None else json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path.endswith("/oauth/token/inspect"):
            STATE["counts"]["inspect"] += 1
            token = (parse_qs(parsed.query).get("token") or [""])[0]
            if token.startswith("at-"):
                uid = token[3:]
                return self._reply(200, {"open_id": f"oid-{uid}", "platform": 4,
                                         "uid": int(uid)})
            return self._reply(400, {"error": "invalid_token"})
        return self._reply(404, {"error": "unknown path"})

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length)

        if self.path.endswith("/oauth/guest/token/grant"):
            STATE["counts"]["oauth"] += 1
            form = parse_qs(body.decode())
            uid = (form.get("uid") or [""])[0]
            password = (form.get("password") or [""])[0]
            if password in STATE["bad_passwords"] or not uid:
                return self._reply(400, {"error": "access_denied",
                                         "error_description": "invalid uid/password"})
            return self._reply(200, {"access_token": f"at-{uid}",
                                     "open_id": f"oid-{uid}"})

        if self.path.endswith("/MajorLogin"):
            STATE["counts"]["major"] += 1
            STATE["major_headers"].append({
                "release_version": self.headers.get("ReleaseVersion"),
                "x_ga_sv": self.headers.get("X-Ga-Sv"),
                "authorization": self.headers.get("Authorization"),
                "x_ga": self.headers.get("X-Ga"),
                "user_agent": self.headers.get("User-Agent"),
                "x_unity_version": self.headers.get("X-Unity-Version"),
            })
            if STATE["major_status"] is not None:
                return self._reply(STATE["major_status"], raw=STATE["major_body"])

            # The request body must be the AES-encrypted GameData payload.
            try:
                plaintext = unpad(AES.new(jwt_maker.AES_KEY, AES.MODE_CBC,
                                          jwt_maker.AES_IV).decrypt(body),
                                  AES.block_size)
                fields = jwt_maker.parse_proto(plaintext)
            except Exception as e:
                return self._reply(400, raw=f"BR_BAD_PAYLOAD: {e}".encode())

            user_id = _fget(fields, 19, "string")
            if not user_id:
                return self._reply(400, raw=b"BR_PLATFORM_INVALID_OPENID")
            STATE["last_login_fields"] = {
                "user_id": user_id,
                "open_id": _fget(fields, 22, "string"),
                "access_token": _fget(fields, 29, "string"),
                "platform_type": _fget(fields, 23, "varint"),
                "version_code": _fget(fields, 7, "string"),
            }
            proto = b"".join([
                jwt_maker._field_varint(1, 10800000000 + int(user_id)),
                jwt_maker._field_str(2, STATE["region"]),
                jwt_maker._field_str(5, "live"),
                jwt_maker._field_str(8, make_game_jwt(user_id)),
                jwt_maker._field_str(10, ""),
            ])
            return self._reply(200, raw=b"\x00" * 64 + proto)

        return self._reply(404, {"error": "unknown path"})


def start_garena_stub():
    server = ThreadingHTTPServer(("127.0.0.1", 0), GarenaHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


def stub_url(server, path=""):
    return f"http://127.0.0.1:{server.server_address[1]}{path}"
