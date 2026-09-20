#!/usr/bin/env python3
"""Offline end-to-end tests for the /like flow.

Runs the real Flask app against two stub upstreams on localhost:

  * a stub "guest JWT provider"  (replaces guest-jwt.vercel.app)
  * a stub "game cluster"        (replaces clientbp.<cluster>.com)

So every code path that used to be invisible in production - cluster failover,
release-version drift, token rejection, protobuf decoding - can be exercised
without touching Garena.

Usage:
    python3 tests/test_offline.py
"""

import json
import os
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

import jwt  # noqa: E402
from Crypto.Cipher import AES  # noqa: E402
from Crypto.Util.Padding import unpad  # noqa: E402

import like_pb2  # noqa: E402
import like_count_pb2  # noqa: E402

AES_KEY = b'Yg&tc%DEuh6%Zc^8'
AES_IV = b'6oyZDr22E3ychjM%'
TEST_UID = "123456789"
TEST_ACCOUNTS = [("5618826963", "password-one"), ("5618845326", "password-two")]

# Shared state for the stubs, mutated by the tests.
STATE = {
    "release_version": "OB55",     # version the provider puts in its JWTs
    "required_release": "OB55",    # version the game cluster accepts
    "cluster_status": None,        # force a status code on the game cluster
    "likes": 4242,
    "cluster_requests": [],
}


def make_jwt(account_uid, release_version):
    now = int(time.time())
    return jwt.encode(
        {
            "account_id": int(account_uid),
            "noti_region": "BD",
            "lock_region": "BD",
            "release_version": release_version,
            "client_version": "1.132.3",
            "exp": now + 3600,
        },
        "stub-secret",
        algorithm="HS256",
    )


class StubProvider(BaseHTTPRequestHandler):
    """Stands in for the guest-JWT provider."""

    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def do_GET(self):
        from urllib.parse import urlparse, parse_qs

        query = parse_qs(urlparse(self.path).query)
        uid = (query.get("uid") or [""])[0]
        password = (query.get("password") or [""])[0]
        if not uid or not password:
            payload = {"message": "Missing uid or password"}
            status = 400
        elif password == "wrong-password":
            payload = {"status": "error", "message": "invalid password"}
            status = 200
        else:
            token = make_jwt(uid, STATE["release_version"])
            payload = {
                "status": "success",
                "token": token,
                "account_id": uid,
                "region": "BD",
                "access_token": "stub-access-token",
                "open_id": "stub-open-id",
                "account_name": f"guest-{uid[-3:]}",
            }
            status = 200
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class StubCluster(BaseHTTPRequestHandler):
    """Stands in for a Garena client cluster."""

    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def _send(self, status, body=b"", content_type="application/x-www-form-urlencoded"):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body:
            self.wfile.write(body)

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length)
        auth = self.headers.get("Authorization", "")
        record = {
            "path": self.path,
            "release_version": self.headers.get("ReleaseVersion"),
            "x_ga_sv": self.headers.get("X-GA-SV"),
            "token": auth.replace("Bearer ", ""),
            "bytes": len(body),
        }
        STATE["cluster_requests"].append(record)

        if STATE["cluster_status"] is not None:
            return self._send(STATE["cluster_status"], b"stub forced failure")

        claims = {}
        try:
            claims = jwt.decode(auth.replace("Bearer ", ""), options={"verify_signature": False})
        except Exception:
            pass

        # Reject tokens minted for a different game release, exactly like the
        # live cluster does after a patch.
        if claims.get("release_version") != STATE["required_release"]:
            return self._send(403, b"<html>token release version rejected</html>")

        if self.path.endswith("/GetPlayerPersonalShow"):
            info = like_count_pb2.Info()
            info.AccountInfo.UID = int(TEST_UID)
            info.AccountInfo.PlayerNickname = "StubPlayer"
            info.AccountInfo.Likes = STATE["likes"]
            return self._send(200, info.SerializeToString())

        if self.path.endswith("/LikeProfile"):
            cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
            plaintext = unpad(cipher.decrypt(body), AES.block_size)
            message = like_pb2.like()
            message.ParseFromString(plaintext)
            if message.uid != int(TEST_UID):
                return self._send(400, b"wrong uid")
            if message.region not in ("BD", "IND", "US", "BR", "SAC", "NA"):
                return self._send(400, b"wrong region")
            STATE["likes"] += 1
            return self._send(200)

        return self._send(404, b"unknown path")


class StubServer:
    def __init__(self, handler):
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    @property
    def url(self):
        return f"http://127.0.0.1:{self.server.server_address[1]}"

    def stop(self):
        self.server.shutdown()
        self.server.server_close()


def start_app(cluster_hosts, accounts=None):
    """(Re)import app.py with the stub upstreams wired in via env vars."""
    accounts = accounts or TEST_ACCOUNTS
    account_file = "/tmp/ff_test_accounts.txt"
    with open(account_file, "w") as f:
        for uid, password in accounts:
            f.write(f"{uid}:{password}\n")
    os.environ["FF_ACCOUNT_FILE"] = account_file
    os.environ["FF_TOKEN_FILE"] = "/tmp/ff_test_tokens.json"
    os.environ["FF_CLIENT_HOSTS"] = ",".join(cluster_hosts)
    os.environ["FF_PLAYER_INFO_BUDGET"] = "20"
    for module in [m for m in list(sys.modules) if m == "app"]:
        del sys.modules[module]
    if os.path.exists("/tmp/ff_test_tokens.json"):
        os.remove("/tmp/ff_test_tokens.json")
    import app as app_module
    app_module.app.config["TESTING"] = True
    app_module.PREFERRED_HOST["host"] = None
    return app_module


CHECKS = []


def check(name, condition, detail=""):
    CHECKS.append((name, bool(condition), detail))
    print(f"{'PASS' if condition else 'FAIL'}  {name}" + (f"  -> {detail}" if detail and not condition else ""))


def main():
    provider = StubProvider
    provider_server = StubServer(provider)
    cluster = StubServer(StubCluster)
    os.environ["FF_TOKEN_URL"] = f"{provider_server.url}/token"

    try:
        # ---------------------------------------------------------------- 1
        # Happy path, with a dead first cluster to prove failover works.
        STATE.update({"release_version": "OB55", "required_release": "OB55",
                      "cluster_status": None, "likes": 4242, "cluster_requests": []})
        app_module = start_app(["http://127.0.0.1:9", cluster.url])
        client = app_module.app.test_client()

        response = client.get(f"/like?uid={TEST_UID}")
        payload = response.get_json()
        check("happy path returns 200", response.status_code == 200, json.dumps(payload)[:300])
        check("one like per token is counted",
              payload.get("LikesGivenByAPI") == len(TEST_ACCOUNTS), json.dumps(payload)[:300])
        check("both tokens were used", payload.get("successful_requests") == len(TEST_ACCOUNTS),
              str(payload.get("like_diagnostics")))
        check("player info read back", payload.get("PlayerNickname") == "StubPlayer")
        check("failover recorded on the dead host",
              any(r["path"] == "/GetPlayerPersonalShow" for r in STATE["cluster_requests"]))
        headers_seen = {r["release_version"] for r in STATE["cluster_requests"]}
        check("ReleaseVersion header sent", headers_seen == {"OB55"}, str(headers_seen))
        check("X-GA-SV header sent",
              all(r["x_ga_sv"] for r in STATE["cluster_requests"]))

        # ---------------------------------------------------------------- 2
        # Stale provider: JWTs are minted for the previous release, the cluster
        # rejects them. The API must say so instead of "all tokens rejected".
        STATE.update({"release_version": "OB54", "required_release": "OB55",
                      "cluster_requests": []})
        app_module = start_app(["http://127.0.0.1:9", cluster.url])
        client = app_module.app.test_client()

        response = client.get(f"/like?uid={TEST_UID}")
        payload = response.get_json()
        check("stale tokens give 502", response.status_code == 502, str(response.status_code))
        check("stale tokens report the version mismatch",
              payload.get("reason") == "tokens_rejected" and "OB54" in (payload.get("hint") or ""),
              json.dumps(payload)[:300])
        check("stale tokens expose upstream status",
              any(d.get("status") == 403 for attempt in payload.get("upstream", [])
                  for d in attempt.get("diagnostics", [])),
              json.dumps(payload)[:400])

        # ---------------------------------------------------------------- 3
        # Provider is down: the error must point at the provider, not the game.
        STATE.update({"release_version": "OB55", "required_release": "OB55"})
        app_module = start_app(["http://127.0.0.1:9", cluster.url],
                               accounts=[("5618826963", "wrong-password")])
        client = app_module.app.test_client()
        response = client.get(f"/like?uid={TEST_UID}")
        payload = response.get_json()
        check("provider rejection gives 503", response.status_code == 503, str(response.status_code))
        check("provider rejection is explained",
              "provider" in json.dumps(payload).lower() or "token" in json.dumps(payload).lower(),
              json.dumps(payload)[:300])

        # ---------------------------------------------------------------- 4
        # /diagnose explains each hop.
        STATE.update({"release_version": "OB55", "required_release": "OB55",
                      "cluster_requests": []})
        app_module = start_app(["http://127.0.0.1:9", cluster.url])
        client = app_module.app.test_client()
        response = client.get("/diagnose")
        report = response.get_json()
        check("diagnose returns 200", response.status_code == 200, str(response.status_code))
        check("diagnose checks the provider",
              report["provider"]["checked"] == len(TEST_ACCOUNTS) and report["provider"]["ok"] == len(TEST_ACCOUNTS),
              json.dumps(report["provider"])[:300])
        check("diagnose probes the clusters",
              any(entry.get("ok") for entry in report["clusters"]), json.dumps(report["clusters"])[:300])
        check("diagnose never leaks a token",
              all("token" not in entry for entry in report["clusters"])
              and all(entry.get("token", "").endswith("...") or "token" not in entry
                      for entry in report["provider"]["samples"]),
              json.dumps(report)[:300])

        # ---------------------------------------------------------------- 5
        # Token cache: /token_status reports the release version in use.
        response = client.get("/token_status")
        status = response.get_json()
        check("token_status reports release version",
              status.get("release_versions") == ["OB55"] and status.get("count") == len(TEST_ACCOUNTS),
              json.dumps(status)[:300])
    finally:
        provider_server.stop()
        cluster.stop()

    failed = [name for name, ok, _ in CHECKS if not ok]
    print()
    print(f"{len(CHECKS) - len(failed)}/{len(CHECKS)} checks passed")
    if failed:
        print("failed: " + ", ".join(failed))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
