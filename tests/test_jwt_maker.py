#!/usr/bin/env python3
"""Offline tests for the standalone JWT maker (jwt_maker.py).

Everything runs against a stub Garena backend (tests/garena_stub.py): the full
OAuth-grant -> MajorLogin -> JWT-parse pipeline is exercised without touching
Garena's real servers.

Usage:
    python3 tests/test_jwt_maker.py
"""

import base64
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
sys.path.insert(0, HERE)

import garena_stub  # noqa: E402

CHECKS = []


def check(name, condition, detail=""):
    CHECKS.append((name, bool(condition)))
    print(f"{'PASS' if condition else 'FAIL'}  {name}"
          + (f"  -> {detail}" if detail and not condition else ""))


def claims_of(token):
    payload = token.split(".")[1]
    payload += "=" * (-len(payload) % 4)
    return json.loads(base64.urlsafe_b64decode(payload))


def fresh_maker(server, accounts=None):
    """(Re)import jwt_maker with the stub backend wired in via env vars."""
    os.environ["FF_OAUTH_URL"] = garena_stub.stub_url(server, "/oauth/guest/token/grant")
    os.environ["FF_INSPECT_URL"] = garena_stub.stub_url(server, "/oauth/token/inspect")
    os.environ["FF_LOGIN_URL"] = garena_stub.stub_url(server, "/MajorLogin")
    account_file = "/tmp/ff_maker_accounts.txt"
    with open(account_file, "w") as handle:
        for uid, password in (accounts or []):
            handle.write(f"{uid}:{password}\n")
    os.environ["FF_ACCOUNT_FILE"] = account_file
    for module in [m for m in list(sys.modules) if m == "jwt_maker"]:
        del sys.modules[module]
    import jwt_maker
    jwt_maker.app.config["TESTING"] = True
    return jwt_maker


def main():
    server = garena_stub.start_garena_stub()
    uid = "5618826963"
    try:
        # ---------------------------------------------------------------- 1
        # uid + password -> OAuth grant -> MajorLogin -> game JWT
        garena_stub.reset_state()
        maker = fresh_maker(server)
        client = maker.app.test_client()

        response = client.get(f"/token?uid={uid}&password=some-good-password")
        result = response.get_json()
        token = result.get("token", "")
        check("uid mint returns 200 and a JWT",
              response.status_code == 200 and token.startswith("eyJ"), json.dumps(result)[:200])
        claims = claims_of(token)
        check("minted JWT carries OB55 claims",
              claims.get("release_version") == "OB55" and claims.get("noti_region") == "BD",
              json.dumps(claims))
        check("result mirrors the account",
              result.get("region") == "BD" and result.get("uid") == uid
              and result.get("account_id") == str(10800000000 + int(uid)),
              json.dumps(result)[:250])

        decoded = garena_stub.STATE["last_login_fields"]
        check("GameData request carries uid/open_id/platform",
              decoded and decoded["user_id"] == uid
              and decoded["open_id"] == f"oid-{uid}"
              and decoded["platform_type"] == 4,
              json.dumps(decoded))
        header = garena_stub.STATE["major_headers"][-1]
        check("MajorLogin ships OB55 headers",
              header["release_version"] == "OB55"
              and header["x_ga_sv"] == maker.LOGIN_X_GA_SV
              and (header["authorization"] or "").startswith("Bearer")
              and header["x_ga"] == "v1 1"
              and header["x_unity_version"] == "2018.4.12f1",
              json.dumps(header))

        # ---------------------------------------------------------------- 2
        # Cache: a second identical mint must not hit Garena again.
        response = client.get(f"/token?uid={uid}&password=some-good-password")
        check("second mint is served from cache",
              response.get_json().get("token") == token
              and garena_stub.STATE["counts"]["oauth"] == 1
              and garena_stub.STATE["counts"]["major"] == 1,
              json.dumps(garena_stub.STATE["counts"]))

        # ---------------------------------------------------------------- 3
        # /api/get_jwt success + failure shapes
        response = client.get(f"/api/get_jwt?guest_uid={uid}&guest_password=some-good-password")
        check("get_jwt returns BearerAuth",
              response.status_code == 200
              and response.get_json().get("BearerAuth", "").startswith("eyJ"),
              json.dumps(response.get_json())[:200])
        response = client.get("/api/get_jwt?guest_uid=5618999999&guest_password=wrong-password")
        result = response.get_json()
        check("bad account gives get_jwt 500",
              response.status_code == 500 and result.get("success") is False
              and "oauth" in (result.get("detail") or ""),
              json.dumps(result)[:250])
        response = client.get("/api/get_jwt")
        check("get_jwt without params is a 400",
              response.status_code == 400 and response.get_json().get("success") is False)

        # ---------------------------------------------------------------- 4
        # access_token flow (platform resolved via token inspect)
        garena_stub.reset_state()
        response = client.get("/token?access_token=at-5618845326")
        result = response.get_json()
        check("access_token mint works via inspect",
              result.get("token", "").startswith("eyJ")
              and result.get("uid") == "5618845326"
              and garena_stub.STATE["counts"]["inspect"] == 1,
              json.dumps(result)[:200])
        response = client.get("/api/get_jwt?access_token=bogus-token")
        check("bad access_token gives get_jwt 400",
              response.status_code == 400 and response.get_json().get("success") is False)

        # ---------------------------------------------------------------- 5
        # Batch endpoint over the accounts file
        garena_stub.reset_state()
        maker = fresh_maker(server, accounts=[
            (uid, "some-good-password"),
            ("5618845326", "another-good-password"),
            ("5618999999", "wrong-password"),
        ])
        client = maker.app.test_client()
        response = client.get("/token")
        result = response.get_json()
        check("batch mint returns one JWT per good account",
              len(result.get("tokens", [])) == 2 and result.get("failed") == 1,
              json.dumps(result)[:200])

        # ---------------------------------------------------------------- 6
        # Health metadata
        response = client.get("/health")
        result = response.get_json()
        check("health reports login config",
              result.get("ok") is True and result.get("release_version") == "OB55"
              and "MajorLogin" in maker.MAJOR_LOGIN_URL,
              json.dumps(result)[:200])

        # ---------------------------------------------------------------- 7
        # Known MajorLogin error strings map to readable messages
        garena_stub.reset_state(major_status=400, major_body=b"BR_PLATFORM_INVALID_PLATFORM")
        maker = fresh_maker(server)
        client = maker.app.test_client()
        response = client.get(f"/token?uid={uid}&password=some-good-password")
        result = response.get_json()
        check("login error strings are translated",
              result.get("token") == "N/A"
              and "platform" in (result.get("error") or ""),
              json.dumps(result)[:250])
    finally:
        server.shutdown()
        server.server_close()
        for var in ("FF_OAUTH_URL", "FF_INSPECT_URL", "FF_LOGIN_URL", "FF_ACCOUNT_FILE"):
            os.environ.pop(var, None)

    failed = [name for name, ok in CHECKS if not ok]
    print()
    print(f"{len(CHECKS) - len(failed)}/{len(CHECKS)} checks passed")
    if failed:
        print("failed: " + ", ".join(failed))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
