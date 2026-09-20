#!/usr/bin/env python3
"""Standalone Free Fire guest-JWT maker (OB55-era login flow).

Given a guest account's ``uid:password`` pair this service mints the game JWT
that ``clientbp.*`` clusters expect in ``Authorization: Bearer`` — without
depending on third-party token providers (the ones this bot used to rely on
broke after the OB55 update).

Pipeline (mirrors the official mobile client):

  1. ``uid + password``  ──OAuth grant──▶  Garena ``access_token`` + ``open_id``
  2. access/open id + device fingerprint (GameData protobuf, AES-CBC)
                       ──MajorLogin────▶  loginbp cluster → signed game JWT
  3. schema-free protobuf scan of the (64-byte signature + protobuf) response

The protobuf request is hand-encoded (no .pb2 dependency, so it runs on any
runtime including Vercel's python3.8); the response is decoded with a generic
wire-format scanner. Field layout/values follow the OB55 public reference
implementations (Sept 2026).

Endpoints (drop-in compatible with the common jwt-generator services):

  GET /token?uid=<uid>&password=<password>
  GET /token?access_token=<garena_access_token>
  GET /token                      → batch over FF_ACCOUNT_FILE (uid:password lines)
  GET /api/get_jwt?guest_uid=<uid>&guest_password=<password>
  GET /api/get_jwt?access_token=<token>
  GET /health

Environment (all optional):
  FF_OAUTH_URL        guest OAuth grant endpoint
  FF_INSPECT_URL      access-token inspect endpoint
  FF_LOGIN_URL        MajorLogin endpoint     (default loginbp.ppmainecoonghj.com)
  FF_LOGIN_RELEASE   ReleaseVersion header    (default OB55)
  FF_LOGIN_X_GA_SV    X-Ga-Sv build stamp      (default 1789534056, client 1.132.2)
  FF_CLIENT_VERSION   version_code in GameData (default 1.132.2)
  FF_PLATFORM_TYPE    default platform_type    (default 4 = guest)
  FF_ACCOUNT_FILE     accounts file for batch minting (uid:password lines or json dict)
  FF_CACHE_SECONDS    success cache TTL        (default 21600 = 6h)
  FF_NEG_CACHE_SECONDS failure cache TTL       (default 60)
  FF_MINT_WORKERS     batch parallelism        (default 10)
  PORT                listen port for `python3 jwt_maker.py` (default 5030)
"""

import base64
import hashlib
import json
import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from flask import Flask, jsonify, request

# ----------------------------------------------------------------------------
# Configuration
# ----------------------------------------------------------------------------
OAUTH_URL = os.environ.get(
    "FF_OAUTH_URL", "https://ffmconnect.live.gop.garenanow.com/oauth/guest/token/grant"
)
INSPECT_URL = os.environ.get(
    "FF_INSPECT_URL", "https://100067.connect.garena.com/oauth/token/inspect"
)
MAJOR_LOGIN_URL = os.environ.get(
    "FF_LOGIN_URL", "https://loginbp.ppmainecoonghj.com/MajorLogin"
)
LOGIN_RELEASE_VERSION = os.environ.get("FF_LOGIN_RELEASE", "OB55")
LOGIN_X_GA_SV = os.environ.get("FF_LOGIN_X_GA_SV", "1789534056")
CLIENT_VERSION = os.environ.get("FF_CLIENT_VERSION", "1.132.2")
DEFAULT_PLATFORM_TYPE = int(os.environ.get("FF_PLATFORM_TYPE", "4"))
ACCOUNT_FILE = os.environ.get("FF_ACCOUNT_FILE", "account.bd.txt")
CACHE_SECONDS = int(os.environ.get("FF_CACHE_SECONDS", "21600"))
NEG_CACHE_SECONDS = int(os.environ.get("FF_NEG_CACHE_SECONDS", "60"))
MINT_WORKERS = int(os.environ.get("FF_MINT_WORKERS", "10"))
MINT_TIMEOUT = (4, 10)

AES_KEY = b'Yg&tc%DEuh6%Zc^8'
AES_IV = b'6oyZDr22E3ychjM%'

OAUTH_CLIENT_ID = "100067"
OAUTH_CLIENT_SECRET = "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3"
GARENA_UA = "GarenaMSDK/4.0.19P4 (Vivo Y15c; Android 12; en;IN;)"

app = Flask(__name__)


# ----------------------------------------------------------------------------
# Minimal protobuf wire-format encoder (for the GameData login request)
# ----------------------------------------------------------------------------
def _varint(value):
    out = bytearray()
    while True:
        bits = value & 0x7F
        value >>= 7
        if value:
            out.append(bits | 0x80)
        else:
            out.append(bits)
            break
    return bytes(out)


def _field_varint(field, value):
    return _varint((field << 3) | 0) + _varint(value)


def _field_bytes(field, data):
    return _varint((field << 3) | 2) + _varint(len(data)) + data


def _field_str(field, text):
    return _field_bytes(field, text.encode("utf-8"))


def build_game_data(open_id, access_token, uid, platform_type=DEFAULT_PLATFORM_TYPE):
    """Serialized GameData login payload. Field numbers and static values match
    the OB55 client request (reference-verified byte-for-byte against the
    community ``my.proto`` definition)."""
    p = str(platform_type)
    parts = [
        _field_str(3, "2025-05-29 13:11:47"),
        _field_str(4, "free fire"),
        _field_varint(5, 1),
        _field_str(7, CLIENT_VERSION),
        _field_str(8, "Android OS 11 / API-30 (RKQ1.201112.002/eng.realme.20221110.193122)"),
        _field_str(9, "Handheld"),
        _field_str(10, "JIO"),
        _field_str(11, "MOBILE"),
        _field_varint(12, 720),
        _field_varint(13, 1600),
        _field_str(15, "ARM Cortex-A73 | 2200 | 4"),
        _field_varint(16, 4096),
        _field_str(17, "Adreno (TM) 610"),
        _field_str(18, "OpenGL ES 3.2"),
        _field_str(19, str(uid)),
        _field_str(20, "182.75.115.22"),
        _field_str(21, "en"),
        _field_str(22, open_id),
        _field_varint(23, platform_type),
        _field_str(24, "Handheld"),
        _field_str(25, "realme RMX1825"),
        _field_str(26, "280"),
        _field_str(29, access_token),
        _field_varint(60, 30000),
        _field_varint(61, 27500),
        _field_varint(62, 1940),
        _field_varint(63, 720),
        _field_varint(64, 28000),
        _field_varint(65, 30000),
        _field_varint(66, 28000),
        _field_varint(67, 30000),
        _field_varint(70, 4),
        _field_varint(73, 2),
        _field_str(74, "/data/app/com.dts.freefireth-XaT5M7jRwEL-nPaKOQvqdg==/lib/arm"),
        _field_varint(76, 1),
        _field_str(77, "2f4a7f349f3a3ea581fc4d803bc5a977|/data/app/com.dts.freefireth-XaT5M7jRwEL-nPaKOQvqdg==/base.apk"),
        _field_varint(78, 6),
        _field_varint(79, 1),
        _field_str(81, "64"),
        _field_str(83, "2022041388"),
        _field_varint(85, 1),
        _field_str(86, "OpenGLES3"),
        _field_varint(87, 16383),
        _field_varint(88, 4),
        _field_bytes(89, b"\x10U\x15\x03\x02\t\rPYN\tEX\x03AZO9X\x07\rU\niZPVj\x05\rm\t\x04c"),
        _field_varint(92, 8999),
        _field_str(93, "3rd_party"),
        _field_str(94, "Jp2DT7F3Is55K/92LSJ4PWkJxZnMzSNn+HEBK2AFBDBdrLpWTA3bZjtbU3JbXigkIFFJ5ZJKi0fpnlJCPDD2A7h2aPQ="),
        _field_varint(95, 64000),
        _field_varint(97, 1),
        _field_varint(98, 1),
        _field_str(99, p),
        _field_bytes(100, p.encode()),
    ]
    return b"".join(parts)


# ----------------------------------------------------------------------------
# Generic protobuf wire-format scanner (for the MajorLogin response)
# ----------------------------------------------------------------------------
def _read_varint(buf, pos):
    result = 0
    shift = 0
    while True:
        if pos >= len(buf):
            raise ValueError("truncated varint")
        byte = buf[pos]
        pos += 1
        result |= (byte & 0x7F) << shift
        if not (byte & 0x80):
            break
        shift += 7
        if shift > 63:
            raise ValueError("varint too long")
    return result, pos


def parse_proto(buf, depth=0, max_depth=8):
    """Best-effort field map of a protobuf buffer with no .proto schema.

    Returns ``{field_number: [(kind, value), ...]}`` where kind is one of
    varint/string/message/bytes/fixed32/fixed64."""
    fields = {}
    pos = 0
    while pos < len(buf):
        try:
            tag, pos = _read_varint(buf, pos)
        except Exception:
            break
        field_num = tag >> 3
        wire_type = tag & 7
        if field_num == 0:
            break
        try:
            if wire_type == 0:
                value, pos = _read_varint(buf, pos)
                fields.setdefault(field_num, []).append(("varint", value))
            elif wire_type == 1:
                if pos + 8 > len(buf):
                    break
                fields.setdefault(field_num, []).append(
                    ("fixed64", int.from_bytes(buf[pos:pos + 8], "little")))
                pos += 8
            elif wire_type == 2:
                length, pos = _read_varint(buf, pos)
                if pos + length > len(buf):
                    break
                value = buf[pos:pos + length]
                pos += length
                as_str = None
                try:
                    text = value.decode("utf-8")
                    if text and all(c.isprintable() or c in "\r\n\t" for c in text):
                        as_str = text
                except Exception:
                    pass
                if as_str is not None:
                    fields.setdefault(field_num, []).append(("string", as_str))
                else:
                    nested = None
                    if 0 < len(value) and depth < max_depth:
                        try:
                            nested = parse_proto(value, depth + 1, max_depth) or None
                        except Exception:
                            nested = None
                    if nested is not None:
                        fields.setdefault(field_num, []).append(("message", nested))
                    else:
                        fields.setdefault(field_num, []).append(("bytes", value.hex()))
            elif wire_type == 5:
                if pos + 4 > len(buf):
                    break
                fields.setdefault(field_num, []).append(
                    ("fixed32", int.from_bytes(buf[pos:pos + 4], "little")))
                pos += 4
            else:
                break
        except Exception:
            break
    return fields


def _has_jwt(fields):
    return any(
        kind == "string" and value.startswith("eyJ")
        for values in fields.values() for kind, value in values
    )


def decode_major_login(raw):
    """Decode a MajorLogin response: ``[64-byte signature][protobuf body]``.

    The signature length has shifted between releases, so if the body at
    offset 64 has no JWT, scan nearby offsets for one."""
    if not raw:
        return None
    offset = 64 if len(raw) > 64 else 0
    fields = parse_proto(raw[offset:])
    if fields and _has_jwt(fields):
        return fields
    for off in range(0, min(128, len(raw))):
        fields = parse_proto(raw[off:])
        if fields and _has_jwt(fields):
            return fields
    return fields or None


def _fget(fields, number, kind=None):
    for k, value in fields.get(number, []):
        if kind is None or k == kind:
            return value
    return None


# ----------------------------------------------------------------------------
# JWT helpers (claims are read without verifying the signature)
# ----------------------------------------------------------------------------
def jwt_claims(token):
    try:
        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        return json.loads(base64.urlsafe_b64decode(payload).decode())
    except Exception:
        return {}


# ----------------------------------------------------------------------------
# Garena calls
# ----------------------------------------------------------------------------
def guest_oauth_grant(uid, password):
    """guest uid+password → Garena access_token/open_id. Returns (data, error)."""
    data = {
        "uid": uid,
        "password": password,
        "response_type": "token",
        "client_type": "2",
        "client_secret": OAUTH_CLIENT_SECRET,
        "client_id": OAUTH_CLIENT_ID,
    }
    headers = {
        "Host": "100067.connect.garena.com",
        "User-Agent": GARENA_UA,
        "Content-Type": "application/x-www-form-urlencoded",
    }
    try:
        response = requests.post(OAUTH_URL, headers=headers, data=data, timeout=MINT_TIMEOUT)
    except Exception as e:
        return None, f"oauth request failed: {type(e).__name__}: {str(e)[:140]}"
    if response.status_code != 200:
        return None, f"oauth HTTP {response.status_code}: {response.text[:160]}"
    try:
        payload = response.json()
    except ValueError:
        return None, f"oauth returned non-JSON: {response.text[:120]}"
    if not payload.get("access_token") or not payload.get("open_id"):
        return None, f"oauth response missing access_token or open_id: {json.dumps(payload)[:160]}"
    return payload, None


def inspect_access_token(access_token):
    """access_token → {open_id, platform, uid}. Returns (data, error)."""
    try:
        response = requests.get(
            INSPECT_URL,
            params={"token": access_token},
            headers={"User-Agent": GARENA_UA},
            timeout=MINT_TIMEOUT,
        )
    except Exception as e:
        return None, f"inspect request failed: {type(e).__name__}: {str(e)[:140]}"
    if response.status_code != 200:
        return None, f"inspect HTTP {response.status_code}: {response.text[:160]}"
    try:
        payload = response.json()
    except ValueError:
        return None, f"inspect returned non-JSON: {response.text[:120]}"
    missing = [k for k in ("open_id", "platform", "uid") if k not in payload]
    if missing:
        return None, f"inspect response missing {missing}: {json.dumps(payload)[:160]}"
    return payload, None


_LOGIN_ERROR_MESSAGES = {
    "BR_PLATFORM_INVALID_PLATFORM": "this account is registered on another platform",
    "BR_GOP_TOKEN_AUTH_FAILED": "AccessToken invalid.",
    "BR_PLATFORM_INVALID_OPENID": "OpenID invalid.",
}


def major_login(open_id, access_token, uid, platform_type):
    """Run MajorLogin and return (result_dict, error)."""
    game_data = build_game_data(open_id, access_token, uid, platform_type)
    try:
        body = AES.new(AES_KEY, AES.MODE_CBC, AES_IV).encrypt(pad(game_data, AES.block_size))
    except Exception as e:
        return None, f"login encryption failed: {type(e).__name__}: {str(e)[:120]}"

    headers = {
        "User-Agent": "UnityPlayer/2018.4.12f1 (UnityWebRequest/1.0, libcurl/8.5.0-DEV)",
        "Accept": "*/*",
        "Accept-Encoding": "deflate, gzip",
        "X-Ga-Sv": LOGIN_X_GA_SV,
        "Authorization": "Bearer ",
        "X-Ga": "v1 1",
        "ReleaseVersion": LOGIN_RELEASE_VERSION,
        "Content-Type": "application/x-www-form-urlencoded",
        "X-Unity-Version": "2018.4.12f1",
    }
    try:
        response = requests.post(MAJOR_LOGIN_URL, data=body, headers=headers, timeout=MINT_TIMEOUT)
    except Exception as e:
        return None, f"MajorLogin request failed: {type(e).__name__}: {str(e)[:140]}"
    if response.status_code != 200:
        text = response.text.strip()
        return None, _LOGIN_ERROR_MESSAGES.get(text, f"MajorLogin HTTP {response.status_code}: {text[:160]}")

    fields = decode_major_login(response.content)
    if not fields:
        return None, f"MajorLogin response not decodable ({len(response.content)} bytes)"
    token = _fget(fields, 8, "string")
    if not token or not token.startswith("eyJ"):
        return None, "MajorLogin response contains no JWT"

    return {
        "token": token,
        "account_id": _fget(fields, 1, "varint"),
        "region": _fget(fields, 2, "string") or _fget(fields, 3, "string"),
        "status": _fget(fields, 5, "string"),
        "server_url": _fget(fields, 10, "string") or "",
    }, None


# ----------------------------------------------------------------------------
# Minting + cache
# ----------------------------------------------------------------------------
_cache_lock = threading.Lock()
_cache = {}


def _cache_key(kind, value):
    return f"{kind}:{hashlib.sha256(str(value).encode()).hexdigest()[:16]}"


def _cache_get(key):
    with _cache_lock:
        entry = _cache.get(key)
        if entry and entry[0] > time.time():
            return entry[1]
        if entry:
            del _cache[key]
    return None


def _cache_put(key, result):
    claims = jwt_claims(result.get("token", ""))
    jwt_ttl = claims.get("exp", 0) - time.time() - 300
    ttl = max(60, min(CACHE_SECONDS, jwt_ttl)) if jwt_ttl > 60 else CACHE_SECONDS
    with _cache_lock:
        _cache[key] = (time.time() + ttl, result)


def _result(uid, login, access_token, error=None):
    result = {
        "region": (login or {}).get("region") or "N/A",
        "status": (login or {}).get("status") or "N/A",
        "team": "STAR_GMRR",
        "token": (login or {}).get("token") or "N/A",
        "token_access": access_token or "N/A",
        "uid": str(uid) if uid is not None else "N/A",
        "account_id": str((login or {}).get("account_id") or "N/A"),
        "ServerUrl": (login or {}).get("server_url", ""),
    }
    if error:
        result["error"] = error
    return result


def mint_token(uid, password):
    """uid+password → result dict (``.token`` is the game JWT or 'N/A')."""
    key = _cache_key("up", f"{uid}:{password}")
    cached = _cache_get(key)
    if cached:
        return cached

    oauth, error = guest_oauth_grant(uid, password)
    if error:
        result = _result(uid, None, None, error)
        with _cache_lock:
            _cache[key] = (time.time() + NEG_CACHE_SECONDS, result)
        return result

    login, error = major_login(
        oauth["open_id"], oauth["access_token"], uid, DEFAULT_PLATFORM_TYPE
    )
    result = _result(uid, login, oauth["access_token"], error)
    if not error:
        _cache_put(key, result)
    return result


def mint_from_access_token(access_token, uid=None):
    """Garena access_token → result dict (platform resolved via inspect)."""
    key = _cache_key("at", access_token)
    cached = _cache_get(key)
    if cached:
        return cached

    inspect, error = inspect_access_token(access_token)
    if error:
        return _result(uid, None, access_token, f"INVALID_TOKEN: {error}")

    uid = uid or str(inspect["uid"])
    platform_type = inspect.get("platform", DEFAULT_PLATFORM_TYPE)
    login, error = major_login(inspect["open_id"], access_token, uid, platform_type)
    result = _result(uid, login, access_token, error)
    if not error:
        _cache_put(key, result)
    return result


# ----------------------------------------------------------------------------
# Accounts file (uid:password lines, or a JSON {uid: password} map)
# ----------------------------------------------------------------------------
def load_accounts(path=None):
    path = path or ACCOUNT_FILE
    try:
        with open(path, "r", encoding="utf-8") as handle:
            text = handle.read().strip()
    except OSError:
        return []
    if not text:
        return []
    if text.startswith("{"):
        try:
            return [(str(u), str(p)) for u, p in json.loads(text).items()]
        except ValueError:
            return []
    pairs = []
    for line in text.splitlines():
        line = line.strip()
        if line and not line.startswith("#") and ":" in line:
            uid, password = line.split(":", 1)
            pairs.append((uid.strip(), password.strip()))
    return pairs


# ----------------------------------------------------------------------------
# HTTP API (drop-in compatible with common jwt-generator services)
# ----------------------------------------------------------------------------
@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "ok": True,
        "login_url": MAJOR_LOGIN_URL,
        "release_version": LOGIN_RELEASE_VERSION,
        "client_version": CLIENT_VERSION,
    })


@app.route("/token", methods=["GET"])
def token_endpoint():
    access_token = request.args.get("access_token")
    if access_token:
        return jsonify(mint_from_access_token(access_token))

    uid = request.args.get("uid")
    password = request.args.get("password")
    if uid and password:
        return jsonify(mint_token(uid, password))

    limit = max(1, min(request.args.get("limit", default=500, type=int) or 500, 2000))
    accounts = load_accounts()[:limit]
    if not accounts:
        return jsonify({"tokens": [], "failed": 0,
                        "error": f"no accounts in {os.path.basename(ACCOUNT_FILE)}"})

    good, failed = [], 0
    with ThreadPoolExecutor(max_workers=MINT_WORKERS) as pool:
        futures = {pool.submit(mint_token, u, p): u for u, p in accounts}
        for future in as_completed(futures):
            try:
                result = future.result()
            except Exception as e:
                failed += 1
                app.logger.error("mint failed for %s: %s", futures[future], e)
                continue
            if result.get("token", "N/A") != "N/A":
                good.append(result["token"])
            else:
                failed += 1
    return jsonify({"tokens": good, "failed": failed})


@app.route("/api/get_jwt", methods=["GET"])
def get_jwt():
    access_token = request.args.get("access_token")
    guest_uid = request.args.get("guest_uid")
    guest_password = request.args.get("guest_password")

    if access_token:
        result = mint_from_access_token(access_token)
        if result.get("token", "N/A") != "N/A":
            return jsonify({"success": True, "BearerAuth": result["token"]})
        return jsonify({"success": False,
                        "message": result.get("error", "INVALID_TOKEN")}), 400

    if guest_uid and guest_password:
        result = mint_token(guest_uid, guest_password)
        if result.get("token", "N/A") != "N/A":
            return jsonify({"success": True, "BearerAuth": result["token"]})
        return jsonify({
            "success": False,
            "message": "unregistered or banned account.",
            "detail": result.get("error", "jwt not found in response."),
        }), 500

    return jsonify({
        "success": False,
        "message": "missing access_token (or guest_uid + guest_password)",
    }), 400


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "5030")))
