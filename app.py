from flask import Flask, request, jsonify
import asyncio
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from google.protobuf.json_format import MessageToJson
import binascii
import aiohttp
import requests
import json
import like_pb2
import like_count_pb2
import uid_generator_pb2
from google.protobuf.message import DecodeError
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
import time
import os
from datetime import datetime
import jwt
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)

# ---------------------------------------------------------------------------
# Configuration
#
# Garena rotates its client clusters, the client build stamp and the OB
# release version with every patch (see the "Free Fire Latest Update Config"
# style configs that the OB55 update shipped: release OB55 / client 1.132.3
# and the global cluster moving from clientbp.ggpolarbear.com to
# clientbp.ppmainecoonghj.com).
#
# Everything below can be overridden with environment variables so the next
# patch can be absorbed without editing code:
#
#   FF_RELEASE_VERSION  OB55              current OB release
#   FF_X_GA_SV          1789638359        client build stamp header (X-GA-SV)
#   FF_REGION           BD                default account region
#   FF_CLIENT_HOSTS     comma separated   global cluster list (first = preferred)
#   FF_TOKEN_URL        ...               guest JWT provider endpoint
#   FF_TOKEN_FILE       token_bd.json     where minted tokens are cached
# ---------------------------------------------------------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))


def _env_list(name, default):
    raw = os.environ.get(name, "")
    items = [item.strip() for item in raw.split(",") if item.strip()]
    return items or list(default)


CURRENT_RELEASE_VERSION = os.environ.get("FF_RELEASE_VERSION", "OB55")
X_GA_SV = os.environ.get("FF_X_GA_SV", "1789638359")
DEFAULT_REGION = os.environ.get("FF_REGION", "BD")
TOKEN_URL = os.environ.get("FF_TOKEN_URL", "https://guest-jwt.vercel.app/token")

# Oldest first is a mistake here: the first entry is the one the majority of
# requests use, the rest are failover targets.
GLOBAL_CLUSTER_HOSTS = _env_list(
    "FF_CLIENT_HOSTS",
    (
        "clientbp.ppmainecoonghj.com",      # current global cluster (OB55)
        "clientbp.ggpolarbear.com",         # previous global cluster
        "clientbp.common.ggbluefox.com",
        "clientbp.ggbluefox.com",
    ),
)

# Region specific clusters. Anything not listed here falls back to the global
# list above.
REGION_CLUSTER_HOSTS = {
    "IND": ("client.ind.freefiremobile.com",),
    "US": ("client.us.freefiremobile.com",),
    "BR": ("client.us.freefiremobile.com",),
    "SAC": ("client.us.freefiremobile.com",),
    "NA": ("client.us.freefiremobile.com",),
}

INFO_PATH = "/GetPlayerPersonalShow"
LIKE_PATH = "/LikeProfile"

# (connect, read) timeouts. Garena answers a healthy request in well under a
# second, so a short read timeout keeps /like inside the platform limit.
REQUEST_TIMEOUT = (4, 8)
INITIAL_TOKEN_ATTEMPTS = int(os.environ.get("FF_TOKEN_ATTEMPTS", "5"))
MAX_TOKEN_ATTEMPTS = int(os.environ.get("FF_MAX_TOKEN_ATTEMPTS", "12"))
# Wall-clock budget for one player-info lookup: every host/token combination can
# cost a full timeout, so bound the total instead of multiplying them.
PLAYER_INFO_BUDGET = float(os.environ.get("FF_PLAYER_INFO_BUDGET", "25"))

TOKEN_CACHE = {}
TOKEN_CACHE_TIME = {}
TOKEN_CACHE_ERROR = {}
TOKEN_REFRESH_INTERVAL = 7200
TOKEN_REFRESH_LOCK = threading.Lock()

ACCOUNT_FILE = os.environ.get("FF_ACCOUNT_FILE", os.path.join(BASE_DIR, "account.bd.txt"))
TOKEN_FILE = os.environ.get("FF_TOKEN_FILE", os.path.join(BASE_DIR, "token_bd.json"))

# Empty JWT payload -> we never put a token or a password in an API response.
def redact_token(token):
    if not token or not isinstance(token, str):
        return ""
    return token[:12] + "..." if len(token) > 15 else "***"


# ---------- Token helpers ----------
def token_claims(token):
    """Decoded (unverified) JWT claims, or {} when the token is unreadable."""
    try:
        return jwt.decode(token, options={"verify_signature": False})
    except Exception:
        return {}


def get_token_expiry(token):
    exp = token_claims(token).get("exp")
    return exp if isinstance(exp, int) else None


def is_token_valid(token):
    exp = get_token_expiry(token)
    if exp is None:
        # Unreadable tokens are kept: the server is the final judge.
        return True
    return int(time.time()) < (exp - 300)


def token_release_version(token, default=None):
    """Use the version for which the JWT was issued instead of a stale constant."""
    return token_claims(token).get("release_version") or default or CURRENT_RELEASE_VERSION


def token_region(token, default=None):
    claims = token_claims(token)
    return claims.get("noti_region") or claims.get("lock_region") or default or DEFAULT_REGION


def load_accounts():
    try:
        accounts = []
        if os.path.exists(ACCOUNT_FILE):
            with open(ACCOUNT_FILE, "r") as f:
                for line in f:
                    line = line.strip()
                    if ':' in line:
                        uid, password = line.split(':', 1)
                        accounts.append({"uid": uid.strip(), "password": password.strip()})
        return accounts
    except Exception as e:
        app.logger.error(f"Error loading accounts: {e}")
        return []


def save_tokens(tokens):
    """Persist tokens, falling back to a writable temp file on serverless hosts."""
    for path in (TOKEN_FILE, os.path.join("/tmp", os.path.basename(TOKEN_FILE))):
        try:
            directory = os.path.dirname(path)
            if directory and not os.path.isdir(directory):
                continue
            with open(path, "w") as f:
                json.dump(tokens, f, indent=2)
            return True
        except Exception as e:
            app.logger.warning(f"Could not save tokens to {path}: {e}")
    return False


def load_tokens():
    try:
        if "BD" in TOKEN_CACHE and "BD" in TOKEN_CACHE_TIME:
            time_diff = (datetime.now() - TOKEN_CACHE_TIME["BD"]).total_seconds()
            if time_diff < TOKEN_REFRESH_INTERVAL:
                valid_tokens = [t for t in TOKEN_CACHE["BD"] if is_token_valid(t.get('token', ''))]
                if valid_tokens:
                    return valid_tokens
                if refresh_tokens():
                    return load_tokens()
                return None

        if os.path.exists(TOKEN_FILE):
            with open(TOKEN_FILE, "r") as f:
                tokens = json.load(f)
            valid_tokens = [t for t in tokens if is_token_valid(t.get('token', ''))]
            if valid_tokens:
                TOKEN_CACHE["BD"] = valid_tokens
                TOKEN_CACHE_TIME["BD"] = datetime.now()
                return valid_tokens

        # No usable tokens on disk (missing, empty or all expired): mint new ones.
        if refresh_tokens():
            return load_tokens()
        return None
    except Exception as e:
        app.logger.error(f"Error loading tokens: {e}")
        return None


def fetch_token_from_api(uid, password, retries=1):
    """Ask the guest-JWT provider for a token. Returns (token_data, error)."""
    last_error = None
    for attempt in range(retries):
        try:
            # params also safely URL-encodes passwords containing special chars.
            response = requests.get(
                TOKEN_URL,
                params={"uid": uid, "password": password},
                timeout=(4, 10)
            )
            if response.status_code == 200:
                data = response.json()
                if isinstance(data, dict) and data.get('status') == 'success' and 'token' in data:
                    return {
                        "token": data['token'],
                        "uid": str(data.get('account_id', uid)),
                        "region": data.get('region', DEFAULT_REGION),
                        "access_token": data.get('access_token', ''),
                        "open_id": data.get('open_id', ''),
                        "account_name": data.get('account_name', ''),
                        "release_version": token_claims(data['token']).get('release_version', ''),
                        "fetched_at": int(time.time()),
                    }, None
                last_error = f"provider rejected account: {json.dumps(data)[:180]}"
                return None, last_error
            if response.status_code == 429:
                last_error = "provider rate limited (HTTP 429)"
                time.sleep(5)
                continue
            last_error = f"provider HTTP {response.status_code}: {response.text[:180]}"
            return None, last_error
        except Exception as e:
            last_error = f"{type(e).__name__}: {str(e)[:180]}"
            time.sleep(2)
            continue
    return None, last_error or "provider request failed"


def refresh_tokens(force=False):
    """Refresh every configured guest account concurrently.

    `force=True` skips nothing at the moment (the provider is always asked),
    but keeps the call sites readable for the "tokens were rejected" retry.
    """
    with TOKEN_REFRESH_LOCK:
        try:
            accounts = load_accounts()
            if not accounts:
                message = "No accounts are configured for token refresh"
                app.logger.error(message)
                TOKEN_CACHE_ERROR["BD"] = message
                return False

            # Fetching every account sequentially could block /like for minutes
            # when the provider is slow. Refresh concurrently and keep the whole
            # cold-start refresh inside the platform request limit.
            new_tokens = []
            errors = []
            worker_count = min(10, len(accounts))
            with ThreadPoolExecutor(max_workers=worker_count) as executor:
                futures = {
                    executor.submit(
                        fetch_token_from_api,
                        account['uid'],
                        account['password']
                    ): account['uid']
                    for account in accounts
                }
                for future in as_completed(futures):
                    try:
                        token_data, error = future.result()
                        if token_data and is_token_valid(token_data.get('token', '')):
                            new_tokens.append(token_data)
                        elif error:
                            errors.append(f"{futures[future]}: {error}")
                    except Exception as e:
                        errors.append(f"{futures[future]}: {type(e).__name__}: {e}")

            if not new_tokens:
                message = "Token provider returned no usable tokens"
                if errors:
                    message += " | first error -> " + errors[0]
                app.logger.error(message)
                TOKEN_CACHE_ERROR["BD"] = message
                return False

            # Do not call load_tokens() here. When the file contains only
            # expired tokens, that function calls refresh_tokens() and used to
            # recurse forever. Read the file directly and keep valid entries.
            existing = []
            if os.path.exists(TOKEN_FILE):
                try:
                    with open(TOKEN_FILE, "r") as f:
                        existing = json.load(f)
                except (OSError, ValueError, TypeError):
                    existing = []

            refreshed_uids = {t.get('uid') for t in new_tokens}
            new_tokens.extend(
                t for t in existing
                if t.get('uid') not in refreshed_uids
                and is_token_valid(t.get('token', ''))
            )

            # A serverless filesystem may be read-only; the in-memory cache
            # still makes the freshly issued tokens usable for this instance.
            save_tokens(new_tokens)
            TOKEN_CACHE["BD"] = new_tokens
            TOKEN_CACHE_TIME["BD"] = datetime.now()
            TOKEN_CACHE_ERROR["BD"] = None
            app.logger.info(
                "Refreshed %s/%s accounts (release %s)",
                len(new_tokens), len(accounts), CURRENT_RELEASE_VERSION
            )
            return True
        except Exception as e:
            app.logger.exception(f"Error refreshing tokens: {e}")
            TOKEN_CACHE_ERROR["BD"] = f"{type(e).__name__}: {e}"
            return False


def auto_refresh_tokens():
    while True:
        try:
            refresh_tokens()
            time.sleep(TOKEN_REFRESH_INTERVAL)
        except Exception:
            time.sleep(300)


# ---------- Encryption & Protobuf ----------
def encrypt_message(plaintext):
    try:
        key = b'Yg&tc%DEuh6%Zc^8'
        iv = b'6oyZDr22E3ychjM%'
        cipher = AES.new(key, AES.MODE_CBC, iv)
        padded_message = pad(plaintext, AES.block_size)
        encrypted_message = cipher.encrypt(padded_message)
        return binascii.hexlify(encrypted_message).decode('utf-8')
    except Exception as e:
        app.logger.warning("encrypt_message failed: %s", e)
        return None


def create_like_protobuf(user_id, region=None):
    try:
        message = like_pb2.like()
        message.uid = int(user_id)
        message.region = region or DEFAULT_REGION
        return message.SerializeToString()
    except Exception as e:
        app.logger.warning("create_like_protobuf failed: %s", e)
        return None


def create_uid_protobuf(uid):
    try:
        message = uid_generator_pb2.uid_generator()
        message.saturn_ = int(uid)
        message.garena = 1
        return message.SerializeToString()
    except Exception as e:
        app.logger.warning("create_uid_protobuf failed: %s", e)
        return None


def enc(uid):
    protobuf_data = create_uid_protobuf(uid)
    if protobuf_data is None:
        return None
    return encrypt_message(protobuf_data)


def decode_protobuf(binary):
    try:
        items = like_count_pb2.Info()
        items.ParseFromString(binary)
        return items
    except Exception:
        return None


# ---------- Upstream client calls ----------
def build_client_headers(token, release_version=None):
    """Headers the current client build sends to the in-game API."""
    version = release_version or token_release_version(token)
    return {
        'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 11; ASUS_Z01QD Build/PI)",
        'Connection': "Keep-Alive",
        'Accept-Encoding': "gzip",
        'Authorization': f"Bearer {token}",
        'Content-Type': "application/x-www-form-urlencoded",
        'Expect': "100-continue",
        'X-Unity-Version': "2018.4.11f1",
        'X-GA': "v1 1",
        'X-GA-SV': X_GA_SV,
        'ReleaseVersion': version,
    }


def hosts_for_region(region):
    """Ordered cluster hosts for a region. Env override wins for every region."""
    override = _env_list("FF_CLIENT_HOSTS", ())
    if override:
        return override
    return list(REGION_CLUSTER_HOSTS.get((region or "").upper(), GLOBAL_CLUSTER_HOSTS))


# Remember the cluster that most recently answered so the common case is a
# single round trip instead of probing every retired host first.
PREFERRED_HOST = {"host": None}
PREFERRED_HOST_LOCK = threading.Lock()


def ordered_hosts(region):
    hosts = hosts_for_region(region)
    with PREFERRED_HOST_LOCK:
        preferred = PREFERRED_HOST["host"]
    if preferred and preferred in hosts:
        return [preferred] + [h for h in hosts if h != preferred]
    return hosts


def remember_working_host(host):
    with PREFERRED_HOST_LOCK:
        PREFERRED_HOST["host"] = host


def _base_url(host):
    """Accept bare hosts (prod) and full URLs (local stub servers in tests)."""
    if host.startswith("http://") or host.startswith("https://"):
        return host.rstrip("/")
    return f"https://{host}"


def _body_snippet(response, limit=200):
    try:
        text = response.text
    except Exception:
        return ""
    return " ".join(text.split())[:limit]


def post_encrypted(path, encrypted_hex, token, region=None, release_version=None, deadline=None):
    """POST an encrypted protobuf body to the region's cluster with failover.

    Returns (result, diagnostics):
      result      -> None, or {"status", "content", "host", "release_version"}
      diagnostics -> list of per-host attempts (host, status/error, body hint)
    """
    diagnostics = []
    try:
        edata = bytes.fromhex(encrypted_hex)
    except (ValueError, TypeError) as e:
        return None, [{"host": None, "error": f"invalid payload: {e}"}]

    version = release_version or token_release_version(token)
    for host in ordered_hosts(region):
        if deadline is not None and time.monotonic() > deadline:
            diagnostics.append({"host": host, "status": None, "error": "skipped: time budget exhausted"})
            break
        url = f"{_base_url(host)}{path}"
        headers = build_client_headers(token, version)
        try:
            response = requests.post(
                url, data=edata, headers=headers, verify=False, timeout=REQUEST_TIMEOUT
            )
        except requests.RequestException as e:
            diagnostics.append({
                "host": host, "status": None,
                "error": f"{type(e).__name__}: {str(e)[:160]}"
            })
            continue

        entry = {
            "host": host,
            "status": response.status_code,
            "bytes": len(response.content),
        }
        if response.status_code != 200:
            entry["body"] = _body_snippet(response, 120)
            diagnostics.append(entry)
            # 5xx/404 usually means this cluster is retired or geo-blocked for
            # our egress IP; 401/403 can also be cluster specific. Either way the
            # next host is worth one try.
            continue
        if not response.content:
            entry["error"] = "empty response body"
            diagnostics.append(entry)
            continue

        diagnostics.append(entry)
        remember_working_host(host)
        return {
            "status": response.status_code,
            "content": response.content,
            "host": host,
            "release_version": version,
        }, diagnostics

    return None, diagnostics


def make_request(encrypted_uid, token, region=None, deadline=None):
    """Fetch a player's personal show page. Returns (Info, diagnostics)."""
    result, diagnostics = post_encrypted(
        INFO_PATH, encrypted_uid, token, region, deadline=deadline
    )
    if result is None:
        app.logger.warning("Player info API failed: %s", diagnostics)
        return None, diagnostics

    info = decode_protobuf(result["content"])
    if info is None:
        app.logger.warning(
            "Player info API returned an undecodable protobuf (%s bytes) from %s",
            len(result["content"]), result["host"]
        )
        diagnostics[-1]["error"] = "response was not a decodable protobuf"
        return None, diagnostics
    if info.AccountInfo.UID == 0 and not info.AccountInfo.PlayerNickname:
        diagnostics[-1]["error"] = "protobuf decoded to an empty account"
        return None, diagnostics
    return info, diagnostics


def _attempt_summary(attempts):
    """Condense per-token attempts into one actionable reason + hint."""
    statuses = [d.get("status") for attempt in attempts for d in attempt.get("diagnostics", [])]
    errors = [d.get("error") for attempt in attempts for d in attempt.get("diagnostics", [])]
    versions = {attempt.get("release_version") for attempt in attempts if attempt.get("release_version")}

    if not attempts:
        return ("no_valid_tokens",
                "Every stored token is expired and the provider returned none.")
    if not any(status is not None for status in statuses):
        return ("upstream_unreachable",
                "No cluster accepted a connection. Garena geo-gates some clusters "
                "against datacenter IPs - run /diagnose (or diagnose.py from a phone "
                "hotspot) to confirm.")
    if any(status in (401, 403) for status in statuses):
        hint = "Tokens were rejected by the game API."
        stale = {v for v in versions if v and v != CURRENT_RELEASE_VERSION}
        if stale:
            hint += (f" Tokens were issued for {', '.join(sorted(stale))} but the current "
                     f"release is {CURRENT_RELEASE_VERSION} - update the token provider or "
                     "the account list.")
        else:
            hint += (" The accounts may be banned, or the credentials in account.bd.txt are "
                     "no longer valid.")
        return ("tokens_rejected", hint)
    if any(status == 429 for status in statuses):
        return ("rate_limited", "Garena returned HTTP 429. Slow down and retry later.")
    if statuses:
        return ("upstream_error",
                f"Clusters answered with {sorted({s for s in statuses})}. "
                "Check the diagnostics for response bodies and FF_RELEASE_VERSION / FF_X_GA_SV.")
    if errors:
        return ("upstream_error", f"Last error: {errors[-1]}")
    return ("unknown", "No cluster produced a usable response.")


def get_player_info(encrypted_uid, tokens, max_attempts=None, budget=None):
    """Try valid tokens until one returns the player profile.

    Bounded by a wall-clock budget: a dead cluster costs a full timeout per
    host, so an unbounded retry loop would blow past the platform request limit.

    Returns (info, token, diagnostics).
    """
    if max_attempts is None:
        max_attempts = max(INITIAL_TOKEN_ATTEMPTS, 1)
    max_attempts = min(max_attempts, max(MAX_TOKEN_ATTEMPTS, 1))
    deadline = time.monotonic() + (budget if budget is not None else PLAYER_INFO_BUDGET)

    attempts = []
    used = 0
    for token_data in tokens:
        if time.monotonic() > deadline:
            break
        token = token_data.get('token', '')
        if not token or not is_token_valid(token):
            continue
        used += 1
        region = token_data.get('region') or token_region(token)
        info, diagnostics = make_request(encrypted_uid, token, region, deadline=deadline)
        attempts.append({
            "account_uid": token_data.get('uid'),
            "region": region,
            "release_version": token_release_version(token),
            "token": redact_token(token),
            "diagnostics": diagnostics,
        })
        if info is not None:
            return info, token, {"attempts": attempts, "reason": None, "hint": None}
        if used >= max_attempts:
            break
    reason, hint = _attempt_summary(attempts)
    return None, None, {"attempts": attempts, "reason": reason, "hint": hint}


# ---------- Like requests: one per token ----------
async def send_like_request(uid, token, region, hosts, session):
    """Send one like. Returns (token, "200" or failure reason, host)."""
    reason = "no cluster configured"
    protobuf_message = create_like_protobuf(uid, region)
    if protobuf_message is None:
        return token, "payload error", None
    encrypted_uid = encrypt_message(protobuf_message)
    if encrypted_uid is None:
        return token, "encryption error", None

    try:
        edata = bytes.fromhex(encrypted_uid)
    except (ValueError, TypeError):
        return token, "invalid payload", None

    version = token_release_version(token)
    headers = build_client_headers(token, version)
    timeout = aiohttp.ClientTimeout(total=REQUEST_TIMEOUT[0] + REQUEST_TIMEOUT[1])

    for host in hosts:
        url = f"{_base_url(host)}{LIKE_PATH}"
        try:
            async with session.post(url, data=edata, headers=headers, timeout=timeout) as response:
                status = response.status
                if status == 200:
                    remember_working_host(host)
                    return token, "200", host
                reason = f"HTTP {status}"
        except Exception as e:
            reason = f"{type(e).__name__}: {str(e)[:80]}"
    return token, reason, None


async def send_likes(uid, tokens):
    """One like per token. Returns (success_count, diagnostics)."""
    if not tokens:
        return 0, {"successful_requests": 0, "attempted": 0, "failed": []}

    hosts_seen = []
    timeout = aiohttp.ClientTimeout(total=REQUEST_TIMEOUT[0] + REQUEST_TIMEOUT[1])
    async with aiohttp.ClientSession(timeout=timeout) as session:
        tasks = []
        for token_data in tokens:
            token = token_data.get('token', '')
            if not token or not is_token_valid(token):
                continue
            # Each account likes in its own region, so the cluster is chosen per
            # token, not from the first token in the file.
            region = token_data.get('region') or token_region(token)
            hosts = ordered_hosts(region)
            hosts_seen = hosts_seen or hosts
            tasks.append(send_like_request(uid, token, region, hosts, session))
        results = await asyncio.gather(*tasks, return_exceptions=True)

    success = 0
    failures = []
    for result in results:
        if isinstance(result, Exception):
            failures.append({"error": f"{type(result).__name__}: {str(result)[:80]}"})
            continue
        token, reason, host = result
        if reason == "200":
            success += 1
        else:
            failures.append({"token": redact_token(token), "reason": reason})

    diagnostics = {
        "successful_requests": success,
        "attempted": len(results),
        "hosts": hosts_seen,
        "failed": failures[:5],
    }
    return success, diagnostics


# ---------- Flask Endpoints ----------
def _player_fields(info):
    payload = json.loads(MessageToJson(info))
    account = payload.get('AccountInfo', {})
    return {
        "likes": int(account.get('Likes', 0) or 0),
        "nickname": str(account.get('PlayerNickname', '')),
        "uid": int(account.get('UID', 0) or 0),
    }


def _failure_response(error, diag, status=502):
    attempts = diag.get("attempts", [])
    return jsonify({
        "error": error,
        "details": diag.get("hint") or "All game tokens were rejected or the upstream player-info service is unavailable",
        "reason": diag.get("reason"),
        "hint": diag.get("hint"),
        "upstream": attempts[:3],
        "upstream_attempts": len(attempts),
        "config": {
            "release_version": CURRENT_RELEASE_VERSION,
            "x_ga_sv": X_GA_SV,
            "clusters": hosts_for_region(DEFAULT_REGION),
        },
    }), status


@app.route('/like', methods=['GET'])
def handle_requests():
    uid = request.args.get("uid")
    if not uid:
        return jsonify({"error": "UID is required"}), 400

    try:
        tokens = load_tokens()
        if tokens is None or not tokens:
            reason = TOKEN_CACHE_ERROR.get("BD") or "No valid tokens available"
            return jsonify({
                "error": "No valid tokens available",
                "details": reason,
                "hint": "Check that account.bd.txt holds working guest accounts and that "
                        "the token provider (FF_TOKEN_URL) answers /diagnose.",
            }), 503

        encrypted_uid = enc(uid)
        if encrypted_uid is None:
            return jsonify({"error": "Invalid UID or encryption failed"}), 400

        # Before: try several tokens because individual game accounts can be
        # rejected even though the JWT has not reached its exp timestamp.
        before, token, diag = get_player_info(encrypted_uid, tokens)

        if before is None and diag.get("reason") in ("tokens_rejected", "unknown", "upstream_error"):
            # A fresh JWT sometimes works when the cached one is refused by the
            # game server (revoked sessions, version bump), so refresh once.
            app.logger.info("Retrying with freshly minted tokens (%s)", diag.get("reason"))
            if refresh_tokens():
                tokens = load_tokens() or tokens
                before, token, diag = get_player_info(encrypted_uid, tokens)

        if before is None:
            return _failure_response("Failed to get player info", diag)

        before_fields = _player_fields(before)

        # Send like (one per token)
        success_count, like_diag = asyncio.run(send_likes(uid, tokens))

        time.sleep(1)  # small delay for processing

        after, _, after_diag = get_player_info(encrypted_uid, tokens)
        if after is None:
            return jsonify({
                "error": "Failed to get player info after likes",
                "details": "Likes were sent, but the upstream player-info service could not be read",
                "reason": after_diag.get("reason"),
                "hint": after_diag.get("hint"),
                "upstream": after_diag.get("attempts", [])[:3],
                "like_diagnostics": like_diag,
            }), 502
        after_fields = _player_fields(after)

        like_given = after_fields["likes"] - before_fields["likes"]
        status = 1 if like_given != 0 else 2

        return jsonify({
            "LikesGivenByAPI": like_given,
            "LikesafterCommand": after_fields["likes"],
            "LikesbeforeCommand": before_fields["likes"],
            "PlayerNickname": after_fields["nickname"],
            "UID": after_fields["uid"],
            "status": status,
            "tokens_used": len(tokens),
            "successful_requests": success_count,
            "release_version": token_release_version(token or ""),
            "like_diagnostics": like_diag,
        })
    except Exception as e:
        app.logger.exception("Error handling /like")
        return jsonify({"error": str(e)}), 500


@app.route('/refresh_tokens', methods=['POST'])
def refresh_tokens_endpoint():
    if refresh_tokens():
        tokens = TOKEN_CACHE.get("BD", [])
        versions = sorted({t.get("release_version") or token_release_version(t.get("token", ""))
                           for t in tokens})
        return jsonify({
            "success": True,
            "message": "BD tokens refreshed",
            "count": len(tokens),
            "release_versions": versions,
            "expected_release_version": CURRENT_RELEASE_VERSION,
        })
    return jsonify({
        "success": False,
        "message": "Failed to refresh tokens",
        "details": TOKEN_CACHE_ERROR.get("BD"),
    }), 500


@app.route('/token_status', methods=['GET'])
def token_status():
    tokens = load_tokens()
    if tokens:
        now = int(time.time())
        expiries = [get_token_expiry(t.get('token', '')) for t in tokens]
        expiries = [e for e in expiries if e]
        versions = sorted({t.get("release_version") or token_release_version(t.get("token", ""))
                           for t in tokens})
        return jsonify({
            "server": "BD",
            "count": len(tokens),
            "last_refresh": TOKEN_CACHE_TIME.get("BD", "Never").isoformat() if "BD" in TOKEN_CACHE_TIME else "Never",
            "expires_in_seconds": (min(expiries) - now) if expiries else None,
            "release_versions": versions,
            "expected_release_version": CURRENT_RELEASE_VERSION,
            "x_ga_sv": X_GA_SV,
            "clusters": hosts_for_region(DEFAULT_REGION),
            "last_error": TOKEN_CACHE_ERROR.get("BD"),
        })
    return jsonify({
        "server": "BD",
        "count": 0,
        "status": "No tokens",
        "last_error": TOKEN_CACHE_ERROR.get("BD"),
    })


def build_diagnosis(limit=3, probe_clusters=True):
    """Explain exactly which hop is broken, without leaking credentials.

    Shared by the /diagnose route and diagnose.py (which is handy when the
    server's egress IP is geo-blocked and you need to test from a phone).
    """
    report = {
        "config": {
            "release_version": CURRENT_RELEASE_VERSION,
            "x_ga_sv": X_GA_SV,
            "region": DEFAULT_REGION,
            "token_url": TOKEN_URL,
            "account_file": os.path.basename(ACCOUNT_FILE),
            "token_file": os.path.basename(TOKEN_FILE),
        },
        "accounts_configured": len(load_accounts()),
        "provider": {"checked": 0, "ok": 0, "samples": [], "error": None},
        "clusters": [],
    }

    # 1. Can the provider still mint tokens for these accounts, and for which
    #    release version?
    accounts = load_accounts()[:limit]
    minted = []
    for account in accounts:
        token_data, error = fetch_token_from_api(account['uid'], account['password'])
        report["provider"]["checked"] += 1
        sample = {"account_uid": account['uid']}
        if token_data:
            claims = token_claims(token_data['token'])
            sample.update({
                "ok": True,
                "token": redact_token(token_data['token']),
                "region": token_data.get('region'),
                "release_version": claims.get('release_version'),
                "client_version": claims.get('client_version'),
                "expires_in_seconds": (claims.get('exp', 0) - int(time.time())) if claims.get('exp') else None,
            })
            report["provider"]["ok"] += 1
            minted.append(token_data["token"])
        else:
            sample.update({"ok": False, "error": error})
            report["provider"]["error"] = report["provider"]["error"] or error
        report["provider"]["samples"].append(sample)

    expected = CURRENT_RELEASE_VERSION
    stale = sorted({s["release_version"] for s in report["provider"]["samples"]
                    if s.get("ok") and s.get("release_version") and s["release_version"] != expected})
    if stale:
        report["provider"]["verdict"] = (
            f"Provider mints {', '.join(stale)} tokens but the live game release is {expected}. "
            "The game API rejects outdated tokens - use a current provider or mint tokens "
            "in-process."
        )
    elif report["provider"]["ok"]:
        report["provider"]["verdict"] = f"Provider mints {expected} tokens."
    else:
        report["provider"]["verdict"] = "Provider returned no tokens - accounts, credentials or provider are broken."

    # 2. Does each cluster accept one of those tokens?
    if probe_clusters and minted and accounts:
        token = minted[0]
        region = token_region(token, DEFAULT_REGION)
        # Probe with one of the accounts that just logged in, so the request is
        # a like-for-like test of the credentials the bot actually uses.
        encrypted_uid = enc(accounts[0]['uid'])
        for host in ordered_hosts(region):
            url = f"{_base_url(host)}{INFO_PATH}"
            entry = {"host": host, "region": region}
            try:
                response = requests.post(
                    url,
                    data=bytes.fromhex(encrypted_uid),
                    headers=build_client_headers(token, CURRENT_RELEASE_VERSION),
                    verify=False,
                    timeout=REQUEST_TIMEOUT,
                )
                entry["status"] = response.status_code
                entry["bytes"] = len(response.content)
                entry["body"] = _body_snippet(response, 160)
                entry["ok"] = response.status_code == 200 and len(response.content) > 0
                if entry["ok"]:
                    info = decode_protobuf(response.content)
                    if info is not None:
                        entry["player_uid"] = info.AccountInfo.UID
            except requests.RequestException as e:
                entry.update({"ok": False, "error": f"{type(e).__name__}: {str(e)[:160]}"})
            report["clusters"].append(entry)

        report["clusters_verdict"] = (
            next((f"Working cluster: {e['host']}" for e in report["clusters"] if e.get("ok")), None)
            or "No cluster accepted the request. If the provider minted valid tokens, the "
               "egress IP is probably blocked (Garena geo-gates clusters) or FF_RELEASE_VERSION / "
               "FF_X_GA_SV are stale."
        )
    elif probe_clusters:
        report["clusters_verdict"] = "Skipped: the provider minted no token to probe with."
    else:
        report["clusters_verdict"] = "Skipped (probe=0)."

    # 3. What do the cached tokens look like?
    try:
        cached = json.load(open(TOKEN_FILE))
    except Exception:
        cached = []
    now = int(time.time())
    report["cached_tokens"] = {
        "count": len(cached),
        "valid": sum(1 for t in cached if is_token_valid(t.get('token', ''))),
        "expired": sum(1 for t in cached if not is_token_valid(t.get('token', ''))),
        "release_versions": sorted({token_release_version(t.get('token', '')) for t in cached}) if cached else [],
        "oldest_expiry_in_seconds": min([get_token_expiry(t.get('token','')) - now
                                         for t in cached if get_token_expiry(t.get('token',''))], default=None),
    }
    return report


@app.route('/diagnose', methods=['GET'])
def diagnose():
    try:
        limit = max(1, min(int(request.args.get("limit", 3)), len(load_accounts()) or 1))
    except (TypeError, ValueError):
        limit = 3
    probe_clusters = request.args.get("probe", "1") not in ("0", "false", "no")
    return jsonify(build_diagnosis(limit=limit, probe_clusters=probe_clusters))


if __name__ == '__main__':
    refresh_thread = threading.Thread(target=auto_refresh_tokens, daemon=True)
    refresh_thread.start()
    app.run(debug=True, use_reloader=False, host='0.0.0.0', port=5000)
