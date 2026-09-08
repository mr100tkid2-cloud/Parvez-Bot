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
import time
import os
from datetime import datetime, timedelta
import jwt

app = Flask(__name__)

TOKEN_CACHE = {}
TOKEN_CACHE_TIME = {}
TOKEN_REFRESH_INTERVAL = 7200
TOKEN_REFRESH_LOCK = threading.Lock()

ACCOUNT_FILE = "account.bd.txt"
TOKEN_FILE = "token_bd.json"

# ---------- Helper functions ----------
def get_token_expiry(token):
    try:
        decoded = jwt.decode(token, options={"verify_signature": False})
        return decoded.get('exp')
    except:
        return None

def is_token_valid(token):
    exp = get_token_expiry(token)
    if exp is None:
        return True
    now = int(time.time())
    return now < (exp - 300)

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
    try:
        with open(TOKEN_FILE, "w") as f:
            json.dump(tokens, f, indent=2)
        return True
    except Exception as e:
        app.logger.error(f"Error saving tokens: {e}")
        return False

def load_tokens():
    try:
        if "BD" in TOKEN_CACHE and "BD" in TOKEN_CACHE_TIME:
            time_diff = (datetime.now() - TOKEN_CACHE_TIME["BD"]).total_seconds()
            if time_diff < TOKEN_REFRESH_INTERVAL:
                valid_tokens = [t for t in TOKEN_CACHE["BD"] if is_token_valid(t.get('token', ''))]
                if valid_tokens:
                    return valid_tokens
                else:
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
                else:
                    if refresh_tokens():
                        return load_tokens()
                    return None

        if refresh_tokens():
            return load_tokens()
        return None
    except Exception as e:
        app.logger.error(f"Error loading tokens: {e}")
        return None

def fetch_token_from_api(uid, password, retries=3):
    url = f"https://guest-jwt.vercel.app/token?uid={uid}&password={password}"
    for attempt in range(retries):
        try:
            response = requests.get(url, timeout=30)
            if response.status_code == 200:
                data = response.json()
                if data.get('status') == 'success' and 'token' in data:
                    return {
                        "token": data['token'],
                        "uid": str(data.get('account_id', uid)),
                        "region": data.get('region', 'BD'),
                        "access_token": data.get('access_token', ''),
                        "open_id": data.get('open_id', ''),
                        "account_name": data.get('account_name', '')
                    }
                else:
                    return None
            elif response.status_code == 429:
                time.sleep(5)
                continue
            else:
                return None
        except Exception as e:
            time.sleep(2)
            continue
    return None

def refresh_tokens():
    # Prevent simultaneous requests from refreshing the same accounts. This is
    # particularly important on startup, when every saved token may be expired.
    with TOKEN_REFRESH_LOCK:
        try:
            accounts = load_accounts()
            if not accounts:
                app.logger.error("No accounts are configured for token refresh")
                return False

            new_tokens = []
            for idx, account in enumerate(accounts):
                token_data = fetch_token_from_api(account['uid'], account['password'])
                if token_data and is_token_valid(token_data.get('token', '')):
                    new_tokens.append(token_data)
                if idx < len(accounts) - 1:
                    time.sleep(2)

            if not new_tokens:
                app.logger.error("Token provider returned no valid tokens")
                return False

            # Do not call load_tokens() here. When the file contains only expired
            # tokens, that function calls refresh_tokens() and used to recurse
            # forever. Read the file directly and retain only still-valid entries.
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

            # A serverless filesystem may be read-only; the in-memory cache still
            # makes the freshly issued tokens usable for the current instance.
            save_tokens(new_tokens)
            TOKEN_CACHE["BD"] = new_tokens
            TOKEN_CACHE_TIME["BD"] = datetime.now()
            return True
        except Exception as e:
            app.logger.exception(f"Error refreshing tokens: {e}")
            return False

def auto_refresh_tokens():
    while True:
        try:
            refresh_tokens()
            time.sleep(TOKEN_REFRESH_INTERVAL)
        except Exception as e:
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
        return None

def create_like_protobuf(user_id, region="BD"):
    try:
        message = like_pb2.like()
        message.uid = int(user_id)
        message.region = region
        return message.SerializeToString()
    except Exception as e:
        return None

def create_uid_protobuf(uid):
    try:
        message = uid_generator_pb2.uid_generator()
        message.saturn_ = int(uid)
        message.garena = 1
        return message.SerializeToString()
    except Exception as e:
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
    except:
        return None

# ---------- Like requests: one per token ----------
async def send_like_request(encrypted_uid, token, url, session):
    try:
        edata = bytes.fromhex(encrypted_uid)
        headers = {
            'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
            'Connection': "Keep-Alive",
            'Accept-Encoding': "gzip",
            'Authorization': f"Bearer {token}",
            'Content-Type': "application/x-www-form-urlencoded",
            'Expect': "100-continue",
            'X-Unity-Version': "2018.4.11f1",
            'X-GA': "v1 1",
            'ReleaseVersion': token_release_version(token)
        }
        timeout = aiohttp.ClientTimeout(total=30)
        async with session.post(url, data=edata, headers=headers, timeout=timeout) as response:
            return response.status
    except Exception as e:
        return None

async def send_likes(uid, url):
    try:
        protobuf_message = create_like_protobuf(uid, "BD")
        if protobuf_message is None:
            return None
        encrypted_uid = encrypt_message(protobuf_message)
        if encrypted_uid is None:
            return None

        tokens = load_tokens()
        if tokens is None or not tokens:
            return None

        token_list = [t['token'] for t in tokens if 'token' in t and is_token_valid(t['token'])]
        if not token_list:
            return None

        timeout = aiohttp.ClientTimeout(total=30)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            tasks = []
            for token in token_list:
                tasks.append(send_like_request(encrypted_uid, token, url, session))
            results = await asyncio.gather(*tasks, return_exceptions=True)
            success = sum(1 for r in results if r == 200)
            return success
    except Exception as e:
        return None

# ---------- Get player info ----------
def token_release_version(token, default="OB54"):
    """Use the version for which the JWT was issued instead of a stale constant."""
    try:
        claims = jwt.decode(token, options={"verify_signature": False})
        return claims.get("release_version") or default
    except Exception:
        return default


def make_request(encrypted_uid, token):
    try:
        url = "https://clientbp.ggpolarbear.com/GetPlayerPersonalShow"
        edata = bytes.fromhex(encrypted_uid)
        headers = {
            'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
            'Connection': "Keep-Alive",
            'Accept-Encoding': "gzip",
            'Authorization': f"Bearer {token}",
            'Content-Type': "application/x-www-form-urlencoded",
            'Expect': "100-continue",
            'X-Unity-Version': "2018.4.11f1",
            'X-GA': "v1 1",
            'ReleaseVersion': token_release_version(token)
        }
        response = requests.post(url, data=edata, headers=headers, verify=False, timeout=30)
        if response.status_code != 200:
            app.logger.warning("Player info API returned HTTP %s", response.status_code)
            return None
        result = decode_protobuf(response.content)
        if result is None:
            app.logger.warning("Player info API returned an invalid protobuf response")
        return result
    except Exception as e:
        app.logger.warning("Player info request failed: %s", e)
        return None


def get_player_info(encrypted_uid, tokens):
    """Try all valid tokens; one rejected account must not break the API."""
    for token_data in tokens:
        token = token_data.get('token', '')
        if token and is_token_valid(token):
            info = make_request(encrypted_uid, token)
            if info is not None:
                return info, token
    return None, None

# ---------- Flask Endpoints ----------
@app.route('/like', methods=['GET'])
def handle_requests():
    uid = request.args.get("uid")
    if not uid:
        return jsonify({"error": "UID is required"}), 400

    try:
        tokens = load_tokens()
        if tokens is None or not tokens:
            return jsonify({"error": "No valid tokens available"}), 500

        encrypted_uid = enc(uid)
        if encrypted_uid is None:
            return jsonify({"error": "Invalid UID or encryption failed"}), 400

        # Before: try every token because an individual game account can be
        # rejected even though its JWT has not reached its exp timestamp.
        before, token = get_player_info(encrypted_uid, tokens)
        if before is None:
            # Tokens may have been revoked after issuance. Refresh once and retry.
            if refresh_tokens():
                tokens = TOKEN_CACHE.get("BD", [])
                before, token = get_player_info(encrypted_uid, tokens)
        if before is None:
            return jsonify({
                "error": "Failed to get player info",
                "details": "All game tokens were rejected or the upstream player-info service is unavailable"
            }), 502
        before_json = json.loads(MessageToJson(before))
        before_like = int(before_json.get('AccountInfo', {}).get('Likes', 0))

        # Send like (one per token)
        url = "https://clientbp.ggpolarbear.com/LikeProfile"
        success_count = asyncio.run(send_likes(uid, url))
        if success_count is None:
            return jsonify({"error": "Like request failed"}), 500

        time.sleep(1)  # small delay for processing

        # After
        after, _ = get_player_info(encrypted_uid, tokens)
        if after is None:
            return jsonify({
                "error": "Failed to get player info after likes",
                "details": "Likes were sent, but the upstream player-info service could not be read"
            }), 502
        after_json = json.loads(MessageToJson(after))
        after_like = int(after_json.get('AccountInfo', {}).get('Likes', 0))
        player_name = str(after_json.get('AccountInfo', {}).get('PlayerNickname', ''))
        player_uid = int(after_json.get('AccountInfo', {}).get('UID', 0))

        like_given = after_like - before_like
        status = 1 if like_given != 0 else 2

        return jsonify({
            "LikesGivenByAPI": like_given,
            "LikesafterCommand": after_like,
            "LikesbeforeCommand": before_like,
            "PlayerNickname": player_name,
            "UID": player_uid,
            "status": status,
            "tokens_used": len(tokens),
            "successful_requests": success_count
        })
    except Exception as e:
        app.logger.error(f"Error: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/refresh_tokens', methods=['POST'])
def refresh_tokens_endpoint():
    if refresh_tokens():
        return jsonify({"success": True, "message": "BD tokens refreshed"})
    else:
        return jsonify({"success": False, "message": "Failed to refresh tokens"}), 500

@app.route('/token_status', methods=['GET'])
def token_status():
    tokens = load_tokens()
    if tokens:
        return jsonify({
            "server": "BD",
            "count": len(tokens),
            "last_refresh": TOKEN_CACHE_TIME.get("BD", "Never").isoformat() if "BD" in TOKEN_CACHE_TIME else "Never"
        })
    else:
        return jsonify({"server": "BD", "count": 0, "status": "No tokens"})

if __name__ == '__main__':
    refresh_thread = threading.Thread(target=auto_refresh_tokens, daemon=True)
    refresh_thread.start()
    app.run(debug=True, use_reloader=False, host='0.0.0.0', port=5000)