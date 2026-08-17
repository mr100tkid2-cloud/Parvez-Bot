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
    try:
        accounts = load_accounts()
        if not accounts:
            return False
        new_tokens = []
        for idx, account in enumerate(accounts):
            token_data = fetch_token_from_api(account['uid'], account['password'])
            if token_data:
                new_tokens.append(token_data)
            if idx < len(accounts) - 1:
                time.sleep(2)
        if new_tokens:
            existing = load_tokens() if os.path.exists(TOKEN_FILE) else []
            if existing:
                existing_uids = {t.get('uid') for t in existing if 'uid' in t}
                for token in existing:
                    if token.get('uid') not in {t.get('uid') for t in new_tokens}:
                        new_tokens.append(token)
            save_tokens(new_tokens)
            TOKEN_CACHE["BD"] = new_tokens
            TOKEN_CACHE_TIME["BD"] = datetime.now()
            return True
        return False
    except Exception as e:
        app.logger.error(f"Error refreshing tokens: {e}")
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
            'ReleaseVersion': "OB54"
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
            'ReleaseVersion': "OB54"
        }
        response = requests.post(url, data=edata, headers=headers, verify=False, timeout=30)
        if response.status_code != 200:
            return None
        return decode_protobuf(response.content)
    except Exception as e:
        return None

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

        token = tokens[0]['token']
        encrypted_uid = enc(uid)
        if encrypted_uid is None:
            return jsonify({"error": "Encryption failed"}), 500

        # Before
        before = make_request(encrypted_uid, token)
        if before is None:
            return jsonify({"error": "Failed to get player info"}), 500
        before_json = json.loads(MessageToJson(before))
        before_like = int(before_json.get('AccountInfo', {}).get('Likes', 0))

        # Send like (one per token)
        url = "https://clientbp.ggpolarbear.com/LikeProfile"
        success_count = asyncio.run(send_likes(uid, url))
        if success_count is None:
            return jsonify({"error": "Like request failed"}), 500

        time.sleep(1)  # small delay for processing

        # After
        after = make_request(encrypted_uid, token)
        if after is None:
            return jsonify({"error": "Failed to get player info after likes"}), 500
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