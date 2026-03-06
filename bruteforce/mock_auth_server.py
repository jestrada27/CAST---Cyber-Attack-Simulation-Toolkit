# cast/modules/bruteforce/mock_auth_server.py
from flask import Flask, request, jsonify
from collections import defaultdict
from datetime import datetime, timedelta
import threading

app = Flask(__name__)

# In-memory demo store (NOT for production)
FAIL_COUNTS = defaultdict(int)
LOCKED_UNTIL = {}
IP_REQUESTS = defaultdict(list)
LOCK = threading.Lock()

# Demo config
MAX_FAILS = 5
LOCKOUT_SECONDS = 60
RATE_LIMIT_WINDOW_SECONDS = 10
RATE_LIMIT_MAX = 10

# Example valid credentials for demo
VALID_USERS = {
    "alice": "password123",
    "bob": "hunter2",
    "testuser": "testpass"
}

@app.route('/login', methods=['POST'])
def login():
    with LOCK:
        now = datetime.utcnow()
        data = request.get_json(silent=True) or {}
        username = data.get("username", "")
        password = data.get("password", "")
        remote_ip = request.remote_addr or "127.0.0.1"

        # Rate limiting by IP (sliding window)
        IP_REQUESTS[remote_ip] = [t for t in IP_REQUESTS[remote_ip] if (now - t).total_seconds() < RATE_LIMIT_WINDOW_SECONDS]
        IP_REQUESTS[remote_ip].append(now)
        if len(IP_REQUESTS[remote_ip]) > RATE_LIMIT_MAX:
            return jsonify({"status": "rate_limited", "message": "Too many requests"}), 429

        # Account lockout
        if username in LOCKED_UNTIL and now < LOCKED_UNTIL[username]:
            return jsonify({"status": "locked", "until": LOCKED_UNTIL[username].isoformat()}), 403

        expected = VALID_USERS.get(username)
        if expected and expected == password:
            FAIL_COUNTS[username] = 0
            return jsonify({"status": "ok", "message": "authenticated"}), 200
        else:
            FAIL_COUNTS[username] += 1
            if FAIL_COUNTS[username] >= MAX_FAILS:
                LOCKED_UNTIL[username] = now + timedelta(seconds=LOCKOUT_SECONDS)
                return jsonify({"status": "locked", "message": "account locked"}), 403
            else:
                return jsonify({"status": "failed", "attempts": FAIL_COUNTS[username]}), 401

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5001)
