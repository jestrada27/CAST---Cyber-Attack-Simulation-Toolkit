import re
import time
import random
import sqlite3
import threading
from datetime import datetime
from collections import defaultdict
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS

app = Flask(__name__)
app.secret_key = "cast-target-insecure-key"
CORS(app)

DB_PATH = ":memory:"
_db_lock = threading.Lock()
_shared_conn = None

_login_attempts = defaultdict(list)
BF_WINDOW_SECONDS = 60
BF_MAX_ATTEMPTS = 10

_dns_log = []
_dns_exfil_bytes = 0

SQLI_PATTERNS = re.compile(
    r"('|\"|\-\-|;|/\*|\*/|xp_|union\s+select|or\s+1\s*=\s*1|"
    r"or\s+'1'\s*=\s*'1|sleep\s*\(|waitfor\s+delay|pg_sleep|"
    r"drop\s+table|insert\s+into|select\s+.*\s+from)",
    re.IGNORECASE
)

XSS_PATTERNS = re.compile(
    r"<script|onerror\s*=|onload\s*=|javascript:|<img|<svg|<iframe",
    re.IGNORECASE
)

DNS_TUNNEL_PATTERNS = re.compile(
    r"([a-z0-9]{20,}\.)|([a-f0-9]{32,}\.)|(\.b64\.)|(\.tunnel\.|\.dns\.|\.exfil\.)",
    re.IGNORECASE
)


def get_db():
    global _shared_conn
    if _shared_conn is None:
        _shared_conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        _shared_conn.row_factory = sqlite3.Row
        init_db(_shared_conn)
    return _shared_conn


def init_db(conn):
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            password TEXT NOT NULL,
            role TEXT DEFAULT 'user',
            email TEXT
        );

        CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            price REAL
        );

        CREATE TABLE IF NOT EXISTS comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            content TEXT,
            stored_at TEXT
        );

        DELETE FROM users;
        DELETE FROM products;
        DELETE FROM comments;

        INSERT INTO users (username, password, role, email) VALUES
            ('admin', 'supersecret123', 'admin', 'admin@cast.local'),
            ('alice', 'password1', 'user', 'alice@cast.local'),
            ('bob', 'hunter2', 'user', 'bob@cast.local');

        INSERT INTO products (name, price) VALUES
            ('Widget A', 9.99),
            ('Widget B', 19.99),
            ('Secret Blueprint', 999.99);
    """)
    conn.commit()


def detect_sqli(value: str) -> dict:
    match = SQLI_PATTERNS.search(value)
    is_timing = bool(re.search(r"sleep\s*\(|waitfor\s+delay|pg_sleep", value, re.IGNORECASE))
    is_union = bool(re.search(r"union\s+select", value, re.IGNORECASE))
    is_bool = bool(re.search(r"or\s+1\s*=\s*1|or\s+'1'\s*=\s*'1", value, re.IGNORECASE))

    if is_timing:
        technique = "timing"
    elif is_union:
        technique = "union"
    elif is_bool:
        technique = "boolean"
    elif match:
        technique = "error"
    else:
        technique = "none"

    return {
        "detected": bool(match),
        "technique": technique,
        "matched_token": match.group(0) if match else None
    }


def detect_xss(value: str) -> dict:
    match = XSS_PATTERNS.search(value)
    if not match:
        return {"detected": False, "technique": "none", "matched_token": None}

    token = match.group(0).lower()
    if "script" in token:
        technique = "script_tag"
    elif "javascript:" in token:
        technique = "js_protocol"
    elif "onerror" in token or "onload" in token:
        technique = "event_handler"
    else:
        technique = "html_injection"

    return {
        "detected": True,
        "technique": technique,
        "matched_token": match.group(0)
    }


def record_attempt(ip):
    now = time.time()
    _login_attempts[ip] = [t for t in _login_attempts[ip] if now - t < BF_WINDOW_SECONDS]
    _login_attempts[ip].append(now)


def attempt_count(ip):
    now = time.time()
    return len([t for t in _login_attempts[ip] if now - t < BF_WINDOW_SECONDS])


def is_rate_limited(ip):
    return attempt_count(ip) > BF_MAX_ATTEMPTS


def analyze_dns_hostname(hostname: str) -> dict:
    label_lengths = [len(p) for p in hostname.split(".")] if hostname else []
    max_label = max(label_lengths) if label_lengths else 0
    entropy_approx = len(set(hostname)) / max(len(hostname), 1)
    suspicious = bool(DNS_TUNNEL_PATTERNS.search(hostname)) or max_label > 40 or entropy_approx > 0.6

    return {
        "suspicious": suspicious,
        "max_label_length": max_label,
        "entropy_approx": round(entropy_approx, 3),
        "labels": hostname.split(".") if hostname else []
    }


# ---------------------------------------------------------------------------
# Health check helper — probes any arbitrary target URL to determine whether
# it is reachable and suitable for attack testing. All checks are generic
# and work against any web target, not just the local CAST server.
# ---------------------------------------------------------------------------
def run_health_checks(target_url: str) -> dict:
    import urllib.request
    import urllib.error
    import urllib.parse
    import json as _json
    import re as _re
    import ssl

    # Strip trailing slash and ensure scheme is present
    target_url = target_url.rstrip("/")
    if not target_url.startswith("http"):
        target_url = "http://" + target_url

    checks = []

    # Shared SSL context that skips cert verification (we're a pentest tool)
    ssl_ctx = ssl.create_default_context()
    ssl_ctx.check_hostname = False
    ssl_ctx.verify_mode = ssl.CERT_NONE

    def fetch(url, timeout=5):
        req = urllib.request.Request(url, headers={"User-Agent": "CAST-HealthCheck/1.0"})
        return urllib.request.urlopen(req, timeout=timeout, context=ssl_ctx)

    raw_html = ""
    response_headers = {}
    http_status = None

    # ------------------------------------------------------------------
    # 1. Host reachable — can we open a TCP connection at all
    # ------------------------------------------------------------------
    try:
        t0 = time.time()
        r = fetch(target_url)
        ms = int((time.time() - t0) * 1000)
        http_status = r.status
        raw_html = r.read(32768).decode("utf-8", errors="ignore")
        response_headers = dict(r.headers)
        checks.append({"id": "reachable", "pass": True, "detail": f"Connected ({http_status})"})
    except urllib.error.HTTPError as e:
        ms = 0
        http_status = e.status
        raw_html = e.read(32768).decode("utf-8", errors="ignore")
        response_headers = dict(e.headers)
        # HTTP errors still mean the host is up
        checks.append({"id": "reachable", "pass": True, "detail": f"Connected (HTTP {e.status})"})
    except Exception as exc:
        checks.append({"id": "reachable", "pass": False, "detail": "Connection refused or timed out"})
        # Host is down — skip remaining checks
        for cid in ("http_200", "latency_ok", "input_fields", "waf_check", "headers_exposed", "auth_endpoint"):
            checks.append({"id": cid, "pass": False, "detail": "skipped — host unreachable"})
        return {"all_pass": False, "checks": checks}

    # ------------------------------------------------------------------
    # 2. HTTP response — returns any non-5xx status
    # ------------------------------------------------------------------
    http_ok = http_status is not None and http_status < 500
    checks.append({
        "id": "http_200",
        "pass": http_ok,
        "detail": f"HTTP {http_status}" if http_ok else f"Server error ({http_status})"
    })

    # ------------------------------------------------------------------
    # 3. Latency — round-trip under 1500ms (generous for remote targets)
    # ------------------------------------------------------------------
    try:
        t0 = time.time()
        fetch(target_url, timeout=5)
        ms = int((time.time() - t0) * 1000)
    except Exception:
        ms = 9999
    latency_ok = ms < 1500
    checks.append({
        "id": "latency_ok",
        "pass": latency_ok,
        "detail": f"{ms}ms" + (" — acceptable" if latency_ok else " — too slow for reliable attacks")
    })

    # ------------------------------------------------------------------
    # 4. Input fields — page contains <input>, <textarea>, or <form>
    # ------------------------------------------------------------------
    input_count = len(_re.findall(r"<input|<textarea|<form", raw_html, _re.IGNORECASE))
    has_inputs = input_count > 0
    checks.append({
        "id": "input_fields",
        "pass": has_inputs,
        "detail": f"{input_count} input field(s) found" if has_inputs else "No input fields detected"
    })

    # ------------------------------------------------------------------
    # 5. WAF / CDN check — look for blocking headers or known WAF signatures
    # ------------------------------------------------------------------
    waf_headers = {"cf-ray", "x-sucuri-id", "x-fw-hash", "x-akamai-transformed", "server-timing"}
    waf_server_values = ("cloudflare", "sucuri", "akamai", "imperva", "incapsula", "barracuda")

    server_hdr = response_headers.get("Server", response_headers.get("server", "")).lower()
    via_hdr    = response_headers.get("Via", "").lower()
    found_waf_header = bool(waf_headers & {h.lower() for h in response_headers})
    found_waf_server = any(w in server_hdr for w in waf_server_values)
    found_waf_body   = bool(_re.search(r"cloudflare|access denied|blocked|captcha", raw_html, _re.IGNORECASE))

    waf_detected = found_waf_header or found_waf_server or found_waf_body
    checks.append({
        "id": "waf_check",
        "pass": not waf_detected,
        "detail": "No WAF/CDN blocking detected" if not waf_detected else "WAF or CDN detected — may block attacks"
    })

    # ------------------------------------------------------------------
    # 6. Headers exposed — server is leaking useful info (good for us)
    # ------------------------------------------------------------------
    useful_headers = ["Server", "X-Powered-By", "X-AspNet-Version", "X-Generator", "Via"]
    found = [h for h in useful_headers if h.lower() in {k.lower() for k in response_headers}]
    headers_ok = len(found) > 0
    checks.append({
        "id": "headers_exposed",
        "pass": headers_ok,
        "detail": ", ".join(found) if headers_ok else "No identifying headers present"
    })

    # ------------------------------------------------------------------
    # 7. Auth endpoint — page or a common path hints at a login form
    # ------------------------------------------------------------------
    has_auth_in_page = bool(_re.search(
        r'(type=["\']password["\']|action=["\'][^"\']*login|href=["\'][^"\']*login'
        r'|href=["\'][^"\']*signin|href=["\'][^"\']*auth)',
        raw_html, _re.IGNORECASE
    ))

    auth_found = has_auth_in_page
    if not auth_found:
        # Try probing common auth paths
        for path in ("/login", "/signin", "/auth", "/admin"):
            try:
                r2 = fetch(target_url + path, timeout=3)
                if r2.status < 500:
                    auth_found = True
                    path_found = path
                    break
            except urllib.error.HTTPError as e:
                if e.status < 500:
                    auth_found = True
                    path_found = path
                    break
            except Exception:
                continue

    checks.append({
        "id": "auth_endpoint",
        "pass": auth_found,
        "detail": "Auth endpoint found" if auth_found else "No login/auth route detected"
    })

    all_pass = all(c["pass"] for c in checks)
    return {"all_pass": all_pass, "checks": checks}


@app.route("/")
def home():
    return send_from_directory(".", "target_console.html")


@app.route("/health_check", methods=["GET"])
def health_check():
    """
    Pre-attack readiness check against any target URL.
    Pass the target as ?url=http://... -- the server probes it and returns
    structured JSON that the UI renders without any logic of its own.
    """
    target = request.args.get("url", "").strip()
    if not target:
        return jsonify({"error": "Missing ?url= parameter"}), 400
    result = run_health_checks(target)
    return jsonify(result)


@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "connected": True,
        "status": "running",
        "message": "CAST target server is running.",
        "time": datetime.utcnow().isoformat()
    })


@app.route("/search", methods=["GET"])
def sqli_search():
    q = request.args.get("q", "")
    sqli_info = detect_sqli(q)
    db = get_db()

    rows = []
    error_text = None
    sql_executed = f"SELECT id, name, price FROM products WHERE name LIKE '%{q}%'"

    try:
        with _db_lock:
            cursor = db.execute(sql_executed)
            rows = [dict(r) for r in cursor.fetchall()]
    except Exception as exc:
        error_text = str(exc)

    vulnerability = sqli_info["detected"] and (bool(rows) or error_text is not None)

    return jsonify({
        "connected": True,
        "attack_detected": sqli_info["detected"],
        "attack_type": "SQL Injection",
        "technique": sqli_info["technique"],
        "payload_received": q,
        "vulnerability": vulnerability,
        "detail": (
            f"SQL injection pattern matched: {sqli_info['matched_token']}"
            if sqli_info["detected"] else "No SQL injection pattern detected."
        ),
        "server_behavior": {
            "sql_executed": sql_executed,
            "rows_returned": len(rows),
            "results": rows,
            "error_disclosed": error_text
        }
    })


@app.route("/login", methods=["POST"])
def sqli_login():
    data = request.get_json(silent=True) or request.form
    username = data.get("username", "")
    password = data.get("password", "")

    sqli_info = detect_sqli(username)
    db = get_db()

    row = None
    error_text = None
    sql_executed = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"

    try:
        with _db_lock:
            cursor = db.execute(sql_executed)
            row = cursor.fetchone()
    except Exception as exc:
        error_text = str(exc)

    logged_in = row is not None
    user_data = dict(row) if row else None
    vulnerability = sqli_info["detected"] and logged_in

    return jsonify({
        "connected": True,
        "attack_detected": sqli_info["detected"],
        "attack_type": "SQL Injection",
        "technique": sqli_info["technique"],
        "payload_received": username,
        "vulnerability": vulnerability,
        "detail": (
            f"Login bypass worked. Logged in as {user_data['username']}."
            if vulnerability else "Login failed or no injection pattern detected."
        ),
        "server_behavior": {
            "sql_executed": sql_executed,
            "login_success": logged_in,
            "user_returned": user_data,
            "error_disclosed": error_text
        }
    })


@app.route("/comment", methods=["POST"])
def xss_stored():
    data = request.get_json(silent=True) or request.form
    content = data.get("content", "")

    xss_info = detect_xss(content)
    db = get_db()

    with _db_lock:
        db.execute(
            "INSERT INTO comments (content, stored_at) VALUES (?, ?)",
            (content, datetime.utcnow().isoformat())
        )
        db.commit()

        cursor = db.execute("SELECT id, content, stored_at FROM comments ORDER BY id DESC LIMIT 5")
        comments = [dict(r) for r in cursor.fetchall()]

    return jsonify({
        "connected": True,
        "attack_detected": xss_info["detected"],
        "attack_type": "XSS",
        "technique": "stored",
        "payload_received": content,
        "vulnerability": xss_info["detected"],
        "detail": (
            "Stored XSS payload was saved without sanitization."
            if xss_info["detected"] else "Comment saved. No obvious XSS pattern detected."
        ),
        "server_behavior": {
            "payload_stored": True,
            "recent_comments": comments,
            "output_escaped": False
        }
    })


@app.route("/reflect", methods=["GET"])
def xss_reflected():
    msg = request.args.get("msg", "")
    xss_info = detect_xss(msg)

    html_body = f"""<!DOCTYPE html>
<html>
<head><title>Reflect</title></head>
<body>
<h2>Results for: {msg}</h2>
<p>No items matched your query.</p>
</body>
</html>"""

    return jsonify({
        "connected": True,
        "attack_detected": xss_info["detected"],
        "attack_type": "XSS",
        "technique": "reflected",
        "payload_received": msg,
        "vulnerability": xss_info["detected"],
        "detail": (
            "Payload was reflected directly into HTML."
            if xss_info["detected"] else "No obvious XSS pattern detected."
        ),
        "server_behavior": {
            "raw_html_sent": html_body,
            "output_escaped": False
        }
    })


@app.route("/bf_login", methods=["POST"])
def bf_login():
    ip = request.remote_addr or "unknown"
    data = request.get_json(silent=True) or request.form

    username = data.get("username", "")
    password = data.get("password", "")

    record_attempt(ip)
    tries = attempt_count(ip)

    if is_rate_limited(ip):
        return jsonify({
            "connected": True,
            "attack_detected": True,
            "attack_type": "Brute Force",
            "technique": "credential_stuffing",
            "payload_received": username,
            "vulnerability": False,
            "detail": "Rate limit hit. Too many login attempts.",
            "server_behavior": {
                "attempt_number": tries,
                "rate_limited": True,
                "login_success": False
            }
        }), 429

    db = get_db()
    row = None

    with _db_lock:
        cursor = db.execute(
            "SELECT * FROM users WHERE username=? AND password=?",
            (username, password)
        )
        row = cursor.fetchone()

    login_success = row is not None
    user_data = dict(row) if row else None

    if login_success:
        time.sleep(0.05)

    return jsonify({
        "connected": True,
        "attack_detected": tries > 3,
        "attack_type": "Brute Force",
        "technique": "credential_stuffing",
        "payload_received": username,
        "vulnerability": login_success,
        "detail": (
            f"Credentials accepted after {tries} attempts."
            if login_success else f"Attempt {tries} failed."
        ),
        "server_behavior": {
            "attempt_number": tries,
            "rate_limited": False,
            "login_success": login_success,
            "user_returned": user_data
        }
    })


@app.route("/dns_query", methods=["POST"])
def dns_tunneling():
    global _dns_exfil_bytes

    data = request.get_json(silent=True) or request.form
    hostname = data.get("hostname", "")

    analysis = analyze_dns_hostname(hostname)
    query_size = len(hostname.encode())

    if analysis["suspicious"]:
        _dns_exfil_bytes += query_size

    entry = {
        "hostname": hostname,
        "timestamp": datetime.utcnow().isoformat(),
        "suspicious": analysis["suspicious"],
        "bytes": query_size
    }
    _dns_log.append(entry)

    resolved_ip = f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"

    return jsonify({
        "connected": True,
        "attack_detected": analysis["suspicious"],
        "attack_type": "DNS Tunneling",
        "technique": "data_exfiltration_via_subdomain",
        "payload_received": hostname,
        "vulnerability": analysis["suspicious"],
        "detail": (
            "Suspicious DNS query accepted by the server."
            if analysis["suspicious"] else "Hostname looks normal."
        ),
        "server_behavior": {
            "resolved_to": resolved_ip,
            "query_bytes": query_size,
            "total_exfil_bytes": _dns_exfil_bytes,
            "queries_logged": len(_dns_log)
        }
    })


@app.route("/dns_status", methods=["GET"])
def dns_status():
    suspicious_count = sum(1 for e in _dns_log if e["suspicious"])
    return jsonify({
        "connected": True,
        "total_queries": len(_dns_log),
        "suspicious_queries": suspicious_count,
        "total_exfil_bytes": _dns_exfil_bytes,
        "recent_queries": _dns_log[-10:]
    })


@app.route("/reset", methods=["POST"])
def reset_state():
    global _dns_exfil_bytes, _shared_conn
    _login_attempts.clear()
    _dns_log.clear()
    _dns_exfil_bytes = 0
    _shared_conn = None
    get_db()

    return jsonify({
        "connected": True,
        "success": True,
        "message": "Server state reset."
    })


if __name__ == "__main__":
    print("CAST Target Server running at http://127.0.0.1:8000")
    app.run(host="127.0.0.1", port=8000, debug=False)