# cast/modules/bruteforce/bruteforce_simulator.py
import argparse
import requests
import uuid
import time
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from .telemetry_db import init_db, insert_event

DEFAULT_TARGET = os.environ.get("CAST_BF_TARGET", "http://127.0.0.1:5001/login")
ALLOW_EXTERNAL = os.environ.get("CAST_BF_ALLOW_EXTERNAL", "false").lower() == "true"

def is_safe_target(url):
    if url.startswith("http://127.0.0.1") or url.startswith("http://localhost"):
        return True
    return ALLOW_EXTERNAL

def attempt_login(session, url, username, password, run_id, dry_run=False):
    remote_ip = "127.0.0.1"
    if dry_run:
        insert_event(run_id, username, password, remote_ip, "dry_run", 0, "dry run - no request sent")
        return {"username": username, "status": "dry_run"}
    try:
        resp = session.post(url, json={"username": username, "password": password}, timeout=5)
        try:
            j = resp.json()
            status = j.get("status", "unknown")
            msg = j.get("message", "") or j.get("error", "")
        except Exception:
            status = "http"
            msg = resp.text[:200]
        insert_event(run_id, username, password, remote_ip, status, resp.status_code, msg)
        return {"username": username, "status": status, "code": resp.status_code}
    except Exception as e:
        insert_event(run_id, username, password, remote_ip, "error", 0, str(e))
        return {"username": username, "status": "error", "error": str(e)}

def run_simulation(target_url, creds, concurrency, attempts_per_user, run_id, dry_run=False, delay_between_attempts=0.05):
    if not is_safe_target(target_url):
        raise RuntimeError("Target not allowed (safety). To allow external targets set CAST_BF_ALLOW_EXTERNAL=true (NOT recommended).")

    init_db()
    results = []
    with ThreadPoolExecutor(max_workers=concurrency) as exe:
        with requests.Session() as session:
            futures = []
            for username, passwords in creds.items():
                for attempt_idx in range(attempts_per_user):
                    pwd = passwords[attempt_idx % len(passwords)]
                    futures.append(exe.submit(attempt_login, session, target_url, username, pwd, run_id, dry_run))
                    time.sleep(delay_between_attempts)
            for fut in as_completed(futures):
                results.append(fut.result())
    return results

def load_credentials_from_file(path):
    d = {}
    with open(path, "r") as f:
        for line in f:
            line=line.strip()
            if not line or line.startswith("#"): continue
            if ":" not in line: continue
            user, pwlist = line.split(":",1)
            ps = [p.strip() for p in pwlist.split(",") if p.strip()]
            d[user.strip()] = ps or [""]
    return d

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--creds", required=True)
    parser.add_argument("--run-id", default=str(uuid.uuid4()))
    parser.add_argument("--concurrency", type=int, default=5)
    parser.add_argument("--attempts-per-user", type=int, default=10)
    parser.add_argument("--target", default=DEFAULT_TARGET)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--delay", type=float, default=0.05)
    args = parser.parse_args()

    print("RUN ID:", args.run_id)
    print("Target:", args.target)
    if not is_safe_target(args.target):
        print("ERROR: target not allowed. Aborting for safety.")
        exit(1)

    creds = load_credentials_from_file(args.creds)
    results = run_simulation(args.target, creds, args.concurrency, args.attempts_per_user, args.run_id, dry_run=args.dry_run, delay_between_attempts=args.delay)
    summary = {}
    for r in results:
        summary[r.get("status")] = summary.get(r.get("status"), 0) + 1
    print("Summary:", summary)
