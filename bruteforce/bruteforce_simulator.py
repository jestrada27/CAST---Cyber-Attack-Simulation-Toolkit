# bruteforce/bruteforce_simulator.py
"""
Brute-force simulator 

- Default target is the local mock server: http://127.0.0.1:5001/login
- Refuses non-local targets unless CAST_BF_ALLOW_EXTERNAL=true is set.
- Telemetry stored in MongoDB (CAST database).

Run from repo root:
  python -m bruteforce.bruteforce_simulator --creds creds.txt --attempts-per-user 3 --dry-run

Live run (make sure mock server is running):
  python -m bruteforce.bruteforce_simulator --creds creds.txt --attempts-per-user 3
"""

import argparse
import uuid
import time
import os
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests

# IMPORTANT: package-relative import
from .telemetry_db import init_db, insert_event

# Default safe target - localhost mock server
DEFAULT_TARGET = os.environ.get("CAST_BF_TARGET", "http://127.0.0.1:5001/login")

# Safety guard: must be localhost unless explicit override
ALLOW_EXTERNAL = os.environ.get("CAST_BF_ALLOW_EXTERNAL", "false").lower() == "true"


def is_safe_target(url: str) -> bool:
    if url.startswith("http://127.0.0.1") or url.startswith("http://localhost"):
        return True
    return ALLOW_EXTERNAL


def load_credentials_from_file(path: str):
    """
    File format:
      username1:pass1,pass2,pass3
      username2:passA,passB

    Lines starting with # are ignored.
    """
    d = {}
    with open(path, "r", encoding="utf-8") as f:
        for raw in f:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            # Skip malformed lines
            if ":" not in line:
                continue
            user, pwlist = line.split(":", 1)
            user = user.strip()
            pwlist = pwlist.strip()
            if not user:
                continue
            passwords = [p.strip() for p in pwlist.split(",") if p.strip()]
            if not passwords:
                passwords = [""]
            d[user] = passwords
    return d


def attempt_login(session: requests.Session, url: str, username: str, password: str, run_id: str, dry_run: bool = False):
    remote_ip = "127.0.0.1"  # simulator-origin placeholder

    if dry_run:
        # Log a simulated attempt without sending a request
        insert_event(
            run_id, username, password, remote_ip,
            status="dry_run", http_code=0,
            message="dry run - no request sent",
            target_url=url
        )
        return {"username": username, "status": "dry_run"}

    try:
        resp = session.post(url, json={"username": username, "password": password}, timeout=5)
        # Try to parse JSON response
        try:
            j = resp.json()
            status = j.get("status", "unknown")
            msg = j.get("message", "") or j.get("error", "")
        except Exception:
            status = "http"
            msg = (resp.text or "")[:200]

        # Log the result
        insert_event(
            run_id, username, password, remote_ip,
            status=status, http_code=resp.status_code,
            message=msg,
            target_url=url
        )
        return {"username": username, "status": status, "code": resp.status_code}

    except Exception as e:
        # Log unexpected exceptions (timeouts, connection errors, etc.)
        insert_event(
            run_id, username, password, remote_ip,
            status="error", http_code=0,
            message=str(e),
            target_url=url
        )
        return {"username": username, "status": "error", "error": str(e)}


def run_simulation(
    target_url: str,
    creds: dict,
    concurrency: int,
    attempts_per_user: int,
    run_id: str,
    dry_run: bool = False,
    delay_between_attempts: float = 0.05
):
   

    if not is_safe_target(target_url):
        raise RuntimeError(
            "Target not allowed. For safety, only localhost is allowed unless CAST_BF_ALLOW_EXTERNAL=true."
        )

    init_db()

    results = []
    with ThreadPoolExecutor(max_workers=concurrency) as exe:
        with requests.Session() as session:
            futures = []
            # Schedule all login attempts
            for username, passwords in creds.items():
                for attempt_idx in range(attempts_per_user):
                    pwd = passwords[attempt_idx % len(passwords)]
                    futures.append(exe.submit(attempt_login, session, target_url, username, pwd, run_id, dry_run))
                    time.sleep(delay_between_attempts)

# Collect results as they complete
            for fut in as_completed(futures):
                results.append(fut.result())

    return results


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--creds", required=True, help="Credentials file: user:pw1,pw2")
    parser.add_argument("--run-id", default=str(uuid.uuid4()), help="Run id")
    parser.add_argument("--concurrency", type=int, default=5)
    parser.add_argument("--attempts-per-user", type=int, default=10)
    parser.add_argument("--target", default=DEFAULT_TARGET)
    parser.add_argument("--dry-run", action="store_true", help="Log telemetry but do not send HTTP requests")
    parser.add_argument("--delay", type=float, default=0.05, help="Delay between spawned attempts (seconds)")
    args = parser.parse_args()

    print("RUN ID:", args.run_id)
    print("Target:", args.target)

    if not is_safe_target(args.target):
        print("ERROR: target is not localhost. Aborting for safety.")
        raise SystemExit(1)

    creds = load_credentials_from_file(args.creds)
    if not creds:
        print("ERROR: No valid credentials parsed from file.")
        raise SystemExit(1)

    results = run_simulation(
        args.target, creds,
        concurrency=args.concurrency,
        attempts_per_user=args.attempts_per_user,
        run_id=args.run_id,
        dry_run=args.dry_run,
        delay_between_attempts=args.delay
    )

    summary = {}
    for r in results:
        st = r.get("status", "unknown")
        summary[st] = summary.get(st, 0) + 1

    print("Summary:", summary)


if __name__ == "__main__":
    main()
