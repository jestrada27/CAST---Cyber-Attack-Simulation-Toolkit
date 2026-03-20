# cast/modules/bruteforce/tests/test_bruteforce.py
import subprocess, time, os, signal, uuid
from bruteforce_simulator import run_simulation, load_credentials_from_file
from telemetry_db import init_db

def start_mock_server():
    p = subprocess.Popen(["python","mock_auth_server.py"], cwd=os.path.dirname(__file__) or ".", stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    time.sleep(1.0)
    return p

def stop_mock_server(p):
    p.terminate()
    try:
        p.wait(timeout=2)
    except:
        p.kill()

def test_dry_run(tmp_path):
    run_id = "test-dry-" + str(uuid.uuid4())
    creds_file = tmp_path / "creds.txt"
    creds_file.write_text("alice:password123,wrongpass\nbob:abc,123")
    init_db()
    creds = load_credentials_from_file(str(creds_file))
    results = run_simulation("http://127.0.0.1:5001/login", creds, concurrency=2, attempts_per_user=2, run_id=run_id, dry_run=True)
    assert len(results) == 4
    assert all(r["status"]=="dry_run" for r in results)

def test_live_against_mock(tmp_path):
    p = start_mock_server()
    try:
        run_id = "test-live-" + str(uuid.uuid4())
        creds_file = tmp_path / "creds2.txt"
        creds_file.write_text("alice:wrong1,wrong2,password123")
        init_db()
        creds = load_credentials_from_file(str(creds_file))
        results = run_simulation("http://127.0.0.1:5001/login", creds, concurrency=1, attempts_per_user=3, run_id=run_id, dry_run=False)
        statuses = [r.get("status") for r in results]
        assert "ok" in statuses or "failed" in statuses
    finally:
        stop_mock_server(p)
