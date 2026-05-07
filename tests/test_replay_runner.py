import socket
import threading
import time

import pytest
import requests
from werkzeug.serving import make_server

from castrange import config
from castrange.app import create_app
from Attacks.modules.replay import ReplayRunner, make_replay_packet
from TargetServer import tserver


def _free_port():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


@pytest.fixture
def target_client():
    tserver.app.testing = True
    with tserver.app.test_client() as client:
        client.post("/reset")
        yield client
        client.post("/reset")


@pytest.fixture
def target_url():
    port = _free_port()
    server = make_server("127.0.0.1", port, tserver.app, threaded=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    url = f"http://127.0.0.1:{port}"

    deadline = time.time() + 5
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                break
        except OSError:
            time.sleep(0.05)
    else:
        server.shutdown()
        thread.join(timeout=2)
        pytest.fail("target server did not become ready")

    try:
        yield url
    finally:
        server.shutdown()
        thread.join(timeout=2)


@pytest.fixture
def castrange_url(tmp_path):
    config.DB_PATH = str(tmp_path / "castrange.db")
    config.TOKEN_FILE = str(tmp_path / "castrange.token")
    config.state.update(level="easy", defense_level="off")

    app = create_app()
    port = _free_port()
    server = make_server("127.0.0.1", port, app, threaded=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    url = f"http://127.0.0.1:{port}"
    deadline = time.time() + 5
    while time.time() < deadline:
        try:
            response = requests.get(f"{url}/_range/health", timeout=0.5)
            if response.status_code == 200:
                break
        except Exception:
            time.sleep(0.05)
    else:
        server.shutdown()
        thread.join(timeout=2)
        pytest.fail("castrange did not become ready")

    try:
        yield url, config.state.token
    finally:
        server.shutdown()
        thread.join(timeout=2)


def test_replay_endpoint_accepts_duplicate_when_unprotected(target_client):
    packet = make_replay_packet("cast-lab-transfer=10")

    first = target_client.get("/replay/verify", query_string=packet)
    replay = target_client.get("/replay/verify", query_string=packet)

    assert first.status_code == 200
    assert first.get_json()["accepted"] is True
    assert first.get_json()["vulnerability"] is False

    body = replay.get_json()
    assert replay.status_code == 200
    assert body["accepted"] is True
    assert body["attack_detected"] is True
    assert body["vulnerability"] is True
    assert body["server_behavior"]["nonce_request_count"] == 2


def test_replay_endpoint_rejects_duplicate_when_protected(target_client):
    packet = make_replay_packet("cast-lab-transfer=10")
    packet["protected"] = "true"

    first = target_client.get("/replay/verify", query_string=packet)
    replay = target_client.get("/replay/verify", query_string=packet)

    assert first.status_code == 200
    assert first.get_json()["accepted"] is True

    body = replay.get_json()
    assert replay.status_code == 409
    assert body["accepted"] is False
    assert body["attack_detected"] is True
    assert body["vulnerability"] is False


def test_replay_runner_sends_real_http_and_reports_vulnerability(target_url):
    runner = ReplayRunner(
        attempts=3,
        rate_limit=20.0,
        dry_run=False,
        target={"ip_or_url": target_url, "environment": "lab"},
        safety_engine=None,
    )

    result = runner.run()

    assert result.mode == "real_http"
    assert result.sample_count == 3
    assert result.success_count == 2
    assert result.replay_summary["vulnerable"] is True
    assert result.replay_summary["accepted_replays"] == 2
    assert any(f.category == "initial_request" and f.status == 200 for f in result.findings)
    assert all(f.method == "GET" for f in result.findings)


def test_dispatcher_routes_replay_to_live_runner(target_url):
    from Attacks.ModuleRunners import run_generic_module_simulation

    out = run_generic_module_simulation(
        "replay",
        attempts=3,
        rate_limit=20.0,
        dry_run=False,
        target={"ip_or_url": target_url, "environment": "lab"},
        safety_engine=None,
    )

    assert out["module_id"] == "replay"
    assert out["mode"] == "real_http"
    assert out["sample_count"] == 3
    assert out["success_count"] == 2
    assert out["replay_summary"]["vulnerable"] is True
    assert out["findings"]


def test_replay_runner_works_against_castrange(castrange_url):
    url, token = castrange_url
    runner = ReplayRunner(
        attempts=3,
        rate_limit=20.0,
        dry_run=False,
        target={
            "ip_or_url": url,
            "environment": "lab",
            "metadata": {"range_token": token},
        },
        safety_engine=None,
    )

    result = runner.run()

    assert result.mode == "real_http"
    assert result.replay_summary["endpoint"] == f"{url}/replay/verify"
    assert result.replay_summary["vulnerable"] is True
    assert result.replay_summary["accepted_replays"] == 2
    assert result.target_metrics is not None
    assert result.target_metrics["triggered"] >= 2
    assert result.target_metrics["success_rate_pct"] > 0
