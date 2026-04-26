import socket
import threading
import time

import pytest
import requests
from werkzeug.serving import make_server

from castrange import config
from castrange.app import create_app


def _free_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


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
            r = requests.get(f"{url}/_range/health", timeout=0.5)
            if r.status_code == 200:
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
        try:
            server.shutdown()
        except Exception:
            pass
        thread.join(timeout=2)


def _set_defense(url, token, level):
    requests.post(f"{url}/_range/config?token={token}",
                  json={"defense_level": level}, timeout=2)


def _reset_log(url, token):
    requests.post(f"{url}/_range/reset?token={token}", timeout=2)


# ---- target guard -----------------------------------------------------------

def test_target_guard_refuses_public_host():
    from Attacks.modules.sqli import SqliRunner
    target = {"ip_or_url": "http://example.com/login"}
    runner = SqliRunner(attempts=5, rate_limit=2.0, dry_run=False,
                        target=target, safety_engine=None)
    result = runner.run()
    assert result.mode == "refused"
    assert "guard" in result.guidance.lower()
    assert result.sample_count == 0


def test_target_guard_allows_explicit_allowlist():
    from Attacks.modules import target_guard
    host = target_guard.assert_permitted(
        "http://example.com/login",
        target={"scope": {"allowed_hosts": ["example.com"]}},
    )
    assert host == "example.com"


def test_target_guard_allows_loopback():
    from Attacks.modules import target_guard
    host = target_guard.assert_permitted("http://127.0.0.1:5002/login")
    assert host == "127.0.0.1"


# ---- end-to-end against castrange -------------------------------------------

def test_sqli_runner_finds_vulns_at_easy(castrange_url):
    from Attacks.modules.sqli import SqliRunner
    url, token = castrange_url
    _reset_log(url, token)

    target = {"ip_or_url": url, "metadata": {"range_token": token}}
    runner = SqliRunner(attempts=12, rate_limit=8.0, dry_run=False,
                        target=target, safety_engine=None)
    result = runner.run()

    assert result.mode == "simulated_active"
    assert result.sample_count > 0
    assert result.success_count > 0, f"expected SQLi findings, got: {[f.evidence for f in result.findings]}"
    assert result.success_rate_percent > 0
    assert result.avg_latency_ms >= 0
    assert result.target_metrics is not None
    assert result.target_metrics["triggered"] > 0
    # No defense, observed detection should be 0 or near it
    assert result.detection_rate_observed_percent < 20


def test_sqli_runner_observes_waf_detection(castrange_url):
    from Attacks.modules.sqli import SqliRunner
    url, token = castrange_url
    _reset_log(url, token)
    _set_defense(url, token, "basic")
    try:
        target = {"ip_or_url": url, "metadata": {"range_token": token}}
        runner = SqliRunner(attempts=12, rate_limit=8.0, dry_run=False,
                            target=target, safety_engine=None)
        result = runner.run()

        assert result.sample_count > 0
        assert result.detection_rate_observed_percent > 0, \
            f"expected WAF 403s, status_counts={result.status_counts}"
        # Ground-truth metrics should also report detections
        assert result.target_metrics is not None
        assert result.target_metrics["detected"] > 0
    finally:
        _set_defense(url, token, "off")


def test_sqli_runner_finds_login_bypass(castrange_url):
    from Attacks.modules.sqli import SqliRunner
    url, token = castrange_url
    _reset_log(url, token)

    target = {
        "ip_or_url": f"{url}/login",
        "metadata": {"range_token": token},
    }
    runner = SqliRunner(attempts=6, rate_limit=8.0, dry_run=False,
                        target=target, safety_engine=None)
    result = runner.run()

    bypass = [f for f in result.findings if f.category == "auth_bypass" and f.success]
    assert bypass, f"expected an auth_bypass success, findings={[f.evidence for f in result.findings]}"
    assert any("/dashboard" in f.evidence for f in bypass)


# ---- dispatcher integration -------------------------------------------------

def test_dispatcher_routes_sqli_to_runner(castrange_url):
    from Attacks.ModuleRunners import run_generic_module_simulation
    url, token = castrange_url
    _reset_log(url, token)

    target = {"ip_or_url": url, "metadata": {"range_token": token}}
    out = run_generic_module_simulation(
        "sqli", attempts=8, rate_limit=8.0, dry_run=False,
        target=target, safety_engine=None,
    )

    # Schema is a strict superset of what the legacy synthetic runner returned
    for field in ("mode", "started_at", "completed_at", "sample_count",
                  "avg_throughput_kbps", "avg_detectability_score",
                  "guidance", "status_counts", "action_events"):
        assert field in out, f"missing field {field}"

    # Plus the new measurement fields
    assert out["module_id"] == "sqli"
    assert out["sample_count"] > 0
    assert out["success_count"] > 0
    assert out["success_rate_percent"] > 0
    assert "detection_rate_observed_percent" in out
    assert out["target_metrics"] is not None
    assert out["target_metrics"]["triggered"] > 0


def test_dispatcher_falls_back_to_legacy_for_unknown(castrange_url):
    """Unknown module_ids still hit the legacy synthetic path."""
    from Attacks.ModuleRunners import run_generic_module_simulation
    url, token = castrange_url

    target = {"ip_or_url": url, "metadata": {"range_token": token}}
    out = run_generic_module_simulation(
        "xss", attempts=4, rate_limit=2.0, dry_run=True,
        target=target, safety_engine=None,
    )
    # legacy synthetic shape — no real HTTP, so module_id field is absent
    assert "module_label" in out
    assert "module_id" not in out  # legacy path never set this


def test_sqli_runner_caps_attempts():
    from Attacks.modules.sqli import SqliRunner
    runner = SqliRunner(attempts=9999, rate_limit=2.0, dry_run=True,
                        target={"ip_or_url": "http://127.0.0.1:9"},
                        safety_engine=None)
    assert runner.attempts == 50  # MAX_ATTEMPTS cap
