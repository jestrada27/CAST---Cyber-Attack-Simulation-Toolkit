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


# ---- exposed information ---------------------------------------------------

def test_exposed_records_and_hashes_extracted(castrange_url):
    from Attacks.modules.sqli import SqliRunner
    url, token = castrange_url
    _reset_log(url, token)

    target = {"ip_or_url": url, "metadata": {"range_token": token}}
    runner = SqliRunner(attempts=12, rate_limit=8.0, dry_run=False,
                        target=target, safety_engine=None)
    result = runner.run()

    es = result.exposed_summary
    assert es["records_extracted"] > 0, f"no records extracted; findings={result.findings}"
    assert es["unique_password_hashes"] >= 4, \
        f"expected the four seeded MD5 hashes; got {es['sample_hashes']}"
    # Known seed: admin's password is "admin" -> 21232f297a57a5a743894a0e4a801fc3
    assert "21232f297a57a5a743894a0e4a801fc3" in es["sample_hashes"]
    assert es["unique_emails"] >= 1
    assert any("@castrange.local" in e for e in es["sample_emails"])


def test_exposed_data_per_finding(castrange_url):
    from Attacks.modules.sqli import SqliRunner
    url, token = castrange_url
    _reset_log(url, token)

    target = {"ip_or_url": url, "metadata": {"range_token": token}}
    runner = SqliRunner(attempts=12, rate_limit=8.0, dry_run=False,
                        target=target, safety_engine=None)
    result = runner.run()

    union_findings = [f for f in result.findings
                      if f.category == "union" and f.success]
    assert union_findings, "expected at least one successful UNION finding"
    sample = union_findings[0]
    assert "records" in sample.exposed_data
    assert sample.exposed_data["records"], "records list should be non-empty"


def test_exposed_summary_in_to_dict(castrange_url):
    from Attacks.modules.sqli import SqliRunner
    url, token = castrange_url
    _reset_log(url, token)

    target = {"ip_or_url": url, "metadata": {"range_token": token}}
    runner = SqliRunner(attempts=8, rate_limit=8.0, dry_run=False,
                        target=target, safety_engine=None)
    out = runner.run().to_dict(safety_engine=None)

    assert "exposed_summary" in out
    assert isinstance(out["exposed_summary"], dict)
    assert out["exposed_summary"]["records_extracted"] > 0
    # findings in dict form should also carry exposed_data on success
    successful = [f for f in out["findings"] if f["success"] and f["category"] == "union"]
    assert successful and successful[0]["exposed_data"].get("records")


def test_auth_bypass_exposes_redirect(castrange_url):
    from Attacks.modules.sqli import SqliRunner
    url, token = castrange_url
    _reset_log(url, token)

    target = {"ip_or_url": f"{url}/login", "metadata": {"range_token": token}}
    runner = SqliRunner(attempts=4, rate_limit=8.0, dry_run=False,
                        target=target, safety_engine=None)
    result = runner.run()

    bypass = [f for f in result.findings
              if f.category == "auth_bypass" and f.success]
    assert bypass, f"expected auth_bypass, findings={result.findings}"
    assert "/dashboard" in bypass[0].exposed_data.get("redirect_to", "")
    assert result.exposed_summary["auth_bypasses"] >= 1


def test_waf_blocks_prevent_exposure(castrange_url):
    from Attacks.modules.sqli import SqliRunner
    url, token = castrange_url
    _reset_log(url, token)
    _set_defense(url, token, "basic")
    try:
        target = {"ip_or_url": url, "metadata": {"range_token": token}}
        runner = SqliRunner(attempts=12, rate_limit=8.0, dry_run=False,
                            target=target, safety_engine=None)
        result = runner.run()
        # WAF should suppress most leakage at the basic level
        assert result.exposed_summary["records_extracted"] == 0
        assert result.exposed_summary["unique_password_hashes"] == 0
    finally:
        _set_defense(url, token, "off")


def test_guidance_mentions_exposure(castrange_url):
    from Attacks.modules.sqli import SqliRunner
    url, token = castrange_url
    _reset_log(url, token)

    target = {"ip_or_url": url, "metadata": {"range_token": token}}
    runner = SqliRunner(attempts=10, rate_limit=8.0, dry_run=False,
                        target=target, safety_engine=None)
    result = runner.run()
    assert "Exposed:" in result.guidance, f"guidance was: {result.guidance!r}"
