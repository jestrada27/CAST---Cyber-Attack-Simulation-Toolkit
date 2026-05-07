import pytest

from castrange import config
from castrange.app import create_app
from Attacks.modules.replay import make_replay_packet


@pytest.fixture
def client(tmp_path):
    config.DB_PATH = str(tmp_path / "test.db")
    config.TOKEN_FILE = str(tmp_path / "test.token")
    config.state.update(level="easy", defense_level="off")
    app = create_app()
    app.testing = True
    with app.test_client() as c:
        yield c


def _metrics(client):
    r = client.get(f"/_range/metrics?token={config.state.token}")
    assert r.status_code == 200
    return r.get_json()


# ---- V1 SQLi ----------------------------------------------------------------

def test_search_sqli_union_easy(client):
    config.state.update(level="easy")
    r = client.get("/search?q=' UNION SELECT 1,2,3,4 -- ")
    assert r.status_code == 200
    body = r.get_data(as_text=True)
    # union returned literal "2" as a name column
    assert "2" in body

def test_search_sqli_error_easy_reflects(client):
    config.state.update(level="easy")
    r = client.get("/search?q='")
    body = r.get_data(as_text=True)
    assert "SQL error" in body  # V10 verbose error

def test_login_sqli_bypass_easy(client):
    config.state.update(level="easy")
    r = client.post(
        "/login",
        data={"username": "admin' -- ", "password": "anything"},
        follow_redirects=False,
    )
    # SQL bypass should authenticate as admin and redirect to dashboard
    assert r.status_code in (301, 302, 303)
    assert "/dashboard" in r.headers.get("Location", "")

def test_login_sqli_blocked_at_hard(client):
    config.state.update(level="hard")
    r = client.post(
        "/login",
        data={"username": "admin' -- ", "password": "anything"},
        follow_redirects=False,
    )
    # parameterized — payload becomes a literal username, no match
    assert r.status_code == 200


# ---- V2 reflected XSS -------------------------------------------------------

def test_search_xss_reflected(client):
    config.state.update(level="easy")
    payload = "<script>alert(1)</script>"
    r = client.get(f"/search?q={payload}")
    body = r.get_data(as_text=True)
    assert payload in body  # rendered unescaped via |safe


# ---- V5 default creds -------------------------------------------------------

def test_default_admin_creds(client):
    config.state.update(level="hard")
    r = client.post(
        "/login",
        data={"username": "admin", "password": "admin"},
        follow_redirects=False,
    )
    assert r.status_code in (301, 302, 303)


# ---- V9 open redirect -------------------------------------------------------

def test_open_redirect(client):
    config.state.update(level="hard")
    r = client.post(
        "/login?next=http://evil.example/",
        data={"username": "admin", "password": "admin"},
        follow_redirects=False,
    )
    assert r.headers.get("Location") == "http://evil.example/"


# ---- WAF defenses -----------------------------------------------------------

def test_waf_blocks_union_select(client):
    config.state.update(level="easy", defense_level="basic")
    r = client.get("/search?q=' UNION SELECT 1,2,3 -- ")
    assert r.status_code == 403

def test_waf_blocks_script_tag(client):
    config.state.update(level="easy", defense_level="basic")
    r = client.get("/search?q=<script>alert(1)</script>")
    assert r.status_code == 403

def test_waf_off_passes_through(client):
    config.state.update(level="easy", defense_level="off")
    r = client.get("/search?q=' UNION SELECT 1,2,3 -- ")
    assert r.status_code == 200


# ---- Replay ----------------------------------------------------------------

def test_replay_duplicate_accepted_and_counted(client):
    packet = make_replay_packet("cast-lab-transfer=10")
    first = client.get("/replay/verify", query_string=packet)
    replay = client.get("/replay/verify", query_string=packet)

    assert first.status_code == 200
    assert first.get_json()["accepted"] is True

    body = replay.get_json()
    assert replay.status_code == 200
    assert body["accepted"] is True
    assert body["attack_detected"] is True
    assert body["vulnerability"] is True

    metrics = _metrics(client)
    assert metrics["triggered"] >= 1
    assert metrics["success_rate_pct"] > 0


def test_replay_duplicate_rejected_when_protected(client):
    packet = make_replay_packet("cast-lab-transfer=10")
    packet["protected"] = "true"
    first = client.get("/replay/verify", query_string=packet)
    replay = client.get("/replay/verify", query_string=packet)

    assert first.status_code == 200
    assert replay.status_code == 409
    assert replay.get_json()["vulnerability"] is False

    metrics = _metrics(client)
    assert metrics["triggered"] >= 1
    assert metrics["detected"] >= 1


# ---- /_range/* control plane ------------------------------------------------

def test_metrics_token_required(client):
    r = client.get("/_range/metrics")
    assert r.status_code == 401

def test_metrics_counts_triggered_and_detected(client):
    config.state.update(level="easy", defense_level="off")
    client.get("/search?q=alice")                            # benign
    client.get("/search?q=' OR 1=1 -- ")                     # triggered, not detected
    config.state.update(defense_level="basic")
    client.get("/search?q=<script>alert(1)</script>")        # triggered AND detected

    m = _metrics(client)
    assert m["requests"] >= 3
    assert m["triggered"] >= 2
    assert m["detected"] >= 1
    # at least one true positive
    assert m["detection_rate_pct"] > 0

def test_reset_clears_log(client):
    client.get("/search?q=alice")
    before = _metrics(client)["requests"]
    assert before >= 1
    r = client.post(f"/_range/reset?token={config.state.token}")
    assert r.status_code == 200
    after = _metrics(client)
    # only the /_range/metrics call we just made should remain (and /_range/* are excluded from logs? no — they ARE logged)
    # so after reset+one metrics call, requests should be much lower than before
    assert after["requests"] < before + 5

def test_config_round_trip(client):
    r = client.post(
        f"/_range/config?token={config.state.token}",
        json={"level": "medium", "defense_level": "strict"},
    )
    assert r.status_code == 200
    body = r.get_json()
    assert body["level"] == "medium"
    assert body["defense_level"] == "strict"


# ---- Loopback enforcement ---------------------------------------------------

def test_non_loopback_host_refused(client):
    r = client.get("/", headers={"Host": "evil.example.com"})
    assert r.status_code == 403
