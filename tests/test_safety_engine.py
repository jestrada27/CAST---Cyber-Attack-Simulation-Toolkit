from Attacks.SafetyEnforcementEngine import SafetyEnforcementEngine, normalize_safety_settings


def makeEngine(module_id="brute force", target_overrides=None, settings_overrides=None):
    target = {
        "name": "Local Lab",
        "ip_or_url": "http://127.0.0.1:5001/login",
        "consent_status": "approved",
        "environment": "lab",
        "allowed_services": ["auth", "http"],
        "approved_users": ["tester"],
    }
    if target_overrides:
        target.update(target_overrides)

    merged = {"authorization": {"experiment_approved": True}}
    for k, v in (settings_overrides or {}).items():
        if k in merged and isinstance(merged[k], dict) and isinstance(v, dict):
            merged[k] = {**merged[k], **v}
        else:
            merged[k] = v
    base_settings = normalize_safety_settings(
        merged,
        module_id=module_id,
        target=target,
        owner_username="tester",
    )
    experiment = {"_id": "exp-1", "owner": "tester", "module_id": module_id}
    user = {"username": "tester"}
    return SafetyEnforcementEngine(experiment=experiment, target=target, user=user, settings=base_settings)


def testauthorizationBlocksUnapprovedTarget():
    engine = makeEngine(target_overrides={"consent_status": "pending"})
    decision = engine.authorize_start()
    assert decision["decision"] == "blocked"
    assert "consent" in decision["message"].lower()


def testscopeRestrictionBlocksExternalHost():
    engine = makeEngine()
    engine.authorize_start()
    decision = engine.evaluate_action(
        "login_attempt",
        {
            "target_url": "http://10.10.10.10/login",
            "target_ip": "10.10.10.10",
            "port": 80,
            "account": "alice",
            "service": "auth",
        },
    )
    assert decision["decision"] == "blocked"
    assert "scope" in decision["event"]["code"]


def testrateLimitingThrottlesExcessiveRequests():
    engine = makeEngine(settings_overrides={"rate_limit": {"login_attempts_per_minute": 1}})
    engine.authorize_start()

    first = engine.evaluate_action(
        "login_attempt",
        {
            "target_url": "http://127.0.0.1:5001/login",
            "target_ip": "127.0.0.1",
            "port": 5001,
            "account": "alice",
            "service": "auth",
        },
    )
    second = engine.evaluate_action(
        "login_attempt",
        {
            "target_url": "http://127.0.0.1:5001/login",
            "target_ip": "127.0.0.1",
            "port": 5001,
            "account": "alice",
            "service": "auth",
        },
    )

    assert first["decision"] == "allowed"
    assert second["decision"] == "throttled"


def testsqliProbeOnlyBlocksDestructivePayloads():
    engine = makeEngine(module_id="sqli")
    engine.authorize_start()

    decision = engine.evaluate_action(
        "payload",
        {
            "target_url": "http://127.0.0.1:5001/search",
            "target_ip": "127.0.0.1",
            "port": 5001,
            "service": "http",
            "payload": "'; DROP TABLE users; --",
        },
    )

    assert decision["decision"] == "blocked"
    assert decision["event"]["code"] == "sqli_probe_only"


def testmonitoringCanTriggerKillSwitch():
    engine = makeEngine(settings_overrides={"monitoring": {"max_detectability_score": 20}})
    engine.authorize_start()

    decision = engine.monitor_activity(
        {
            "detectability_score": 55,
            "bandwidth_kbps": 5,
            "packet_count": 1,
            "unexpected_targets": 0,
        }
    )

    assert decision["decision"] == "terminated"
    assert engine.kill_switch_engaged is True
