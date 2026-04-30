from datetime import datetime
import math
import random
import time
import uuid
from urllib.parse import urlparse

from Attacks.SafetyEnforcementEngine import parse_target_host
from Attacks.modules.sqli import SqliRunner

MODULE_REGISTRY = {
    "sqli": SqliRunner,
}


def _bounded(value, low, high):
    return max(low, min(high, value))


def _risk_band(score):
    if score >= 70:
        return "High"
    if score >= 40:
        return "Moderate"
    return "Low"


def _extract_port(url_or_host, default_port):
    if not url_or_host:
        return default_port
    raw = str(url_or_host).strip()
    if "://" not in raw:
        raw = f"http://{raw}"
    parsed = urlparse(raw)
    if parsed.port:
        return parsed.port
    if parsed.scheme == "https":
        return 443
    return default_port


def _load_bruteforce_credentials():
    try:
        from bruteforce.bruteforce_simulator import load_credentials_from_file

        creds = load_credentials_from_file("bruteforce/creds.txt")
        if creds:
            return creds
    except Exception:
        pass
    return {
        "alice": ["password123", "wrongpass"],
        "bob": ["admin123", "letmein"],
        "charlie": ["summer2025", "Password1!"],
    }


def _handle_safety_decision(decision, event_log, blocked_counter):
    verdict = (decision or {}).get("decision")
    if verdict in {"blocked", "throttled", "terminated"}:
        event_log.append(
            {
                "decision": verdict,
                "message": (decision or {}).get("message", ""),
            }
        )
        blocked_counter[verdict] = blocked_counter.get(verdict, 0) + 1
    return verdict


def _build_safety_fields(safety_engine):
    if not safety_engine:
        return {}
    report = safety_engine.build_report()
    return {
        "safety_report": report,
        "user_alerts": report.get("user_alerts", []),
        "safety_summary": report.get("summary", "Completed"),
    }


def run_bruteforce_experiment(attempts, rate_limit, dry_run=True, target=None, safety_engine=None):
    """
    Brute-force experiment with safety-engine gating per attempt.
    Returns structured telemetry compatible with the experiment details page.
    """
    started_at = datetime.utcnow()
    attempts_per_user = int(_bounded(int(attempts), 1, 10))
    base_rate_limit = _bounded(float(rate_limit), 0.1, 10.0)
    concurrency = int(_bounded(math.ceil(base_rate_limit), 1, 10))
    delay = round(_bounded(0.15 / max(base_rate_limit, 0.1), 0.02, 0.25), 3)
    run_id = str(uuid.uuid4())
    creds = _load_bruteforce_credentials()
    target_url = (target or {}).get("ip_or_url") or "http://127.0.0.1:5001/login"
    target_host = parse_target_host(target_url)
    port = _extract_port(target_url, 80)

    status_counts = {}
    events = []
    sample_results = []
    executed_attempts = 0
    success_count = 0
    login_budget = max(1, min(concurrency * attempts_per_user, len(creds) * attempts_per_user))
    sample_index = 0

    for username, passwords in creds.items():
        for attempt_idx in range(attempts_per_user):
            if executed_attempts >= login_budget:
                break

            password = passwords[attempt_idx % len(passwords)]
            metadata = {
                "target_url": target_url,
                "target_ip": target_host,
                "port": port,
                "account": username,
                "service": "auth",
            }

            decision = safety_engine.evaluate_action("login_attempt", metadata) if safety_engine else {"decision": "allowed"}
            verdict = _handle_safety_decision(decision, events, status_counts)
            if verdict == "blocked":
                continue
            if verdict == "throttled":
                time.sleep(min(delay * 2, 0.25))
                continue
            if verdict == "terminated":
                break

            executed_attempts += 1
            simulated_status = "dry_run" if dry_run else "failed"
            if not dry_run and any(token in password.lower() for token in ("password", "letmein", "admin")) and attempt_idx == attempts_per_user - 1:
                simulated_status = "success"
                success_count += 1

            status_counts[simulated_status] = status_counts.get(simulated_status, 0) + 1
            detectability = round(_bounded(18 + (attempt_idx * 7) + (base_rate_limit * 6), 1, 100), 2)
            throughput = round(2.5 + (base_rate_limit * 1.3) + random.uniform(0.05, 0.5), 3)

            sample_index += 1
            sample_results.append({
                "trial": sample_index,
                "username": username,
                "status": simulated_status,
                "throughput_kbps": throughput,
                "detectability_score": detectability,
                "risk_band": _risk_band(detectability),
            })

            monitor = safety_engine.monitor_activity(
                {
                    "detectability_score": detectability,
                    "bandwidth_kbps": throughput,
                    "packet_count": 1,
                    "unexpected_targets": 0,
                }
            ) if safety_engine else {"decision": "allowed"}

            monitor_verdict = _handle_safety_decision(monitor, events, status_counts)
            if monitor_verdict == "throttled":
                time.sleep(min(delay * 2, 0.25))
            if monitor_verdict == "terminated":
                break

            time.sleep(delay)
        if status_counts.get("terminated"):
            break

    completed_at = datetime.utcnow()
    total_attempts = sum(count for key, count in status_counts.items() if key in {"dry_run", "failed", "success"})
    success_rate = round((success_count / total_attempts) * 100.0, 2) if total_attempts else 0.0

    avg_throughput = round(
        sum(sample["throughput_kbps"] for sample in sample_results) / len(sample_results),
        3
    ) if sample_results else 0.0

    avg_detectability = round(
        sum(sample["detectability_score"] for sample in sample_results) / len(sample_results),
        2
    ) if sample_results else 0.0

    if status_counts.get("terminated"):
        guidance = "Safety engine terminated the brute-force simulation. Review the audit trail before retrying."
    elif status_counts.get("throttled"):
        guidance = "Brute-force attempts were throttled. Reduce login velocity or narrow account scope."
    elif success_rate > 5 and avg_detectability < 45:
        guidance = "Credential abuse simulation showed measurable effectiveness with relatively low noise. Strengthen password policy and lockout controls."
    elif success_rate > 5:
        guidance = "Credential policy appears weak. Increase account lockout and password complexity."
    elif avg_detectability >= 70:
        guidance = "Brute force activity is highly detectable in this run. Reduce request rate and keep testing in dry-run mode while tuning."
    else:
        guidance = "Low compromise rate in this run. Continue monitoring authentication failures and alert thresholds."

    return {
        "mode": "dry_run" if dry_run else "simulated_active",
        "started_at": started_at,
        "completed_at": completed_at,
        "sample_count": total_attempts,
        "avg_throughput_kbps": avg_throughput,
        "avg_detectability_score": avg_detectability,
        "guidance": guidance,
        "run_id": run_id,
        "target_url": target_url,
        "telemetry_mode": "safety_enforced_simulation",
        "status_counts": status_counts,
        "success_rate_percent": success_rate,
        "risk_band": _risk_band(avg_detectability),
        "samples": sample_results,
        "action_events": events,
        **_build_safety_fields(safety_engine),
    }


def run_generic_module_simulation(module_id, attempts, rate_limit, dry_run=True, target=None, safety_engine=None):
    runner_cls = MODULE_REGISTRY.get(module_id)
    if runner_cls is not None:
        runner = runner_cls(attempts, rate_limit, dry_run, target, safety_engine)
        result = runner.run()
        return result.to_dict(safety_engine=safety_engine)

    started_at = datetime.utcnow()
    sample_count = int(_bounded(int(attempts), 1, 50))
    base_rate = _bounded(float(rate_limit), 0.1, 10.0)
    stealth_bias = 1.0 if dry_run else 1.15
    target_url = (target or {}).get("ip_or_url") or "http://127.0.0.1:5001"
    target_host = parse_target_host(target_url)
    port = _extract_port(target_url, 80)

    by_module = {
        "sqli": {
            "throughput_factor": 1.8,
            "detection_factor": 2.6,
            "label": "SQL Injection",
            "payloads": ["' OR 1=1 -- ", "' UNION SELECT NULL-- ", "' AND 1=0 -- "],
            "service": "http",
        },
        "xss": {
            "throughput_factor": 2.2,
            "detection_factor": 2.1,
            "label": "XSS",
            "payloads": ["<script>alert(1)</script>", "<svg onload=alert(1)>", "<img src=x onerror=alert(1)>"],
            "service": "http",
        },
        "replay": {
            "throughput_factor": 2.8,
            "detection_factor": 1.9,
            "label": "Replay",
            "payloads": ["GET /health", "GET /status", "GET /profile"],
            "service": "api",
        },
    }
    cfg = by_module.get(module_id, {"throughput_factor": 1.5, "detection_factor": 2.0, "label": module_id.upper(), "payloads": ["sample"], "service": "http"})

    samples = []
    avg_detectability_total = 0.0
    avg_throughput_total = 0.0
    executed_samples = 0
    action_events = []
    decision_counts = {}

    for idx in range(sample_count):
        payload = cfg["payloads"][idx % len(cfg["payloads"])]
        metadata = {
            "target_url": target_url,
            "target_ip": target_host,
            "port": port,
            "service": cfg["service"],
            "payload": payload,
            "method": "GET",
        }

        decision = safety_engine.evaluate_action("payload", metadata) if safety_engine else {"decision": "allowed"}
        verdict = _handle_safety_decision(decision, action_events, decision_counts)
        if verdict == "blocked":
            continue
        if verdict == "throttled":
            time.sleep(0.1)
            continue
        if verdict == "terminated":
            break

        throughput = round((base_rate * cfg["throughput_factor"] * stealth_bias) + random.uniform(0.05, 0.5), 3)
        detectability = round(_bounded((base_rate * cfg["detection_factor"] * 10) + random.uniform(4, 14), 1, 100), 2)
        avg_throughput_total += throughput
        avg_detectability_total += detectability
        executed_samples += 1

        samples.append({
            "trial": executed_samples,
            "throughput_kbps": throughput,
            "detectability_score": detectability,
            "risk_band": _risk_band(detectability),
        })

        monitor = safety_engine.monitor_activity(
            {
                "detectability_score": detectability,
                "bandwidth_kbps": throughput,
                "packet_count": max(1, int(base_rate * 2)),
                "unexpected_targets": 0,
            }
        ) if safety_engine else {"decision": "allowed"}

        monitor_verdict = _handle_safety_decision(monitor, action_events, decision_counts)
        if monitor_verdict == "throttled":
            time.sleep(0.1)
        if monitor_verdict == "terminated":
            break

    avg_throughput = round(avg_throughput_total / executed_samples, 3) if executed_samples else 0.0
    avg_detectability = round(avg_detectability_total / executed_samples, 2) if executed_samples else 0.0

    if decision_counts.get("terminated"):
        guidance = f"{cfg['label']} run was terminated by safety monitoring."
    elif decision_counts.get("throttled"):
        guidance = f"{cfg['label']} cadence was throttled. Reduce payload frequency or expand the approved window."
    elif avg_detectability >= 70:
        guidance = f"{cfg['label']} profile is noisy. Reduce rate or keep dry-run for tuning."
    elif avg_detectability >= 45:
        guidance = f"{cfg['label']} profile is moderate. Tune payload cadence and validate monitoring alerts."
    else:
        guidance = f"{cfg['label']} profile is low-noise in this simulation."

    completed_at = datetime.utcnow()
    return {
        "mode": "dry_run" if dry_run else "simulated_active",
        "started_at": started_at,
        "completed_at": completed_at,
        "sample_count": executed_samples,
        "avg_throughput_kbps": avg_throughput,
        "avg_detectability_score": avg_detectability,
        "guidance": guidance,
        "module_label": cfg["label"],
        "risk_band": _risk_band(avg_detectability),
        "samples": samples,
        "status_counts": decision_counts,
        "action_events": action_events,
        **_build_safety_fields(safety_engine),
    }
