from datetime import datetime
import random
import time
from urllib.parse import urlparse

from Attacks.SafetyEnforcementEngine import parse_target_host


def _bounded(value, low, high):
    return max(low, min(high, value))


def _effectiveness_target(target):
    return _bounded(float(target or 70.0), 0.0, 95.0)


def _risk_band(score):
    if score >= 70:
        return "High"
    if score >= 40:
        return "Moderate"
    return "Low"


def _extract_port(url_or_host, default_port=53):
    if not url_or_host:
        return default_port
    raw = str(url_or_host).strip()
    if "://" not in raw:
        raw = f"http://{raw}"
    parsed = urlparse(raw)
    if parsed.port:
        return parsed.port
    return default_port


def _handle_safety_decision(decision, event_log, counts):
    verdict = (decision or {}).get("decision")
    if verdict in {"blocked", "throttled", "terminated"}:
        event_log.append({"decision": verdict, "message": (decision or {}).get("message", "")})
        counts[verdict] = counts.get(verdict, 0) + 1
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


def run_dns_tunneling_experiment(attempts, rate_limit, dry_run=True, target=None, safety_engine=None, effectiveness_target_percent=70.0):
    """
    Safe lab simulation for DNS tunneling throughput vs detectability.
    No network traffic is generated.
    """
    started_at = datetime.utcnow()

    sample_count = int(_bounded(int(attempts), 1, 100))
    bounded_rate = _bounded(float(rate_limit), 0.1, 20.0)
    effectiveness_target = _effectiveness_target(effectiveness_target_percent)
    base_qps = max(0.5, bounded_rate * 4.0)
    payload_bytes = 64 if dry_run else 96
    target_url = (target or {}).get("ip_or_url") or "dns://lab.cast.local"
    target_host = parse_target_host(target_url)
    port = _extract_port(target_url)

    samples = []
    detectability_total = 0.0
    throughput_total = 0.0
    status_counts = {}
    action_events = []

    for trial in range(1, sample_count + 1):
        jitter = random.uniform(-0.22, 0.22)
        queries_per_second = max(0.1, base_qps * (1.0 + jitter))

        packet_loss_percent = _bounded(
            (queries_per_second / 12.0) + random.uniform(0.1, 2.0),
            0.0,
            15.0
        )

        throughput_kbps = max(
            0.01,
            ((queries_per_second * payload_bytes * 8.0) / 1000.0) * (1.0 - (packet_loss_percent / 100.0)),
        )

        entropy_score = _bounded(
            0.45 + (queries_per_second / 22.0) + random.uniform(-0.08, 0.10),
            0.0,
            1.0
        )

        detectability_score = _bounded(
            28.0 + (queries_per_second * 2.7) + (entropy_score * 26.0) + (0 if dry_run else 6),
            1.0,
            100.0
        )

        metadata = {
            "target_url": target_url,
            "target_ip": target_host,
            "port": port,
            "service": "dns",
            "payload_bytes": payload_bytes,
            "queries_per_second": round(queries_per_second, 2),
            "packet_count": max(1, int(round(queries_per_second * 6))),
        }
        decision = safety_engine.evaluate_action("packet", metadata) if safety_engine else {"decision": "allowed"}
        verdict = _handle_safety_decision(decision, action_events, status_counts)
        if verdict == "blocked":
            continue
        if verdict == "throttled":
            time.sleep(0.1)
            continue
        if verdict == "terminated":
            break

        throughput_total += throughput_kbps
        detectability_total += detectability_score

        samples.append({
            "trial": trial,
            "queries_per_second": round(queries_per_second, 2),
            "payload_bytes": payload_bytes,
            "packet_loss_percent": round(packet_loss_percent, 2),
            "entropy_score": round(entropy_score, 3),
            "throughput_kbps": round(throughput_kbps, 3),
            "detectability_score": round(detectability_score, 2),
            "risk_band": _risk_band(detectability_score),
        })

        monitor = safety_engine.monitor_activity(
            {
                "detectability_score": round(detectability_score, 2),
                "bandwidth_kbps": round(throughput_kbps, 3),
                "packet_count": metadata["packet_count"],
                "unexpected_targets": 0,
            }
        ) if safety_engine else {"decision": "allowed"}
        monitor_verdict = _handle_safety_decision(monitor, action_events, status_counts)
        if monitor_verdict == "throttled":
            time.sleep(0.1)
        if monitor_verdict == "terminated":
            break

    executed_samples = len(samples)
    avg_throughput = round(throughput_total / executed_samples, 3) if executed_samples else 0.0
    avg_detectability = round(detectability_total / executed_samples, 2) if executed_samples else 0.0
    effectiveness_score = 0.0 if dry_run or not executed_samples else effectiveness_target
    overall_risk = _risk_band(avg_detectability)

    if status_counts.get("terminated"):
        guidance = "Safety engine terminated the DNS simulation. Review unexpected thresholds and lab-only settings."
    elif status_counts.get("throttled"):
        guidance = "DNS traffic was throttled by the safety engine. Lower query cadence or payload size."
    elif avg_detectability >= 70:
        guidance = "High detection risk. Lower rate_limit, reduce payload size, or keep testing in dry-run mode."
    elif avg_detectability >= 45:
        guidance = "Moderate detection risk. Tune queries per second and monitor DNS entropy patterns."
    else:
        guidance = "Low detection profile in this simulation. Current settings appear comparatively stealthier."

    completed_at = datetime.utcnow()

    return {
        "mode": "dry_run" if dry_run else "simulated_active",
        "started_at": started_at,
        "completed_at": completed_at,
        "sample_count": executed_samples,
        "success_rate_percent": effectiveness_score,
        "simulation_effectiveness_target_percent": effectiveness_target,
        "avg_throughput_kbps": avg_throughput,
        "avg_detectability_score": avg_detectability,
        "guidance": guidance,
        "risk_band": overall_risk,
        "samples": samples,
        "status_counts": status_counts,
        "action_events": action_events,
        **_build_safety_fields(safety_engine),
    }
