from datetime import datetime
import random


def _bounded(value, low, high):
    return max(low, min(high, value))


def _risk_band(score):
    if score >= 70:
        return "High"
    if score >= 40:
        return "Moderate"
    return "Low"


def run_dns_tunneling_experiment(attempts, rate_limit, dry_run=True):
    """
    Safe lab simulation for DNS tunneling throughput vs detectability.
    No network traffic is generated.
    """
    started_at = datetime.utcnow()

    sample_count = int(_bounded(int(attempts), 1, 50))
    bounded_rate = _bounded(float(rate_limit), 0.1, 10.0)
    base_qps = max(0.5, bounded_rate * 4.0)
    payload_bytes = 64 if dry_run else 96

    samples = []
    detectability_total = 0.0
    throughput_total = 0.0

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

    avg_throughput = round(throughput_total / sample_count, 3)
    avg_detectability = round(detectability_total / sample_count, 2)
    overall_risk = _risk_band(avg_detectability)

    if avg_detectability >= 70:
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
        "sample_count": sample_count,
        "avg_throughput_kbps": avg_throughput,
        "avg_detectability_score": avg_detectability,
        "guidance": guidance,
        "risk_band": overall_risk,
        "samples": samples,
    }