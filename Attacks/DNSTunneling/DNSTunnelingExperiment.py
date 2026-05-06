from datetime import datetime
import random


def run_dns_tunneling_experiment(attempts, rate_limit, dry_run=True):
    """
    Safe lab simulation for DNS tunneling throughput vs detectability.
    No network traffic is generated.
    """
    sample_count = max(1, min(int(attempts), 50))
    bounded_rate = max(0.1, min(float(rate_limit), 10.0))
    base_qps = max(0.5, bounded_rate * 4.0)
    payload_bytes = 64 if dry_run else 96

    samples = []
    detectability_total = 0.0
    throughput_total = 0.0

    for trial in range(1, sample_count + 1):
        jitter = random.uniform(-0.22, 0.22)
        queries_per_second = max(0.1, base_qps * (1.0 + jitter))
        packet_loss_percent = max(0.0, min(15.0, (queries_per_second / 12.0) + random.uniform(0.1, 2.0)))
        throughput_kbps = max(
            0.01,
            ((queries_per_second * payload_bytes * 8.0) / 1000.0) * (1.0 - (packet_loss_percent / 100.0)),
        )
        entropy_score = max(0.0, min(1.0, 0.45 + (queries_per_second / 22.0) + random.uniform(-0.08, 0.1)))
        detectability_score = max(
            1.0,
            min(100.0, 28.0 + (queries_per_second * 2.7) + (entropy_score * 26.0) + (0 if dry_run else 6)),
        )

        throughput_total += throughput_kbps
        detectability_total += detectability_score

        samples.append(
            {
                "trial": trial,
                "queries_per_second": round(queries_per_second, 2),
                "payload_bytes": payload_bytes,
                "packet_loss_percent": round(packet_loss_percent, 2),
                "throughput_kbps": round(throughput_kbps, 3),
                "detectability_score": round(detectability_score, 2),
            }
        )

    avg_throughput = round(throughput_total / sample_count, 3)
    avg_detectability = round(detectability_total / sample_count, 2)

    if avg_detectability >= 70:
        guidance = "High detection risk. Lower rate_limit or reduce payload size."
    elif avg_detectability >= 45:
        guidance = "Moderate detection risk. Tune qps and monitor DNS entropy."
    else:
        guidance = "Low detection profile in this simulation."

    now = datetime.utcnow()
    return {
        "mode": "dry_run" if dry_run else "simulated_active",
        "started_at": now,
        "completed_at": now,
        "sample_count": sample_count,
        "avg_throughput_kbps": avg_throughput,
        "avg_detectability_score": avg_detectability,
        "guidance": guidance,
        "samples": samples,
    }
