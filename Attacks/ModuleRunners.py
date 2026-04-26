from datetime import datetime
import math
import random
import uuid


def _bounded(value, low, high):
    return max(low, min(high, value))


def _risk_band(score):
    if score >= 70:
        return "High"
    if score >= 40:
        return "Moderate"
    return "Low"


def run_bruteforce_experiment(attempts, rate_limit, dry_run=True):
    """
    Execute the brute-force simulator with safe defaults and return
    structured telemetry for experiment history and detail views.
    """
    started_at = datetime.utcnow()

    attempts = int(_bounded(int(attempts), 1, 50))
    base_rate_limit = _bounded(float(rate_limit), 0.1, 10.0)

    attempts_per_user = int(_bounded(attempts, 1, 10))
    concurrency = int(_bounded(math.ceil(base_rate_limit), 1, 10))
    delay = round(_bounded(0.12 / max(base_rate_limit, 0.1), 0.01, 0.2), 3)

    run_id = str(uuid.uuid4())

    from bruteforce.bruteforce_simulator import DEFAULT_TARGET, load_credentials_from_file, run_simulation

    creds = load_credentials_from_file("bruteforce/creds.txt")
    if not creds:
        raise RuntimeError("No credentials available in bruteforce/creds.txt")

    sample_results = []
    telemetry_mode = "mongodb"

    try:
        results = run_simulation(
            target_url=DEFAULT_TARGET,
            creds=creds,
            concurrency=concurrency,
            attempts_per_user=attempts_per_user,
            run_id=run_id,
            dry_run=bool(dry_run),
            delay_between_attempts=delay,
        )
    except Exception as error:
        status_name = "dry_run" if dry_run else "simulated"
        fallback_attempts = min(len(creds) * attempts_per_user, 50)
        results = [
            {
                "username": f"user_{idx + 1}",
                "status": status_name
            }
            for idx in range(fallback_attempts)
        ]
        telemetry_mode = f"fallback_local ({error})"

    status_counts = {}
    total_attempts = len(results)

    successful_statuses = {"success", "compromised", "authenticated"}
    noisy_statuses = {"success", "blocked", "locked", "rate_limited", "alerted"}

    for index, result in enumerate(results, start=1):
        status = result.get("status", "unknown")
        status_counts[status] = status_counts.get(status, 0) + 1

        estimated_throughput = round(
            (base_rate_limit * 1.6) + random.uniform(0.08, 0.65),
            3
        )

        detectability_score = round(
            _bounded(
                18 + (concurrency * 4.5) + (attempts_per_user * 2.2) + random.uniform(-4, 7),
                1,
                100
            ),
            2
        )

        sample_results.append({
            "trial": index,
            "username": result.get("username", f"user_{index}"),
            "status": status,
            "throughput_kbps": estimated_throughput,
            "detectability_score": detectability_score,
            "risk_band": _risk_band(detectability_score),
        })

    completed_at = datetime.utcnow()

    success_count = sum(
        1 for result in results
        if result.get("status", "").lower() in successful_statuses
    )
    success_rate = round((success_count / total_attempts) * 100.0, 2) if total_attempts else 0.0

    avg_throughput = round(
        sum(sample["throughput_kbps"] for sample in sample_results) / len(sample_results),
        3
    ) if sample_results else 0.0

    avg_detectability = round(
        sum(sample["detectability_score"] for sample in sample_results) / len(sample_results),
        2
    ) if sample_results else 0.0

    if success_rate > 5 and avg_detectability < 45:
        guidance = "Credential abuse simulation showed measurable effectiveness with relatively low noise. Strengthen password policy and lockout controls."
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
        "target_url": DEFAULT_TARGET,
        "telemetry_mode": telemetry_mode,
        "status_counts": status_counts,
        "success_rate_percent": success_rate,
        "risk_band": _risk_band(avg_detectability),
        "samples": sample_results,
    }


def run_generic_module_simulation(module_id, attempts, rate_limit, dry_run=True):
    """
    Safe simulation for modules that do not yet have a dedicated backend runner.
    Returns structured telemetry compatible with the experiment details page.
    """
    started_at = datetime.utcnow()

    sample_count = int(_bounded(int(attempts), 1, 50))
    base_rate = _bounded(float(rate_limit), 0.1, 10.0)
    stealth_bias = 1.0 if dry_run else 1.15

    by_module = {
        "sqli": {"throughput_factor": 1.8, "detection_factor": 2.6, "label": "SQL Injection"},
        "xss": {"throughput_factor": 2.2, "detection_factor": 2.1, "label": "XSS"},
        "replay": {"throughput_factor": 2.8, "detection_factor": 1.9, "label": "Replay"},
    }
    cfg = by_module.get(module_id, {"throughput_factor": 1.5, "detection_factor": 2.0, "label": module_id.upper()})

    samples = []
    for trial in range(1, sample_count + 1):
        throughput = round(
            (base_rate * cfg["throughput_factor"] * stealth_bias) + random.uniform(0.05, 0.5),
            3
        )
        detectability = round(
            _bounded((base_rate * cfg["detection_factor"] * 10) + random.uniform(4, 14), 1, 100),
            2
        )
        samples.append({
            "trial": trial,
            "throughput_kbps": throughput,
            "detectability_score": detectability,
            "risk_band": _risk_band(detectability),
        })

    avg_throughput = round(
        sum(sample["throughput_kbps"] for sample in samples) / len(samples),
        3
    ) if samples else 0.0

    avg_detectability = round(
        sum(sample["detectability_score"] for sample in samples) / len(samples),
        2
    ) if samples else 0.0

    if avg_detectability >= 70:
        guidance = f"{cfg['label']} profile is noisy. Reduce rate or keep dry-run enabled for tuning."
    elif avg_detectability >= 45:
        guidance = f"{cfg['label']} profile is moderate. Tune payload cadence and validate monitoring alerts."
    else:
        guidance = f"{cfg['label']} profile is low-noise in this simulation."

    completed_at = datetime.utcnow()

    return {
        "mode": "dry_run" if dry_run else "simulated_active",
        "started_at": started_at,
        "completed_at": completed_at,
        "sample_count": sample_count,
        "avg_throughput_kbps": avg_throughput,
        "avg_detectability_score": avg_detectability,
        "guidance": guidance,
        "module_label": cfg["label"],
        "risk_band": _risk_band(avg_detectability),
        "samples": samples,
    }