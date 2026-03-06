from datetime import datetime
import math
import random
import uuid


def _bounded(value, low, high):
    return max(low, min(high, value))


def run_bruteforce_experiment(attempts, rate_limit, dry_run=True):
    """
    Execute the existing brute-force simulator with safe defaults.
    Falls back to dry-run behavior when selected by the user.
    """
    started_at = datetime.utcnow()
    attempts_per_user = int(_bounded(int(attempts), 1, 10))
    concurrency = int(_bounded(math.ceil(float(rate_limit)), 1, 10))
    delay = round(_bounded(0.12 / max(float(rate_limit), 0.1), 0.01, 0.2), 3)
    run_id = str(uuid.uuid4())

    # Lazy import keeps app startup resilient if optional module deps are missing.
    from bruteforce.bruteforce_simulator import DEFAULT_TARGET, load_credentials_from_file, run_simulation

    creds = load_credentials_from_file("bruteforce/creds.txt")
    if not creds:
        raise RuntimeError("No credentials available in bruteforce/creds.txt")

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
        telemetry_mode = "mongodb"
    except Exception as error:
        # If telemetry DB is unavailable (for example missing MONGODB_URI),
        # fall back to a local safe simulation so the module still runs.
        status_name = "dry_run" if dry_run else "simulated"
        total_users = len(creds)
        total_attempts = total_users * attempts_per_user
        results = [{"username": f"user_{idx+1}", "status": status_name} for idx in range(total_attempts)]
        telemetry_mode = f"fallback_local ({error})"

    status_counts = {}
    for result in results:
        status = result.get("status", "unknown")
        status_counts[status] = status_counts.get(status, 0) + 1

    completed_at = datetime.utcnow()
    total_attempts = len(results)
    success_count = status_counts.get("success", 0)
    success_rate = round((success_count / total_attempts) * 100.0, 2) if total_attempts else 0.0

    if success_rate > 5:
        guidance = "Credential policy appears weak. Increase account lockout and password complexity."
    else:
        guidance = "Low compromise rate in this run. Continue monitoring failed auth telemetry."

    return {
        "mode": "dry_run" if dry_run else "simulated_active",
        "started_at": started_at,
        "completed_at": completed_at,
        "sample_count": total_attempts,
        "avg_throughput_kbps": 0.0,
        "avg_detectability_score": round(_bounded(25 + (concurrency * 4) + (attempts_per_user * 1.5), 1, 100), 2),
        "guidance": guidance,
        "run_id": run_id,
        "target_url": DEFAULT_TARGET,
        "telemetry_mode": telemetry_mode,
        "status_counts": status_counts,
        "success_rate_percent": success_rate,
    }


def run_generic_module_simulation(module_id, attempts, rate_limit, dry_run=True):
    """
    Safe simulation for modules that do not yet have a dedicated backend runner.
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

    avg_throughput = round((base_rate * cfg["throughput_factor"] * stealth_bias) + random.uniform(0.05, 0.5), 3)
    avg_detectability = round(_bounded((base_rate * cfg["detection_factor"] * 10) + random.uniform(4, 14), 1, 100), 2)

    if avg_detectability >= 70:
        guidance = f"{cfg['label']} profile is noisy. Reduce rate or keep dry-run for tuning."
    elif avg_detectability >= 45:
        guidance = f"{cfg['label']} profile is moderate. Tune payload cadence and validate alerts."
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
    }
