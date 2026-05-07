from functools import wraps

from flask import Blueprint, abort, jsonify, request

from castrange.blueprints.replay import clear_replay_state
from castrange.config import state
from castrange.db import get_conn, init_db

bp = Blueprint("range_api", __name__)


def _require_token(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        token = request.headers.get("X-Range-Token") or request.args.get("token")
        if not token or token != state.token:
            abort(401)
        return f(*args, **kwargs)
    return wrapper


@bp.route("/health")
def health():
    return jsonify({"status": "ok", "service": "castrange", "config": state.get()})


@bp.route("/reset", methods=["POST"])
@_require_token
def reset():
    init_db()
    clear_replay_state()
    return jsonify({"status": "reset"})


@bp.route("/log")
@_require_token
def log():
    since_id = request.args.get("since_id")
    conn = get_conn()
    if since_id and since_id.isdigit():
        rows = conn.execute(
            "SELECT * FROM access_log WHERE id > ? ORDER BY id",
            (int(since_id),),
        ).fetchall()
    else:
        rows = conn.execute("SELECT * FROM access_log ORDER BY id").fetchall()
    conn.close()
    return jsonify({"entries": [dict(r) for r in rows], "count": len(rows)})


@bp.route("/metrics")
@_require_token
def metrics():
    conn = get_conn()
    total = conn.execute("SELECT COUNT(*) AS c FROM access_log").fetchone()["c"]
    triggered = conn.execute(
        "SELECT COUNT(*) AS c FROM access_log WHERE vuln_triggered = 1"
    ).fetchone()["c"]
    detected = conn.execute(
        "SELECT COUNT(*) AS c FROM access_log WHERE detected = 1"
    ).fetchone()["c"]
    true_positives = conn.execute(
        "SELECT COUNT(*) AS c FROM access_log WHERE detected = 1 AND vuln_triggered = 1"
    ).fetchone()["c"]
    success = conn.execute(
        "SELECT COUNT(*) AS c FROM access_log "
        "WHERE vuln_triggered = 1 AND detected = 0 AND status < 500"
    ).fetchone()["c"]
    latencies = [r["latency_ms"] for r in conn.execute(
        "SELECT latency_ms FROM access_log ORDER BY latency_ms"
    ).fetchall()]
    avg_latency = sum(latencies) / len(latencies) if latencies else 0
    conn.close()

    def pct(p):
        if not latencies:
            return 0
        idx = max(0, min(len(latencies) - 1, int(p * (len(latencies) - 1))))
        return latencies[idx]

    detection_rate = (true_positives / triggered * 100.0) if triggered else 0.0
    false_positives = detected - true_positives
    fp_rate = (false_positives / detected * 100.0) if detected else 0.0
    success_rate = (success / triggered * 100.0) if triggered else 0.0

    return jsonify({
        "requests": total,
        "triggered": triggered,
        "detected": detected,
        "success_rate_pct": round(success_rate, 2),
        "detection_rate_pct": round(detection_rate, 2),
        "false_positive_rate_pct": round(fp_rate, 2),
        "avg_latency_ms": round(avg_latency, 2),
        "p50_latency_ms": pct(0.5),
        "p95_latency_ms": pct(0.95),
        "config": state.get(),
    })


@bp.route("/config", methods=["GET", "POST"])
@_require_token
def config_endpoint():
    if request.method == "POST":
        body = request.get_json(silent=True) or request.form or {}
        new = state.update(level=body.get("level"),
                           defense_level=body.get("defense_level"))
        return jsonify(new)
    return jsonify(state.get())
