import os
import re
import time
from pathlib import Path

from flask import Flask, abort, g, render_template, request

from castrange import config
from castrange.db import init_db, log_request
from castrange.defenses.waf import waf_check

# Ground-truth attack signatures. Independent of the WAF — these tag whether an
# inbound request CONTAINS an attack payload, regardless of whether defenses block it.
GROUND_TRUTH_TELLS = re.compile(
    r"('|--|\bunion\s+select\b|\bor\b\s+['\"]?\s*1\s*=\s*1|"
    r"<script\b|onerror\s*=|onload\s*=|<svg\b|javascript:)",
    re.IGNORECASE,
)


def _refuse_production():
    if (os.environ.get("FLASK_ENV") or "").lower() == "production":
        raise RuntimeError("CASTRange refuses to start with FLASK_ENV=production.")


def _gather_inputs():
    parts = [request.path or "", request.query_string.decode("utf-8", errors="replace")]
    if request.method in ("POST", "PUT", "PATCH"):
        for k, v in (request.form or {}).items():
            parts.append(f"{k}={v}")
        if request.is_json:
            body = request.get_json(silent=True)
            if body is not None:
                parts.append(str(body))
    return "\n".join(parts)


def create_app():
    _refuse_production()
    init_db()

    app = Flask(__name__, template_folder="templates", static_folder="static")
    app.secret_key = os.environ.get("CASTRANGE_SECRET", "deliberately-weak-secret")

    Path(config.TOKEN_FILE).write_text(config.state.token, encoding="utf-8")

    @app.before_request
    def _start_request():
        host = (request.host or "").split(":")[0].lower()
        if host not in ("127.0.0.1", "localhost", "::1", "[::1]"):
            abort(403)
        g.start_time = time.time()
        g.payload_signature = None
        g.vuln_triggered = False
        g.detected = False

    @app.before_request
    def _tag_ground_truth():
        if (request.path or "").startswith("/_range"):
            return None
        blob = _gather_inputs()
        m = GROUND_TRUTH_TELLS.search(blob)
        if m:
            g.vuln_triggered = True
            g.payload_signature = m.group(0)
        return None

    @app.before_request
    def _waf():
        return waf_check()

    @app.after_request
    def _finish_request(response):
        response.headers["X-CASTRange"] = "vulnerable-target-do-not-expose"
        latency_ms = int((time.time() - getattr(g, "start_time", time.time())) * 1000)
        try:
            log_request(
                method=request.method,
                path=request.path,
                query=request.query_string.decode("utf-8", errors="replace"),
                status=response.status_code,
                latency_ms=latency_ms,
                remote_ip=request.remote_addr or "",
                payload_signature=getattr(g, "payload_signature", None),
                vuln_triggered=getattr(g, "vuln_triggered", False),
                detected=getattr(g, "detected", False),
            )
        except Exception:
            pass
        return response

    from castrange.blueprints.auth import bp as auth_bp
    from castrange.blueprints.replay import bp as replay_bp
    from castrange.blueprints.search import bp as search_bp
    from castrange.blueprints.range_api import bp as range_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(replay_bp)
    app.register_blueprint(search_bp)
    app.register_blueprint(range_bp, url_prefix="/_range")

    @app.route("/")
    def index():
        return render_template("index.html")

    return app
