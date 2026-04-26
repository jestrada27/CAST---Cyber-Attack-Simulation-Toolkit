import re

from flask import g, jsonify, request

from castrange.config import state

# Conservative attack signatures. Independent of the ground-truth tagger so we
# can measure detection_rate and false_positive_rate against it.
SQLI_PATTERNS = [
    re.compile(r"\bunion\b\s+\bselect\b", re.IGNORECASE),
    re.compile(r"\bor\b\s+['\"]?\s*1\s*=\s*1", re.IGNORECASE),
    re.compile(r"\bor\b\s+['\"]?\s*[a-z0-9]+['\"]?\s*=\s*['\"]?[a-z0-9]+['\"]?\s*(--|#)", re.IGNORECASE),
    re.compile(r"(--\s|#\s|/\*).*\b(select|drop|update|delete|insert|union)\b", re.IGNORECASE),
    re.compile(r"\bdrop\s+table\b|\btruncate\s+table\b", re.IGNORECASE),
]

XSS_PATTERNS = [
    re.compile(r"<script\b", re.IGNORECASE),
    re.compile(r"\son\w+\s*=", re.IGNORECASE),
    re.compile(r"javascript:", re.IGNORECASE),
    re.compile(r"<svg\b[^>]*\bon\w+", re.IGNORECASE),
    re.compile(r"<img\b[^>]*\bon\w+", re.IGNORECASE),
]

ALL_PATTERNS = SQLI_PATTERNS + XSS_PATTERNS


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


def waf_check():
    """Run as a before_request hook. Returns a Response to short-circuit, or None."""
    if (request.path or "").startswith("/_range"):
        return None

    cfg = state.get()
    if cfg["defense_level"] == "off":
        return None

    blob = _gather_inputs()
    for rx in ALL_PATTERNS:
        m = rx.search(blob)
        if m:
            g.detected = True
            if not getattr(g, "payload_signature", None):
                g.payload_signature = m.group(0)
            return jsonify({
                "error": "Request blocked by CASTRange WAF",
                "matched": m.group(0),
                "defense_level": cfg["defense_level"],
            }), 403
    return None
