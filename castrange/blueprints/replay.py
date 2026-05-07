import hashlib
import hmac
import json
import threading
import time

from flask import Blueprint, g, jsonify, request

bp = Blueprint("replay", __name__)

REPLAY_SHARED_SECRET = b"super-secret-key"
REPLAY_CLOCK_SKEW_SECONDS = 30
_lock = threading.Lock()
_seen_nonces = set()
_nonce_counts = {}


def clear_replay_state():
    with _lock:
        _seen_nonces.clear()
        _nonce_counts.clear()


def sign_replay_message(message: str, nonce: str, timestamp: int) -> str:
    payload = json.dumps(
        {"message": message, "nonce": nonce, "timestamp": int(timestamp)},
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hmac.new(REPLAY_SHARED_SECRET, payload, hashlib.sha256).hexdigest()


def _truthy(value) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


def _body(status_code, accepted, message, nonce, timestamp, replay_seen,
          protected_mode, signature_valid=True, detail=None):
    vulnerability = bool(accepted and replay_seen and not protected_mode)
    if replay_seen:
        g.vuln_triggered = True
        g.payload_signature = f"replay:{nonce}"
        g.detected = bool(protected_mode)

    payload = {
        "connected": True,
        "accepted": accepted,
        "attack_detected": bool(replay_seen),
        "attack_type": "Replay",
        "technique": "signed_request_reuse",
        "payload_received": message,
        "vulnerability": vulnerability,
        "detail": detail or (
            "Replay accepted by castrange without nonce protection."
            if vulnerability
            else "Replay rejected by castrange nonce protection."
            if replay_seen and protected_mode
            else "Signed request accepted by castrange."
            if accepted
            else "Signed request rejected by castrange."
        ),
        "server_behavior": {
            "nonce": nonce,
            "timestamp": timestamp,
            "replay_seen": bool(replay_seen),
            "protected_mode": bool(protected_mode),
            "signature_valid": bool(signature_valid),
            "accepted": bool(accepted),
            "nonce_request_count": _nonce_counts.get(nonce, 0),
        },
    }
    return jsonify(payload), status_code


@bp.route("/replay/verify", methods=["GET", "POST"])
def verify():
    body = request.get_json(silent=True) if request.is_json else None
    data = body or request.values

    message = str(data.get("message", ""))
    nonce = str(data.get("nonce", ""))
    signature = str(data.get("signature", ""))
    protected_mode = _truthy(data.get("protected") or request.args.get("protected"))

    try:
        timestamp = int(data.get("timestamp", ""))
    except (TypeError, ValueError):
        timestamp = 0

    missing = [
        name for name, value in {
            "message": message,
            "nonce": nonce,
            "timestamp": timestamp,
            "signature": signature,
        }.items()
        if not value
    ]
    if missing:
        return _body(
            400,
            False,
            message,
            nonce,
            timestamp,
            False,
            protected_mode,
            signature_valid=False,
            detail=f"Missing replay field(s): {', '.join(missing)}.",
        )

    if abs(int(time.time()) - timestamp) > REPLAY_CLOCK_SKEW_SECONDS:
        return _body(
            400,
            False,
            message,
            nonce,
            timestamp,
            False,
            protected_mode,
            signature_valid=False,
            detail="Timestamp outside the allowed replay lab window.",
        )

    expected_signature = sign_replay_message(message, nonce, timestamp)
    signature_valid = hmac.compare_digest(signature, expected_signature)
    if not signature_valid:
        return _body(
            401,
            False,
            message,
            nonce,
            timestamp,
            False,
            protected_mode,
            signature_valid=False,
            detail="Invalid HMAC signature.",
        )

    with _lock:
        replay_seen = nonce in _seen_nonces
        _nonce_counts[nonce] = _nonce_counts.get(nonce, 0) + 1
        if protected_mode and replay_seen:
            return _body(
                409,
                False,
                message,
                nonce,
                timestamp,
                True,
                True,
                detail="Replay detected and rejected because nonce protection is enabled.",
            )

        _seen_nonces.add(nonce)
        return _body(200, True, message, nonce, timestamp, replay_seen, protected_mode)
