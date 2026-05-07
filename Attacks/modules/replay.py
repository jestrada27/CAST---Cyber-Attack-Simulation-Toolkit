import hashlib
import hmac
import json
import time
import uuid
from datetime import datetime, UTC
from urllib.parse import urlparse

from Attacks.modules import target_guard
from Attacks.modules.base import BaseRunner, Finding

REPLAY_SHARED_SECRET = b"super-secret-key"


def sign_replay_message(message: str, nonce: str, timestamp: int) -> str:
    payload = json.dumps(
        {"message": message, "nonce": nonce, "timestamp": int(timestamp)},
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hmac.new(REPLAY_SHARED_SECRET, payload, hashlib.sha256).hexdigest()


def make_replay_packet(message: str) -> dict:
    nonce = str(uuid.uuid4())
    timestamp = int(time.time())
    return {
        "message": message,
        "nonce": nonce,
        "timestamp": str(timestamp),
        "signature": sign_replay_message(message, nonce, timestamp),
    }


class ReplayRunner(BaseRunner):
    module_id = "replay"
    module_label = "Replay"

    def run(self):
        result = self._new_result()
        result.mode = "dry_run" if self.dry_run else "real_http"

        endpoint = self._resolve_endpoint()
        if not endpoint:
            result.mode = "refused"
            result.guidance = "No target URL provided for replay testing."
            result.completed_at = datetime.now(UTC)
            return result

        try:
            target_guard.assert_permitted(endpoint, self.target)
        except target_guard.TargetNotPermitted as ex:
            result.mode = "refused"
            result.guidance = f"Target refused by guard: {ex}"
            result.completed_at = datetime.now(UTC)
            return result

        packet = make_replay_packet("cast-lab-transfer=10")
        replay_attempts = self._replay_attempt_count()

        if self.dry_run:
            result.sample_count = replay_attempts + 1
            result.status_counts["dry_run"] = result.sample_count
            result.replay_summary = {
                "endpoint": endpoint,
                "mode": "dry_run",
                "initial_request_accepted": None,
                "replay_attempts": replay_attempts,
                "accepted_replays": 0,
                "rejected_replays": 0,
                "vulnerable": None,
                "nonce": packet["nonce"],
            }
            result.guidance = (
                "Dry run prepared a signed request and replay plan. "
                "Turn off Dry Run to send real HTTP traffic to the lab target."
            )
            result.completed_at = datetime.now(UTC)
            return result

        self._send_packet(result, endpoint, packet, "initial_request")
        for _ in range(replay_attempts):
            if self._runtime_exceeded():
                break
            self._send_packet(result, endpoint, packet, "replay_attempt")
            time.sleep(self.min_interval)

        accepted_replays = sum(
            1 for finding in result.findings
            if finding.category == "replay_attempt" and finding.success
        )
        rejected_replays = sum(
            1 for finding in result.findings
            if finding.category == "replay_attempt" and not finding.success
        )
        initial = next(
            (finding for finding in result.findings if finding.category == "initial_request"),
            None,
        )

        result.replay_summary = {
            "endpoint": endpoint,
            "mode": result.mode,
            "initial_request_accepted": bool(initial and initial.status == 200),
            "replay_attempts": accepted_replays + rejected_replays,
            "accepted_replays": accepted_replays,
            "rejected_replays": rejected_replays,
            "vulnerable": accepted_replays > 0,
            "nonce": packet["nonce"],
        }
        result.target_metrics = self._pull_castrange_metrics()
        result.completed_at = datetime.now(UTC)
        result.guidance = self._build_guidance(result)
        return result

    def _resolve_endpoint(self):
        if not self.target_url:
            return ""
        raw = self.target_url if "://" in self.target_url else "http://" + self.target_url
        parsed = urlparse(raw)
        base = f"{parsed.scheme}://{parsed.netloc}"
        path = parsed.path.rstrip("/")
        if path.startswith("/replay"):
            return raw
        return f"{base}/replay/verify"

    def _replay_attempt_count(self):
        requested = max(1, self.attempts - 1)
        constraints = {}
        if self.safety_engine is not None:
            try:
                constraints = self.safety_engine.settings.get("module_constraints", {}).get("replay", {})
            except Exception:
                constraints = {}
        try:
            max_replays = int(constraints.get("max_replays", 10) or 10)
        except (TypeError, ValueError):
            max_replays = 10
        return max(1, min(requested, max_replays))

    def _metadata(self, endpoint, packet):
        parsed = urlparse(endpoint)
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        return {
            "target_url": endpoint,
            "target_ip": parsed.hostname,
            "port": port,
            "service": "http",
            "payload": packet["nonce"],
            "method": "GET",
            "packet_count": 1,
        }

    def _send_packet(self, result, endpoint, packet, category):
        decision = self._safety_evaluate("request", self._metadata(endpoint, packet))
        verdict = self._record_safety_verdict(decision, result, endpoint=endpoint)
        if verdict == "blocked":
            return None
        if verdict == "throttled":
            time.sleep(self.min_interval * 2)
            return None
        if verdict == "terminated":
            return None

        started = time.time()
        try:
            response = self.session.get(
                endpoint,
                params=packet,
                timeout=self.DEFAULT_TIMEOUT,
                allow_redirects=False,
            )
            latency_ms = int((time.time() - started) * 1000)
            finding = self._evaluate_response(response, latency_ms, endpoint, packet, category)
        except Exception as ex:
            latency_ms = int((time.time() - started) * 1000)
            finding = Finding(
                payload=packet["nonce"],
                endpoint=endpoint,
                method="GET",
                status=0,
                latency_ms=latency_ms,
                success=False,
                evidence=f"network error: {ex}",
                category=category,
            )

        result.sample_count += 1
        result.latencies_ms.append(latency_ms)
        result.findings.append(finding)
        self._update_counts(result, finding)

        detectability = self._detectability(finding)
        result.detectability_scores.append(detectability)
        monitor = self._safety_monitor({
            "detectability_score": detectability,
            "bandwidth_kbps": 1.0,
            "packet_count": 1,
            "unexpected_targets": 0,
        })
        self._record_safety_verdict(monitor, result, endpoint=endpoint)
        return finding

    def _evaluate_response(self, response, latency_ms, endpoint, packet, category):
        try:
            body = response.json()
        except ValueError:
            body = {}

        behavior = body.get("server_behavior") or {}
        accepted = bool(body.get("accepted"))
        vulnerability = bool(body.get("vulnerability"))
        attack_detected = bool(body.get("attack_detected"))
        detail = body.get("detail") or response.text[:120]

        success = bool(category == "replay_attempt" and accepted and vulnerability)
        if success:
            detection = "replay_accepted"
        elif attack_detected:
            detection = "replay_detected"
        elif not accepted:
            detection = "replay_rejected"
        else:
            detection = ""

        if category == "initial_request":
            evidence = "Initial signed request accepted." if accepted else detail
        else:
            evidence = detail
            if behavior.get("nonce_request_count"):
                evidence = f"{evidence} Nonce seen {behavior['nonce_request_count']} time(s)."

        return Finding(
            payload=packet["nonce"],
            endpoint=endpoint,
            method="GET",
            status=response.status_code,
            latency_ms=latency_ms,
            success=success,
            evidence=evidence,
            detection_signal=detection,
            category=category,
            exposed_data={
                "accepted": accepted,
                "vulnerability": vulnerability,
                "replay_seen": bool(behavior.get("replay_seen")),
                "protected_mode": bool(behavior.get("protected_mode")),
            },
        )

    def _update_counts(self, result, finding):
        result.status_counts[finding.category] = result.status_counts.get(finding.category, 0) + 1
        if finding.success:
            result.success_count += 1
            result.status_counts["success"] = result.status_counts.get("success", 0) + 1
        if finding.detection_signal:
            key = finding.detection_signal
            result.status_counts[key] = result.status_counts.get(key, 0) + 1

    def _detectability(self, finding):
        if finding.detection_signal == "replay_accepted":
            return 65.0
        if finding.detection_signal == "replay_detected":
            return 50.0
        if finding.detection_signal == "replay_rejected":
            return 35.0
        return 20.0

    def _build_guidance(self, result):
        summary = result.replay_summary or {}
        if summary.get("vulnerable"):
            return (
                "Replay succeeded against the lab endpoint: the duplicate signed request "
                "was accepted. Add nonce tracking, timestamp windows, and one-time request IDs."
            )
        if summary.get("replay_attempts"):
            return (
                "Replay traffic was sent, but duplicate requests were rejected or detected. "
                "The target appears to have replay protection for this flow."
            )
        if result.status_counts.get("blocked"):
            return "Replay test was blocked by safety policy. Review lab-only scope and method settings."
        return "Replay test did not complete enough requests to determine exposure."

    def _pull_castrange_metrics(self):
        if not self.target_url:
            return None
        meta = self.target.get("metadata") or {}
        token = meta.get("range_token")
        if not token:
            try:
                with open("castrange.token", "r", encoding="utf-8") as token_file:
                    token = token_file.read().strip()
            except OSError:
                return None
        if not token:
            return None

        raw = self.target_url if "://" in self.target_url else "http://" + self.target_url
        parsed = urlparse(raw)
        base = f"{parsed.scheme}://{parsed.netloc}"
        try:
            response = self.session.get(
                f"{base}/_range/metrics",
                params={"token": token},
                timeout=self.DEFAULT_TIMEOUT,
            )
            if response.status_code == 200:
                return response.json()
        except Exception:
            return None
        return None
