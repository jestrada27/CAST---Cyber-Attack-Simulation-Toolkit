import time
from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Optional

import requests


@dataclass
class Finding:
    payload: str
    endpoint: str
    method: str
    status: int
    latency_ms: int
    success: bool
    evidence: str = ""
    detection_signal: str = ""
    category: str = ""


@dataclass
class AttackResult:
    module_id: str = "base"
    module_label: str = "Base"
    mode: str = "simulated_active"
    started_at: datetime = field(default_factory=datetime.utcnow)
    completed_at: Optional[datetime] = None
    sample_count: int = 0
    success_count: int = 0
    findings: list = field(default_factory=list)
    action_events: list = field(default_factory=list)
    status_counts: dict = field(default_factory=dict)
    target_metrics: Optional[dict] = None
    latencies_ms: list = field(default_factory=list)
    detectability_scores: list = field(default_factory=list)
    guidance: str = ""
    target_url: Optional[str] = None

    @property
    def success_rate_percent(self):
        if not self.sample_count:
            return 0.0
        return round(self.success_count / self.sample_count * 100.0, 2)

    @property
    def detection_rate_observed_percent(self):
        if not self.sample_count:
            return 0.0
        detected = sum(1 for f in self.findings if f.detection_signal)
        return round(detected / self.sample_count * 100.0, 2)

    @property
    def avg_latency_ms(self):
        if not self.latencies_ms:
            return 0.0
        return round(sum(self.latencies_ms) / len(self.latencies_ms), 2)

    @property
    def p95_latency_ms(self):
        if not self.latencies_ms:
            return 0
        sorted_ms = sorted(self.latencies_ms)
        idx = max(0, min(len(sorted_ms) - 1, int(0.95 * (len(sorted_ms) - 1))))
        return sorted_ms[idx]

    @property
    def avg_detectability_score(self):
        if not self.detectability_scores:
            return 0.0
        return round(sum(self.detectability_scores) / len(self.detectability_scores), 2)

    def to_dict(self, safety_engine=None):
        elapsed = 0.0
        if self.completed_at:
            elapsed = max((self.completed_at - self.started_at).total_seconds(), 0.001)
        throughput_kbps = round(self.sample_count / elapsed * 0.6, 3) if elapsed else 0.0

        out = {
            "module_id": self.module_id,
            "module_label": self.module_label,
            "mode": self.mode,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "sample_count": self.sample_count,
            "success_count": self.success_count,
            "success_rate_percent": self.success_rate_percent,
            "detection_rate_observed_percent": self.detection_rate_observed_percent,
            "avg_latency_ms": self.avg_latency_ms,
            "p95_latency_ms": self.p95_latency_ms,
            "avg_detectability_score": self.avg_detectability_score,
            "avg_throughput_kbps": throughput_kbps,
            "guidance": self.guidance,
            "status_counts": self.status_counts,
            "action_events": self.action_events,
            "findings": [asdict(f) for f in self.findings],
            "target_url": self.target_url,
            "target_metrics": self.target_metrics,
        }

        if safety_engine is not None:
            try:
                report = safety_engine.build_report()
                out["safety_report"] = report
                out["user_alerts"] = report.get("user_alerts", [])
                out["safety_summary"] = report.get("summary", "Completed")
            except Exception:
                pass

        return out


class BaseRunner:
    """Base class for HTTP attack runners. Subclasses override `module_id`,
    `module_label`, and `run()`."""

    MAX_ATTEMPTS = 50
    MAX_RUNTIME_SECONDS = 120
    DEFAULT_TIMEOUT = 10
    USER_AGENT = "CAST-Range-Tester/0.1"

    module_id = "base"
    module_label = "Base"

    def __init__(self, attempts, rate_limit, dry_run, target, safety_engine):
        self.attempts = max(1, min(int(attempts or 1), self.MAX_ATTEMPTS))
        self.rate_limit = max(0.1, min(float(rate_limit or 1.0), 10.0))
        self.min_interval = max(0.05, 1.0 / self.rate_limit)
        self.dry_run = bool(dry_run)
        self.target = target or {}
        self.safety_engine = safety_engine
        self.target_url = (self.target.get("ip_or_url") or "").strip()
        self.session = requests.Session()
        self.session.headers["User-Agent"] = self.USER_AGENT
        self.deadline = time.time() + self.MAX_RUNTIME_SECONDS

    def _runtime_exceeded(self):
        return time.time() >= self.deadline

    def _new_result(self):
        return AttackResult(
            module_id=self.module_id,
            module_label=self.module_label,
            mode="dry_run" if self.dry_run else "simulated_active",
            started_at=datetime.utcnow(),
            target_url=self.target_url,
        )

    def _safety_evaluate(self, action_type, metadata):
        if not self.safety_engine:
            return {"decision": "allowed"}
        try:
            return self.safety_engine.evaluate_action(action_type, metadata)
        except Exception:
            return {"decision": "allowed"}

    def _safety_monitor(self, signal):
        if not self.safety_engine:
            return {"decision": "allowed"}
        try:
            return self.safety_engine.monitor_activity(signal)
        except Exception:
            return {"decision": "allowed"}

    def _record_safety_verdict(self, decision, result, endpoint=None):
        verdict = (decision or {}).get("decision", "allowed")
        if verdict in ("blocked", "throttled", "terminated"):
            entry = {"decision": verdict, "message": (decision or {}).get("message", "")}
            if endpoint:
                entry["endpoint"] = endpoint
            result.action_events.append(entry)
            result.status_counts[verdict] = result.status_counts.get(verdict, 0) + 1
        return verdict
