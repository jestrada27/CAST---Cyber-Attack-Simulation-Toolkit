from collections import Counter, defaultdict, deque
from copy import deepcopy
from datetime import datetime, timedelta, UTC
from threading import Lock
from urllib.parse import urlparse


APPROVED_CONSENT_STATES = {"approved", "authorized", "verified", "active"}
DESTRUCTIVE_SQL_KEYWORDS = (
    " drop ",
    " delete ",
    " truncate ",
    " alter ",
    " insert ",
    " update ",
    " create ",
    " grant ",
)
SAFE_XSS_MARKERS = (
    "&lt;script&gt;alert(1)&lt;/script&gt;",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "<script>alert(1)</script>",
    '"><script>alert(1)</script>',
)


def utc_now():
    return datetime.now(UTC)


def split_csv_lines(value):
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        values = value
    else:
        values = str(value).replace("\r", "\n").replace(";", ",").splitlines()
    parts = []
    for entry in values:
        for piece in str(entry).split(","):
            item = piece.strip()
            if item:
                parts.append(item)
    return parts


def dedupe_preserve(values):
    seen = set()
    output = []
    for value in values:
        if value not in seen:
            seen.add(value)
            output.append(value)
    return output


def parse_datetime_local(value):
    if not value:
        return None
    text = str(value).strip()
    for fmt in ("%Y-%m-%dT%H:%M", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(text, fmt)
        except ValueError:
            continue
    return None


def normalize_scope_value(value):
    if value is None:
        return None
    text = str(value).strip()
    return text.lower() or None


def parse_target_host(url_or_host):
    if not url_or_host:
        return None
    raw = str(url_or_host).strip()
    if "://" not in raw:
        raw = f"http://{raw}"
    parsed = urlparse(raw)
    return normalize_scope_value(parsed.hostname or parsed.path)


def parse_target_base_url(url_or_host):
    """Return scheme://host:port without path, used to seed the allowed_urls scope."""
    if not url_or_host:
        return None
    raw = str(url_or_host).strip()
    if "://" not in raw:
        raw = f"http://{raw}"
    parsed = urlparse(raw)
    if not parsed.scheme or not parsed.hostname:
        return None
    port_part = f":{parsed.port}" if parsed.port else ""
    return f"{parsed.scheme}://{parsed.hostname}{port_part}"


def merge_scope_lists(*groups):
    merged = []
    for group in groups:
        merged.extend(split_csv_lines(group))
    return dedupe_preserve(merged)


def normalize_safety_settings(raw_settings, module_id, target=None, owner_username=None):
    raw = deepcopy(raw_settings or {})
    target = target or {}
    target_host = parse_target_host(target.get("ip_or_url"))
    target_service_list = merge_scope_lists(target.get("allowed_services"))
    approved_users = merge_scope_lists(
        raw.get("authorization", {}).get("approved_users"),
        target.get("approved_users"),
        [owner_username] if owner_username else [],
    )

    scope = raw.get("scope", {})
    allowed_ips = merge_scope_lists(scope.get("allowed_ips"), [target_host] if target_host else [])
    target_base_url = parse_target_base_url(target.get("ip_or_url"))
    allowed_urls = merge_scope_lists(scope.get("allowed_urls"), [target_base_url] if target_base_url else [])
    allowed_accounts = merge_scope_lists(scope.get("allowed_accounts"), target.get("allowed_accounts"))
    allowed_services = merge_scope_lists(scope.get("allowed_services"), target_service_list)
    allowed_ports = []
    for entry in merge_scope_lists(scope.get("allowed_ports"), target.get("allowed_ports")):
        try:
            allowed_ports.append(int(entry))
        except (TypeError, ValueError):
            continue

    time_limit = raw.get("time_limit", {})
    max_duration_seconds = int(time_limit.get("max_duration_seconds", 90) or 90)
    scheduled_end = parse_datetime_local(time_limit.get("scheduled_end"))
    now = utc_now()
    if scheduled_end and scheduled_end <= now:
        scheduled_end = now + timedelta(seconds=max_duration_seconds)

    normalized = {
        "authorization": {
            "require_target_approval": bool(raw.get("authorization", {}).get("require_target_approval", True)),
            "require_experiment_approval": bool(raw.get("authorization", {}).get("require_experiment_approval", True)),
            "experiment_approved": bool(raw.get("authorization", {}).get("experiment_approved", False)),
            "approved_users": approved_users,
        },
        "scope": {
            "allowed_ips": allowed_ips,
            "allowed_ports": sorted(set(allowed_ports)),
            "allowed_urls": allowed_urls,
            "allowed_accounts": allowed_accounts,
            "allowed_services": allowed_services,
        },
        "rate_limit": {
            "requests_per_minute": int(raw.get("rate_limit", {}).get("requests_per_minute", 60) or 60),
            "login_attempts_per_minute": int(raw.get("rate_limit", {}).get("login_attempts_per_minute", 20) or 20),
            "payloads_per_minute": int(raw.get("rate_limit", {}).get("payloads_per_minute", 30) or 30),
            "bandwidth_kbps": float(raw.get("rate_limit", {}).get("bandwidth_kbps", 256.0) or 256.0),
            "packet_volume_per_minute": int(raw.get("rate_limit", {}).get("packet_volume_per_minute", 240) or 240),
        },
        "time_limit": {
            "max_duration_seconds": max(5, min(max_duration_seconds, 3600)),
            "scheduled_end": scheduled_end,
        },
        "kill_switch": {
            "enabled": bool(raw.get("kill_switch", {}).get("enabled", True)),
            "engaged": bool(raw.get("kill_switch", {}).get("engaged", False)),
            "reason": raw.get("kill_switch", {}).get("reason", ""),
            "engaged_at": raw.get("kill_switch", {}).get("engaged_at"),
        },
        "monitoring": {
            "max_detectability_score": float(raw.get("monitoring", {}).get("max_detectability_score", 80.0) or 80.0),
            "max_scope_violations": int(raw.get("monitoring", {}).get("max_scope_violations", 1) or 1),
            "max_alerts": int(raw.get("monitoring", {}).get("max_alerts", 5) or 5),
            "max_unexpected_targets": int(raw.get("monitoring", {}).get("max_unexpected_targets", 0) or 0),
        },
        "module_constraints": {
            "brute force": {
                "max_attempts_per_account": int(raw.get("module_constraints", {}).get("brute force", {}).get("max_attempts_per_account", 5) or 5),
                "allowed_accounts": allowed_accounts,
            },
            "xss": {
                "safe_payloads_only": bool(raw.get("module_constraints", {}).get("xss", {}).get("safe_payloads_only", True)),
                "safe_payloads": merge_scope_lists(raw.get("module_constraints", {}).get("xss", {}).get("safe_payloads")) or list(SAFE_XSS_MARKERS[:3]),
            },
            "sqli": {
                "probe_only": bool(raw.get("module_constraints", {}).get("sqli", {}).get("probe_only", True)),
            },
            "replay": {
                "lab_only": bool(raw.get("module_constraints", {}).get("replay", {}).get("lab_only", True)),
                "max_replays": int(raw.get("module_constraints", {}).get("replay", {}).get("max_replays", 10) or 10),
                "allow_state_changing_methods": bool(raw.get("module_constraints", {}).get("replay", {}).get("allow_state_changing_methods", False)),
            },
            "dns": {
                "lab_only": bool(raw.get("module_constraints", {}).get("dns", {}).get("lab_only", True)),
                "max_payload_bytes": int(raw.get("module_constraints", {}).get("dns", {}).get("max_payload_bytes", 96) or 96),
                "max_queries_per_second": float(raw.get("module_constraints", {}).get("dns", {}).get("max_queries_per_second", 5.0) or 5.0),
            },
        },
        "module_id": module_id,
        "target_environment": normalize_scope_value(target.get("environment")) or "lab",
    }
    return normalized


def build_safety_settings_from_form(form, target, owner_username):
    module_id = form.get("module_id", "")
    return normalize_safety_settings(
        {
            "authorization": {
                "require_target_approval": True,
                "require_experiment_approval": True,
                "experiment_approved": form.get("experiment_approved") == "on",
                "approved_users": split_csv_lines(form.get("approved_users")),
            },
            "scope": {
                "allowed_ips": split_csv_lines(form.get("allowed_ips")),
                "allowed_ports": split_csv_lines(form.get("allowed_ports")),
                "allowed_urls": split_csv_lines(form.get("allowed_urls")),
                "allowed_accounts": split_csv_lines(form.get("allowed_accounts")),
                "allowed_services": split_csv_lines(form.get("allowed_services")),
            },
            "rate_limit": {
                "requests_per_minute": form.get("requests_per_minute") or 60,
                "login_attempts_per_minute": form.get("login_attempts_per_minute") or 20,
                "payloads_per_minute": form.get("payloads_per_minute") or 30,
                "bandwidth_kbps": form.get("bandwidth_kbps") or 256,
                "packet_volume_per_minute": form.get("packet_volume_per_minute") or 240,
            },
            "time_limit": {
                "max_duration_seconds": form.get("max_duration_seconds") or 90,
                "scheduled_end": form.get("scheduled_end"),
            },
            "kill_switch": {
                "enabled": form.get("kill_switch_enabled") != "off",
                "engaged": False,
                "reason": "",
                "engaged_at": None,
            },
            "monitoring": {
                "max_detectability_score": form.get("max_detectability_score") or 80,
                "max_scope_violations": form.get("max_scope_violations") or 1,
                "max_alerts": form.get("max_alerts") or 5,
                "max_unexpected_targets": form.get("max_unexpected_targets") or 0,
            },
            "module_constraints": {
                "brute force": {
                    "max_attempts_per_account": form.get("bf_max_attempts_per_account") or 5,
                },
                "xss": {
                    "safe_payloads_only": form.get("xss_safe_payloads_only") != "off",
                    "safe_payloads": split_csv_lines(form.get("xss_safe_payloads")),
                },
                "sqli": {
                    "probe_only": form.get("sqli_probe_only") != "off",
                },
                "replay": {
                    "lab_only": form.get("replay_lab_only") != "off",
                    "max_replays": form.get("replay_max_replays") or 10,
                    "allow_state_changing_methods": form.get("replay_allow_state_change") == "on",
                },
                "dns": {
                    "lab_only": form.get("dns_lab_only") != "off",
                    "max_payload_bytes": form.get("dns_max_payload_bytes") or 96,
                    "max_queries_per_second": form.get("dns_max_queries_per_second") or 5,
                },
            },
        },
        module_id=module_id,
        target=target,
        owner_username=owner_username,
    )


class SafetyEnforcementEngine:
    def __init__(self, experiment, target, user, settings, stop_checker=None):
        self.experiment = experiment or {}
        self.target = target or {}
        self.user = user or {}
        self.settings = normalize_safety_settings(
            settings,
            module_id=(experiment or {}).get("module_id", ""),
            target=target,
            owner_username=(user or {}).get("username"),
        )
        self.stop_checker = stop_checker
        self.lock = Lock()
        self.started_at = utc_now()
        self.deadline = self.started_at + timedelta(seconds=self.settings["time_limit"]["max_duration_seconds"])
        scheduled_end = self.settings["time_limit"]["scheduled_end"]
        if scheduled_end:
            self.deadline = min(self.deadline, scheduled_end)

        self.events = []
        self.alerts = []
        self.decision_counts = Counter()
        self.metric_windows = defaultdict(deque)
        self.scope_violations = 0
        self.monitor_alerts = 0
        self.account_attempts = Counter()
        self.seen_targets = set()
        self.total_requests = 0
        self.payloads_seen = 0
        self.total_packet_volume = 0
        self.total_bandwidth_kbps = 0.0
        self.kill_switch_engaged = bool(self.settings["kill_switch"]["engaged"])
        self.kill_reason = self.settings["kill_switch"]["reason"]

        if self.kill_switch_engaged:
            self._append_event(
                decision="terminated",
                severity="critical",
                phase="startup",
                code="kill_switch_preengaged",
                message=self.kill_reason or "Experiment already had the kill switch engaged.",
            )

    def _append_event(self, decision, severity, phase, code, message, metadata=None, alert_user=False):
        event = {
            "time": utc_now(),
            "decision": decision,
            "severity": severity,
            "phase": phase,
            "code": code,
            "message": message,
            "metadata": metadata or {},
        }
        self.events.append(event)
        self.decision_counts[decision] += 1
        if alert_user:
            self.alerts.append(message)
        return event

    def _decision(self, decision, phase, code, message, metadata=None, alert_user=False):
        severity_map = {
            "allowed": "info",
            "blocked": "warning",
            "throttled": "warning",
            "terminated": "critical",
        }
        event = self._append_event(
            decision=decision,
            severity=severity_map.get(decision, "info"),
            phase=phase,
            code=code,
            message=message,
            metadata=metadata,
            alert_user=alert_user or decision in {"blocked", "throttled", "terminated"},
        )
        return {
            "decision": decision,
            "message": message,
            "event": event,
        }

    def _check_external_stop(self):
        if not self.stop_checker or self.kill_switch_engaged:
            return None
        try:
            requested = bool(self.stop_checker())
        except Exception:
            requested = False
        if requested:
            return self.engage_kill_switch("Emergency stop requested by operator.", phase="runtime", metadata={})
        return None

    def engage_kill_switch(self, reason, phase="runtime", metadata=None):
        with self.lock:
            self.kill_switch_engaged = True
            self.kill_reason = reason
            self.settings["kill_switch"]["engaged"] = True
            self.settings["kill_switch"]["reason"] = reason
            self.settings["kill_switch"]["engaged_at"] = utc_now()
        return self._decision("terminated", phase, "kill_switch", reason, metadata=metadata, alert_user=True)

    def authorize_start(self):
        if self.kill_switch_engaged:
            return self._decision(
                "terminated",
                "authorization",
                "kill_switch",
                self.kill_reason or "Kill switch is engaged for this experiment.",
                metadata={"experiment_id": str(self.experiment.get("_id", ""))},
                alert_user=True,
            )

        external_stop = self._check_external_stop()
        if external_stop:
            return external_stop

        owner = self.experiment.get("owner")
        actor = self.user.get("username")
        if owner and actor and owner != actor:
            return self._decision(
                "blocked",
                "authorization",
                "user_mismatch",
                "The active user is not authorized to run this experiment.",
                metadata={"owner": owner, "actor": actor},
            )

        approved_users = set(self.settings["authorization"]["approved_users"])
        if approved_users and actor not in approved_users:
            return self._decision(
                "blocked",
                "authorization",
                "user_not_approved",
                "This user is outside the experiment approval list.",
                metadata={"approved_users": sorted(approved_users)},
            )

        if self.settings["authorization"]["require_experiment_approval"] and not self.settings["authorization"]["experiment_approved"]:
            return self._decision(
                "blocked",
                "authorization",
                "experiment_not_approved",
                "Experiment approval has not been recorded yet.",
                metadata={},
            )

        if self.settings["authorization"]["require_target_approval"]:
            consent_status = normalize_scope_value(self.target.get("consent_status"))
            if consent_status not in APPROVED_CONSENT_STATES:
                return self._decision(
                    "blocked",
                    "authorization",
                    "target_not_approved",
                    "Target consent is not approved for CAST execution.",
                    metadata={"consent_status": self.target.get("consent_status", "unknown")},
                )

        return self._decision(
            "allowed",
            "authorization",
            "authorization_passed",
            "Authorization checks passed.",
            metadata={"target": self.target.get("name"), "user": actor},
        )

    def _scope_allowed(self, metadata):
        scope = self.settings["scope"]
        target_host = normalize_scope_value(metadata.get("target_ip")) or parse_target_host(metadata.get("target_url"))
        target_url = metadata.get("target_url")
        port = metadata.get("port")
        account = metadata.get("account")
        service = normalize_scope_value(metadata.get("service"))

        if scope["allowed_ips"] and target_host and target_host not in {normalize_scope_value(v) for v in scope["allowed_ips"]}:
            return False, "scope_ip", f"Target host '{target_host}' is outside the approved scope."
        if scope["allowed_urls"] and target_url and not any(target_url.startswith(u) for u in scope["allowed_urls"]):
            return False, "scope_url", f"Target URL '{target_url}' is outside the approved scope."
        if scope["allowed_ports"] and port is not None and int(port) not in set(scope["allowed_ports"]):
            return False, "scope_port", f"Port '{port}' is outside the approved scope."
        if scope["allowed_accounts"] and account and account not in set(scope["allowed_accounts"]):
            return False, "scope_account", f"Account '{account}' is outside the approved scope."
        if scope["allowed_services"] and service and service not in {normalize_scope_value(v) for v in scope["allowed_services"]}:
            return False, "scope_service", f"Service '{service}' is outside the approved scope."
        return True, "scope_ok", "Scope checks passed."

    def _enforce_rate_limit(self, action_type, metadata):
        now = utc_now()
        windows = {
            "request": ("requests_per_minute", 60, 1),
            "login_attempt": ("login_attempts_per_minute", 60, 1),
            "payload": ("payloads_per_minute", 60, 1),
            "packet": ("packet_volume_per_minute", 60, int(metadata.get("packet_count", 1) or 1)),
        }
        config = None
        if action_type in windows:
            config = windows[action_type]
        elif metadata.get("packet_count"):
            config = windows["packet"]

        if not config:
            return None

        setting_name, window_seconds, increment = config
        limit = self.settings["rate_limit"][setting_name]
        window = self.metric_windows[setting_name]
        while window and (now - window[0]).total_seconds() >= window_seconds:
            window.popleft()

        projected = len(window) + max(increment, 1)
        if projected > limit:
            retry_after = max(1, window_seconds - int((now - window[0]).total_seconds())) if window else window_seconds
            return self._decision(
                "throttled",
                "runtime",
                "rate_limit",
                f"{setting_name.replace('_', ' ')} threshold reached. Retry after {retry_after}s.",
                metadata={"setting": setting_name, "limit": limit, "retry_after": retry_after},
            )

        for _ in range(max(increment, 1)):
            window.append(now)
        return None

    def _enforce_time_limit(self):
        now = utc_now()
        if now >= self.deadline:
            return self.engage_kill_switch(
                "Time limit reached. Experiment has been terminated.",
                phase="runtime",
                metadata={"deadline": self.deadline},
            )
        return None

    def _enforce_module_constraints(self, action_type, metadata):
        module_id = self.settings["module_id"]
        constraints = self.settings["module_constraints"].get(module_id, {})

        if module_id == "brute force" and action_type == "login_attempt":
            account = metadata.get("account")
            if account:
                self.account_attempts[account] += 1
                if self.account_attempts[account] > constraints.get("max_attempts_per_account", 5):
                    return self._decision(
                        "blocked",
                        "runtime",
                        "bruteforce_limit",
                        f"Account '{account}' exceeded the brute-force safety cap.",
                        metadata={"account": account, "attempts": self.account_attempts[account]},
                    )

        if module_id == "xss" and action_type == "payload":
            payload = str(metadata.get("payload", ""))
            if constraints.get("safe_payloads_only", True):
                allowed_payloads = set(constraints.get("safe_payloads") or [])
                if payload not in allowed_payloads:
                    return self._decision(
                        "blocked",
                        "runtime",
                        "xss_payload_blocked",
                        "Only safe XSS payloads are allowed for this experiment.",
                        metadata={"payload": payload},
                    )

        if module_id == "sqli" and action_type == "payload":
            payload = f" {str(metadata.get('payload', '')).lower()} "
            if constraints.get("probe_only", True) and any(keyword in payload for keyword in DESTRUCTIVE_SQL_KEYWORDS):
                return self._decision(
                    "blocked",
                    "runtime",
                    "sqli_probe_only",
                    "Destructive SQL keywords are blocked in probe-only mode.",
                    metadata={"payload": metadata.get("payload", "")},
                )

        if module_id == "replay":
            if constraints.get("lab_only", True) and self.settings["target_environment"] != "lab":
                return self._decision(
                    "blocked",
                    "runtime",
                    "replay_lab_only",
                    "Replay simulations are restricted to lab environments.",
                    metadata={"environment": self.settings["target_environment"]},
                )
            method = str(metadata.get("method", "GET")).upper()
            if not constraints.get("allow_state_changing_methods", False) and method not in {"GET", "HEAD"}:
                return self._decision(
                    "blocked",
                    "runtime",
                    "replay_method_blocked",
                    "Replay simulation is limited to read-only HTTP methods.",
                    metadata={"method": method},
                )

        if module_id == "dns":
            if constraints.get("lab_only", True) and self.settings["target_environment"] != "lab":
                return self._decision(
                    "blocked",
                    "runtime",
                    "dns_lab_only",
                    "DNS tunneling is restricted to lab environments.",
                    metadata={"environment": self.settings["target_environment"]},
                )
            payload_bytes = int(metadata.get("payload_bytes", 0) or 0)
            queries_per_second = float(metadata.get("queries_per_second", 0.0) or 0.0)
            if payload_bytes > constraints.get("max_payload_bytes", 96):
                return self._decision(
                    "blocked",
                    "runtime",
                    "dns_payload_blocked",
                    "DNS payload size exceeded the lab-only safety cap.",
                    metadata={"payload_bytes": payload_bytes},
                )
            if queries_per_second > constraints.get("max_queries_per_second", 5.0):
                return self._decision(
                    "throttled",
                    "runtime",
                    "dns_rate_throttled",
                    "DNS query rate exceeded the configured safe threshold.",
                    metadata={"queries_per_second": queries_per_second},
                )

        return None

    def evaluate_action(self, action_type, metadata=None):
        metadata = metadata or {}
        external_stop = self._check_external_stop()
        if external_stop:
            return external_stop

        if self.kill_switch_engaged:
            return self._decision(
                "terminated",
                "runtime",
                "kill_switch",
                self.kill_reason or "Kill switch engaged.",
                metadata=metadata,
            )

        time_decision = self._enforce_time_limit()
        if time_decision:
            return time_decision

        allowed, code, message = self._scope_allowed(metadata)
        if not allowed:
            self.scope_violations += 1
            decision = self._decision("blocked", "runtime", code, message, metadata=metadata)
            if self.scope_violations > self.settings["monitoring"]["max_scope_violations"]:
                return self.engage_kill_switch(
                    "Repeated scope violations triggered the emergency stop.",
                    phase="monitoring",
                    metadata={"scope_violations": self.scope_violations},
                )
            return decision

        rate_decision = self._enforce_rate_limit(action_type, metadata)
        if rate_decision:
            return rate_decision

        module_decision = self._enforce_module_constraints(action_type, metadata)
        if module_decision:
            return module_decision

        self.total_requests += 1 if action_type in {"request", "login_attempt", "payload"} else 0
        self.payloads_seen += 1 if action_type == "payload" else 0
        if metadata.get("target_url"):
            self.seen_targets.add(metadata["target_url"])
        return self._decision("allowed", "runtime", "action_allowed", "Action is within policy.", metadata=metadata)

    def monitor_activity(self, metrics=None):
        metrics = metrics or {}
        external_stop = self._check_external_stop()
        if external_stop:
            return external_stop

        detectability = float(metrics.get("detectability_score", 0.0) or 0.0)
        bandwidth_kbps = float(metrics.get("bandwidth_kbps", 0.0) or 0.0)
        packet_count = int(metrics.get("packet_count", 0) or 0)
        unexpected_targets = int(metrics.get("unexpected_targets", 0) or 0)

        self.total_bandwidth_kbps += bandwidth_kbps
        self.total_packet_volume += packet_count

        if detectability > self.settings["monitoring"]["max_detectability_score"]:
            self.monitor_alerts += 1
            return self.engage_kill_switch(
                "Detectability exceeded the configured monitoring threshold.",
                phase="monitoring",
                metadata={"detectability_score": detectability},
            )

        if bandwidth_kbps > self.settings["rate_limit"]["bandwidth_kbps"]:
            return self._decision(
                "throttled",
                "monitoring",
                "bandwidth_throttled",
                "Bandwidth exceeded the configured cap.",
                metadata={"bandwidth_kbps": bandwidth_kbps},
            )

        if packet_count and packet_count > self.settings["rate_limit"]["packet_volume_per_minute"]:
            return self.engage_kill_switch(
                "Packet volume exceeded the configured safe threshold.",
                phase="monitoring",
                metadata={"packet_count": packet_count},
            )

        if unexpected_targets > self.settings["monitoring"]["max_unexpected_targets"]:
            return self.engage_kill_switch(
                "Unexpected target spread detected by monitoring.",
                phase="monitoring",
                metadata={"unexpected_targets": unexpected_targets},
            )

        return self._decision(
            "allowed",
            "monitoring",
            "monitoring_ok",
            "Monitoring checks passed.",
            metadata=metrics,
        )

    def final_status(self):
        if self.kill_switch_engaged:
            return "Terminated"
        if self.decision_counts["blocked"]:
            return "Completed With Blocks"
        if self.decision_counts["throttled"]:
            return "Completed With Throttling"
        return "Completed"

    def build_report(self):
        return {
            "started_at": self.started_at,
            "completed_at": utc_now(),
            "kill_switch_engaged": self.kill_switch_engaged,
            "kill_reason": self.kill_reason,
            "decision_counts": dict(self.decision_counts),
            "user_alerts": self.alerts,
            "scope_violations": self.scope_violations,
            "targets_touched": sorted(self.seen_targets),
            "total_requests": self.total_requests,
            "payloads_seen": self.payloads_seen,
            "total_packet_volume": self.total_packet_volume,
            "total_bandwidth_kbps": round(self.total_bandwidth_kbps, 3),
            "settings": self.settings,
            "events": self.events,
            "summary": self.final_status(),
        }
