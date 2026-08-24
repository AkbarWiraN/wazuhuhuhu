#!/usr/bin/env python3
"""
siem_alarm_scoring_final.py

Final SOC alarm aggregation and risk scoring engine for Wazuh 4.14.7 AIO.

Core design:
- Read raw alerts from wazuh-alerts-*.
- Preserve wazuh-alerts-* as raw evidence.
- Write aggregated alarms to siem-alarm-YYYY.MM.DD.
- Default same-alert definition is deliberately coarse:
    agent.id + rule.id + timestamp_bucket_1h
- srcip/dstip/dstport/proto/url/user/file fields are evidence only, not default split keys.
- source.raw_alert_count == alarm.event_count == risk.frequency_count_1h.

Dependencies:
- Python 3.9+ standard library only.
- Linux fcntl process locking.

Example:
sudo systemctl start siem-alarm-scoring.service
"""

from __future__ import annotations

import argparse
import base64
import collections
import contextlib
import datetime as dt
import hashlib
import json
import logging
import os
import random
import re
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, Iterable, List, Optional, Tuple

try:
    import fcntl
except ImportError:  # pragma: no cover - the production target is Linux.
    fcntl = None


def utc_now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def iso_z(value: dt.datetime) -> str:
    return value.astimezone(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def parse_dt(value: Any) -> Optional[dt.datetime]:
    if value is None:
        return None
    text = str(value)
    if not text:
        return None
    try:
        parsed = dt.datetime.fromisoformat(text.replace("Z", "+00:00"))
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            return None
        return parsed
    except Exception:
        return None


def bucket_start(value: dt.datetime, bucket_minutes: int) -> dt.datetime:
    value = value.astimezone(dt.timezone.utc).replace(second=0, microsecond=0)
    total = value.hour * 60 + value.minute
    floored = (total // bucket_minutes) * bucket_minutes
    return value.replace(hour=floored // 60, minute=floored % 60)


def get_path(data: Dict[str, Any], path: str, default: Any = None) -> Any:
    if not isinstance(data, dict):
        return default
    if path in data:
        return data.get(path, default)
    current: Any = data
    parts = path.split(".")
    for i, part in enumerate(parts):
        if isinstance(current, dict) and part in current:
            current = current[part]
            continue
        if isinstance(current, dict):
            rest = ".".join(parts[i:])
            if rest in current:
                return current.get(rest, default)
        return default
    return current if current is not None else default


def first_value(data: Dict[str, Any], paths: Iterable[str], default: Any = None) -> Any:
    for path in paths:
        value = get_path(data, path)
        if value not in (None, "", "-", "null", "None"):
            return value
    return default


def to_int(value: Any, default: int = 0) -> int:
    try:
        if value is None or value == "":
            return default
        return int(float(str(value)))
    except Exception:
        return default


def safe_str(value: Any, default: str = "-") -> str:
    if value is None:
        return default
    if isinstance(value, (dict, list)):
        return json.dumps(value, sort_keys=True, ensure_ascii=False)
    text = str(value).strip()
    return text if text else default


def normalize_proto(value: Any) -> Optional[str]:
    if value is None:
        return None
    text = safe_str(value).upper()
    mapping = {"6": "TCP", "17": "UDP", "1": "ICMP"}
    text = mapping.get(text, text)
    return None if text in ("-", "NONE", "NULL") else text


def normalize_observed(value: Any) -> Optional[str]:
    text = safe_str(value, "")
    if not text or text in ("-", "0.0.0.0", "::"):
        return None
    return text


def flatten(data: Any, prefix: str = "") -> Dict[str, Any]:
    output: Dict[str, Any] = {}
    if isinstance(data, dict):
        for key, value in data.items():
            new_key = f"{prefix}.{key}" if prefix else str(key)
            output.update(flatten(value, new_key))
    else:
        output[prefix] = data
    return output


class OpenSearchHTTPError(RuntimeError):
    def __init__(self, status: int, method: str, url: str, body: str):
        self.status = status
        self.method = method
        self.url = url
        self.body = body
        super().__init__(f"OpenSearch HTTP {status} {method} {url}: {body}")


class OpenSearchClient:
    RETRYABLE_HTTP_STATUSES = {429, 502, 503, 504}

    def __init__(
        self,
        base_url: str,
        username: str,
        password: str,
        verify_ssl: bool = True,
        ca_cert: Optional[str] = None,
        timeout: int = 60,
        retry_attempts: int = 4,
        retry_backoff_seconds: float = 1.0,
    ):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.retry_attempts = max(1, retry_attempts)
        self.retry_backoff_seconds = max(0.0, retry_backoff_seconds)
        if verify_ssl:
            self.ctx = ssl.create_default_context(cafile=ca_cert) if ca_cert else ssl.create_default_context()
        else:
            self.ctx = ssl._create_unverified_context()
        token = base64.b64encode(f"{username}:{password}".encode()).decode()
        self.headers = {
            "Authorization": f"Basic {token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

    def request(self, method: str, path: str, body: Optional[Dict[str, Any]] = None, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        url = f"{self.base_url}/{path.lstrip('/')}"
        if params:
            url += "?" + urllib.parse.urlencode(params)
        data = json.dumps(body, ensure_ascii=False).encode("utf-8") if body is not None else None
        req = urllib.request.Request(url, data=data, headers=self.headers, method=method.upper())
        for attempt in range(1, self.retry_attempts + 1):
            try:
                with urllib.request.urlopen(req, context=self.ctx, timeout=self.timeout) as response:
                    raw = response.read().decode("utf-8")
                    return json.loads(raw) if raw else {}
            except urllib.error.HTTPError as exc:
                error_body = exc.read().decode("utf-8", errors="replace")
                error = OpenSearchHTTPError(exc.code, method, url, error_body)
                if exc.code not in self.RETRYABLE_HTTP_STATUSES or attempt == self.retry_attempts:
                    raise error from exc
                self._wait_before_retry(attempt, error)
            except urllib.error.URLError as exc:
                error = RuntimeError(f"OpenSearch connection error {method} {url}: {exc}")
                if attempt == self.retry_attempts:
                    raise error from exc
                self._wait_before_retry(attempt, error)
        raise RuntimeError(f"OpenSearch request exhausted retries: {method} {url}")

    def _wait_before_retry(self, attempt: int, error: Exception) -> None:
        delay = self.retry_backoff_seconds * (2 ** (attempt - 1))
        delay += random.uniform(0, min(1.0, delay * 0.25)) if delay else 0.0
        logging.warning(
            "OpenSearch request failed (attempt %d/%d): %s; retrying in %.2fs",
            attempt,
            self.retry_attempts,
            error,
            delay,
        )
        time.sleep(delay)

    def put_template(self, name: str, template: Dict[str, Any]) -> Dict[str, Any]:
        return self.request("PUT", f"_index_template/{name}", template)

    def index_doc(self, index: str, doc_id: str, doc: Dict[str, Any]) -> Dict[str, Any]:
        quoted = urllib.parse.quote(doc_id, safe="")
        return self.request("PUT", f"{index}/_doc/{quoted}", doc)

    def create_doc_if_absent(self, index: str, doc_id: str, doc: Dict[str, Any]) -> bool:
        quoted = urllib.parse.quote(doc_id, safe="")
        try:
            self.request("PUT", f"{index}/_create/{quoted}", doc)
            return True
        except OpenSearchHTTPError as exc:
            if exc.status == 409:
                return False
            raise

    def get_doc(self, index: str, doc_id: str) -> Optional[Dict[str, Any]]:
        quoted = urllib.parse.quote(doc_id, safe="")
        try:
            response = self.request("GET", f"{index}/_doc/{quoted}")
        except OpenSearchHTTPError as exc:
            if exc.status == 404:
                return None
            raise
        if not response.get("found", False):
            return None
        source = response.get("_source")
        return source if isinstance(source, dict) else None

    def search(self, index: str, body: Dict[str, Any], params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        return self.request("POST", f"{index}/_search", body, params)

    def scroll(self, scroll_id: str, keepalive: str) -> Dict[str, Any]:
        return self.request("POST", "_search/scroll", {"scroll": keepalive, "scroll_id": scroll_id})

    def clear_scroll(self, scroll_id: str) -> None:
        try:
            self.request("DELETE", "_search/scroll", {"scroll_id": [scroll_id]})
        except Exception as exc:
            logging.debug("clear_scroll failed: %s", exc)


def threat_score(rule_level: int) -> int:
    if rule_level <= 3:
        return 1
    if rule_level <= 6:
        return 2
    if rule_level <= 9:
        return 3
    if rule_level <= 12:
        return 4
    return 5


def frequency_score(count: int) -> int:
    if count <= 9:
        return 1
    if count <= 49:
        return 2
    if count <= 99:
        return 3
    if count <= 499:
        return 4
    return 5


def risk_level(score: float) -> str:
    if score < 1.5:
        return "Information"
    if score < 2.5:
        return "Low"
    if score < 3.5:
        return "Medium"
    if score < 4.5:
        return "High"
    return "Critical"


def risk_rank(level: Optional[str]) -> int:
    order = {
        "Information": 1,
        "Low": 2,
        "Medium": 3,
        "High": 4,
        "Critical": 5,
    }
    return order.get(str(level), 0)


def recommended_action(level: str, asset: int, threat: int, freq: int) -> Tuple[str, str, bool]:
    if level == "Critical":
        return "Immediate investigation", "15 minutes", True
    if level == "High":
        if asset >= 4 or threat >= 4 or freq >= 5:
            return "Investigate", "1 hour", True
        return "Review", "4 hours", False
    if level == "Medium":
        return "Triage", "1 business day", False
    if level == "Low":
        return "Monitor", "Best effort", False
    return "Baseline", "No SLA", False


def escalation_log_levels(config: Dict[str, Any]) -> set[str]:
    levels = config.get("escalation_log_levels", ["Medium", "High", "Critical"])
    if not isinstance(levels, list):
        return {"Medium", "High", "Critical"}
    return {str(level) for level in levels}


def escalation_log_required(current_level: str, previous_level: Optional[str], config: Dict[str, Any]) -> bool:
    if not bool(config.get("escalation_log_enabled", True)):
        return False
    if current_level not in escalation_log_levels(config):
        return False
    return previous_level is None or risk_rank(current_level) > risk_rank(previous_level)


def asset_category(value: int) -> str:
    return {5: "Critical", 4: "High", 3: "Medium", 2: "Low", 1: "Minimal"}.get(value, "Medium")


def bucket_size_label(minutes: int) -> str:
    if minutes % 60 == 0:
        hours = minutes // 60
        return f"{hours}h"
    return f"{minutes}m"


def load_json(path: str, default: Any) -> Any:
    if not path or not os.path.exists(path):
        return default
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def setup_logging(log_file: str, level: str) -> None:
    log_directory = os.path.dirname(os.path.abspath(log_file))
    os.makedirs(log_directory, exist_ok=True)
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(message)s",
        handlers=[logging.FileHandler(log_file), logging.StreamHandler(sys.stdout)],
    )


@contextlib.contextmanager
def process_lock(lock_file: str) -> Iterable[None]:
    if fcntl is None:
        raise RuntimeError("Process locking requires Linux/fcntl")
    lock_directory = os.path.dirname(os.path.abspath(lock_file))
    os.makedirs(lock_directory, exist_ok=True)
    with open(lock_file, "a+", encoding="utf-8") as handle:
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise RuntimeError(f"Another scoring process holds lock: {lock_file}") from exc
        handle.seek(0)
        handle.truncate()
        handle.write(str(os.getpid()))
        handle.flush()
        try:
            yield
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def validate_search_response(response: Dict[str, Any], context: str) -> None:
    if response.get("timed_out") is True:
        raise RuntimeError(f"OpenSearch search timed out during {context}")
    shards = response.get("_shards", {})
    failed = to_int(shards.get("failed"), 0) if isinstance(shards, dict) else 0
    if failed > 0:
        failures = shards.get("failures", []) if isinstance(shards, dict) else []
        raise RuntimeError(f"OpenSearch reported {failed} failed shard(s) during {context}: {failures}")


def required_alert_errors(alert: Dict[str, Any]) -> List[str]:
    errors: List[str] = []
    timestamp = first_value(alert, ["timestamp"], None)
    if parse_dt(timestamp) is None:
        errors.append("timestamp must contain an ISO-8601 timezone")
    for path in ["agent.id", "rule.id", "rule.description"]:
        if first_value(alert, [path], None) in (None, "", "-", "null", "None"):
            errors.append(f"{path} is required")
    raw_level = first_value(alert, ["rule.level"], None)
    try:
        level = int(str(raw_level))
        if not 0 <= level <= 15:
            errors.append("rule.level must be between 0 and 15")
    except (TypeError, ValueError):
        errors.append("rule.level must be an integer")
    return errors


def get_rule_groups(alert: Dict[str, Any]) -> List[str]:
    groups = first_value(alert, ["rule.groups", "rule.group"], [])
    if isinstance(groups, list):
        return [safe_str(x).lower() for x in groups]
    if isinstance(groups, str):
        return [x.strip().lower() for x in re.split(r"[, ]+", groups) if x.strip()]
    return []


def classify_case_type(alert: Dict[str, Any]) -> str:
    groups = get_rule_groups(alert)
    desc = safe_str(first_value(alert, ["rule.description"], "")).lower()
    decoder = safe_str(first_value(alert, ["decoder.name"], "")).lower()

    if first_value(alert, ["vulnerability.cve", "data.vulnerability.cve"]):
        return "vulnerability"
    if first_value(alert, ["sca.check.id", "data.sca.check.id"]):
        return "sca"
    if first_value(alert, ["syscheck.path"]):
        if "malware" in desc or "yara" in desc or any(g in groups for g in ["malware", "yara", "virus"]):
            return "malware"
        return "fim"
    if any(g in groups for g in ["suricata", "ids", "firewall"]) or "suricata" in decoder:
        return "network"
    if any(g in groups for g in ["web", "attack", "apache", "nginx"]) or any(x in desc for x in ["web", "http", "xss", "sql injection", "url"]):
        return "web"
    if any(g in groups for g in ["authentication_failed", "authentication_failures", "sshd", "pam"]) or any(x in desc for x in ["failed password", "login failed", "authentication failed", "brute"]):
        return "auth"
    if "rootcheck" in groups or first_value(alert, ["rootcheck.file"]):
        return "rootcheck"
    return "generic"


def extract_observed(alert: Dict[str, Any]) -> Dict[str, Optional[str]]:
    return {
        "srcip": normalize_observed(first_value(alert, [
            "data.srcip", "data.src_ip", "srcip", "source.ip", "data.source.ip",
            "data.win.eventdata.IpAddress", "data.win.eventdata.ipAddress"
        ])),
        "dstip": normalize_observed(first_value(alert, [
            "data.dstip", "data.dest_ip", "data.destination.ip", "dstip", "destination.ip", "agent.ip"
        ])),
        "dstport": normalize_observed(first_value(alert, [
            "data.dstport", "data.dest_port", "data.destination.port", "destination.port", "dstport"
        ])),
        "proto": normalize_proto(first_value(alert, [
            "data.proto", "data.protocol", "network.transport", "proto", "protocol"
        ])),
        "url": normalize_observed(first_value(alert, [
            "data.url", "url.path", "http.request.referrer", "data.http.url", "data.http.hostname"
        ])),
        "user": normalize_observed(first_value(alert, [
            "data.user", "user.name", "data.dstuser", "data.srcuser",
            "data.win.eventdata.TargetUserName", "data.win.eventdata.SubjectUserName"
        ])),
        "user_agent": normalize_observed(first_value(alert, [
            "data.http_user_agent", "user_agent.original", "data.http.user_agent"
        ])),
        "file_path": normalize_observed(first_value(alert, [
            "syscheck.path", "file.path", "data.file", "rootcheck.file"
        ])),
        "file_hash": normalize_observed(first_value(alert, [
            "syscheck.sha256_after", "syscheck.sha256", "file.hash.sha256", "data.sha256", "data.hash"
        ])),
        "cve": normalize_observed(first_value(alert, [
            "vulnerability.cve", "data.vulnerability.cve"
        ])),
        "sca_check": normalize_observed(first_value(alert, [
            "sca.check.id", "data.sca.check.id"
        ])),
    }


def read_asset_from_labels(alert: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    value = first_value(alert, [
        "agent.labels.asset.value", "labels.asset.value", "asset.value",
        "agent.labels.asset_value", "labels.asset_value"
    ])
    if value is None:
        return None
    asset_value = max(1, min(5, to_int(value, 3)))
    return {
        "value": asset_value,
        "category": safe_str(first_value(alert, [
            "agent.labels.asset.category", "labels.asset.category", "asset.category",
            "agent.labels.asset_category", "labels.asset_category"
        ], asset_category(asset_value))),
        "type": safe_str(first_value(alert, [
            "agent.labels.asset.type", "labels.asset.type", "asset.type",
            "agent.labels.asset_type", "labels.asset_type"
        ], "Unknown")),
        "owner": safe_str(first_value(alert, [
            "agent.labels.asset.owner", "labels.asset.owner", "asset.owner",
            "agent.labels.asset_owner", "labels.asset_owner"
        ], "Unknown")),
        "environment": safe_str(first_value(alert, [
            "agent.labels.asset.environment", "labels.asset.environment", "asset.environment",
            "agent.labels.environment"
        ], "Unknown")),
        "source": "agent_label",
    }


def get_asset(alert: Dict[str, Any], assets: Dict[str, Any]) -> Dict[str, Any]:
    labelled = read_asset_from_labels(alert)
    if labelled:
        return labelled

    agent_id = safe_str(first_value(alert, ["agent.id"], "000"))
    agent_name = safe_str(first_value(alert, ["agent.name"], "unknown"))
    entry = assets.get(agent_id) if isinstance(assets, dict) else None
    if not entry and isinstance(assets, dict):
        entry = assets.get(agent_name)

    if isinstance(entry, dict):
        value = max(1, min(5, to_int(entry.get("asset_value", entry.get("value", 3)), 3)))
        return {
            "value": value,
            "category": safe_str(entry.get("asset_category", entry.get("category", asset_category(value)))),
            "type": safe_str(entry.get("asset_type", entry.get("type", "Unknown"))),
            "owner": safe_str(entry.get("asset_owner", entry.get("owner", "Unknown"))),
            "environment": safe_str(entry.get("environment", entry.get("asset_environment", "Unknown"))),
            "source": "assets_json",
        }

    logging.warning("No asset metadata for agent.id=%s agent.name=%s. Defaulting to Medium.", agent_id, agent_name)
    return {
        "value": 3,
        "category": "Medium",
        "type": "Unknown",
        "owner": "Unknown",
        "environment": "Unknown",
        "source": "default",
    }


def build_case_key(alert: Dict[str, Any], observed: Dict[str, Optional[str]], bucket_iso: str, config: Dict[str, Any]) -> Tuple[str, str, List[str]]:
    agent_id = safe_str(first_value(alert, ["agent.id"], "000"))
    rule_id = safe_str(first_value(alert, ["rule.id"], "unknown"))
    default_mode = config.get("deduplication_mode", "coarse")
    rule_overrides = config.get("rule_overrides", {})
    override = rule_overrides.get(rule_id, {}) if isinstance(rule_overrides, dict) else {}
    mode = override.get("deduplication_mode", default_mode)

    if mode == "target_aware":
        dstip = observed.get("dstip") or "-"
        key = f"target_aware|{agent_id}|{rule_id}|{dstip}|{bucket_iso}"
        return key, mode, ["agent.id", "rule.id", "dstip", "timestamp_bucket_1h"]

    if mode == "target_port_aware":
        dstip = observed.get("dstip") or "-"
        dstport = observed.get("dstport") or "-"
        proto = observed.get("proto") or "-"
        key = f"target_port_aware|{agent_id}|{rule_id}|{dstip}|{dstport}|{proto}|{bucket_iso}"
        return key, mode, ["agent.id", "rule.id", "dstip", "dstport", "proto", "timestamp_bucket_1h"]

    if mode == "file_aware":
        file_path = observed.get("file_path") or "-"
        key = f"file_aware|{agent_id}|{rule_id}|{file_path}|{bucket_iso}"
        return key, mode, ["agent.id", "rule.id", "file_path", "timestamp_bucket_1h"]

    # Final default for this SOC design.
    key = f"coarse|{agent_id}|{rule_id}|{bucket_iso}"
    return key, "coarse", ["agent.id", "rule.id", "timestamp_bucket_1h"]


def make_id(case_key: str) -> str:
    return hashlib.sha256(case_key.encode("utf-8")).hexdigest()


def build_query(config: Dict[str, Any], gte: str, lte: str, upper_inclusive: bool = True) -> Dict[str, Any]:
    upper_op = "lte" if upper_inclusive else "lt"
    must = [{"range": {"timestamp": {"gte": gte, upper_op: lte}}}]
    must_not = []

    min_level = config.get("min_rule_level")
    if min_level is not None:
        must.append({"range": {"rule.level": {"gte": int(min_level)}}})

    excluded_rule_ids = [str(x) for x in config.get("excluded_rule_ids", [])]
    if excluded_rule_ids:
        must_not.append({"terms": {"rule.id": excluded_rule_ids}})

    excluded_groups = [str(x) for x in config.get("excluded_rule_groups", [])]
    if excluded_groups:
        must_not.append({"terms": {"rule.groups": excluded_groups}})

    return {"bool": {"must": must, "must_not": must_not}}


def fetch_alerts(client: OpenSearchClient, config: Dict[str, Any], gte: str, lte: str, upper_inclusive: bool = True) -> Iterable[Tuple[str, str, Dict[str, Any]]]:
    body = {
        "size": int(config.get("page_size", 1000)),
        "query": build_query(config, gte, lte, upper_inclusive),
        "sort": [{"timestamp": {"order": "asc"}}],
        "_source": True,
    }
    keepalive = config.get("scroll_keepalive", "2m")
    max_alerts = int(config.get("max_alerts_per_run", 50000))
    emitted = 0
    response = client.search(config.get("source_index", "wazuh-alerts-*"), body, {"scroll": keepalive})
    validate_search_response(response, "initial alert search")
    scroll_id = response.get("_scroll_id")

    try:
        while True:
            hits = response.get("hits", {}).get("hits", [])
            if not hits:
                break
            for hit in hits:
                if max_alerts > 0 and emitted >= max_alerts:
                    message = (
                        f"max_alerts_per_run reached ({max_alerts}); run aborted before writing partial aggregates "
                        f"for gte={gte} {'lte' if upper_inclusive else 'lt'}={lte}"
                    )
                    logging.error(
                        message
                    )
                    raise RuntimeError(message)
                emitted += 1
                yield hit.get("_index", ""), hit.get("_id", ""), hit.get("_source", {})
            if not scroll_id:
                break
            response = client.scroll(scroll_id, keepalive)
            validate_search_response(response, "alert scroll")
            scroll_id = response.get("_scroll_id", scroll_id)
    finally:
        if scroll_id:
            client.clear_scroll(scroll_id)


def count_values(counter: collections.Counter, limit: int) -> List[Dict[str, Any]]:
    return [{"value": str(k), "count": int(v)} for k, v in counter.most_common(limit)]


def sample_values(counter: collections.Counter, limit: int) -> List[str]:
    return [str(k) for k, _ in counter.most_common(limit)]


def weighted_median(counter: collections.Counter) -> int:
    if not counter:
        return 0
    total = sum(counter.values())
    midpoint = (total + 1) // 2
    running = 0
    for value, count in sorted(counter.items()):
        running += count
        if running >= midpoint:
            return int(value)
    return int(counter.most_common(1)[0][0])


def select_rule_level(counter: collections.Counter, strategy: str) -> int:
    if not counter:
        return 0
    strategy = str(strategy or "max").lower()
    if strategy == "mode":
        return int(counter.most_common(1)[0][0])
    if strategy == "median":
        return weighted_median(counter)
    return int(max(counter.keys()))


def rule_level_counts(counter: collections.Counter) -> List[Dict[str, int]]:
    return [{"level": int(level), "count": int(count)} for level, count in sorted(counter.items())]


def aggregate(alerts: Iterable[Tuple[str, str, Dict[str, Any]]], assets: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    buckets: Dict[str, Dict[str, Any]] = {}
    bucket_minutes = int(config.get("bucket_minutes", 60))
    skipped = 0

    for source_index, doc_id, alert in alerts:
        errors = required_alert_errors(alert)
        if errors:
            skipped += 1
            if skipped <= 10:
                logging.warning(
                    "Skipping malformed alert index=%s id=%s: %s",
                    source_index,
                    doc_id,
                    "; ".join(errors),
                )
            continue
        ts = parse_dt(first_value(alert, ["timestamp"], None))
        assert ts is not None
        bucket_iso = iso_z(bucket_start(ts, bucket_minutes))
        observed = extract_observed(alert)
        case_key, mode, key_fields = build_case_key(alert, observed, bucket_iso, config)

        if case_key not in buckets:
            buckets[case_key] = {
                "case_key": case_key,
                "deduplication_mode": mode,
                "dedup_key_fields": key_fields,
                "bucket_start": bucket_iso,
                "bucket_minutes": bucket_minutes,
                "first_seen": ts,
                "last_seen": ts,
                "event_count": 0,
                "sample_source_index": source_index,
                "sample_document_id": doc_id,
                "sample_alert": alert,
                "case_type": classify_case_type(alert),
                "max_rule_level": to_int(first_value(alert, ["rule.level"], 0), 0),
                "rule_levels": collections.Counter(),
                "asset": get_asset(alert, assets),
                "srcip": collections.Counter(),
                "dstip": collections.Counter(),
                "dstport": collections.Counter(),
                "proto": collections.Counter(),
                "url": collections.Counter(),
                "user": collections.Counter(),
                "user_agent": collections.Counter(),
                "file_path": collections.Counter(),
                "file_hash": collections.Counter(),
                "cve": collections.Counter(),
                "sca_check": collections.Counter(),
            }

        bucket = buckets[case_key]
        bucket["event_count"] += 1
        bucket["first_seen"] = min(bucket["first_seen"], ts)
        bucket["last_seen"] = max(bucket["last_seen"], ts)
        current_rule_level = to_int(first_value(alert, ["rule.level"], 0), 0)
        bucket["max_rule_level"] = max(bucket["max_rule_level"], current_rule_level)
        bucket["rule_levels"][current_rule_level] += 1

        for field in ["srcip", "dstip", "dstport", "proto", "url", "user", "user_agent", "file_path", "file_hash", "cve", "sca_check"]:
            value = observed.get(field)
            if value:
                bucket[field][value] += 1

    if skipped:
        logging.warning("Skipped malformed alerts: %d (details limited to first 10)", skipped)
    return buckets


def destination_index_for_bucket(config: Dict[str, Any], bucket_iso: str) -> str:
    parsed = parse_dt(bucket_iso) or utc_now()
    prefix = config.get("destination_index_prefix", "siem-alarm")
    return f"{prefix}-{parsed.strftime('%Y.%m.%d')}"


def normalize_level_history(value: Any) -> List[Dict[str, str]]:
    if not isinstance(value, list):
        return []
    history = []
    for item in value:
        if not isinstance(item, dict):
            continue
        level = item.get("level")
        at = item.get("at")
        if level and at:
            history.append({"level": str(level), "at": str(at)})
    return history


def build_doc(bucket: Dict[str, Any], config: Dict[str, Any], existing_doc: Optional[Dict[str, Any]] = None) -> Tuple[str, Dict[str, Any]]:
    sample = bucket["sample_alert"]
    count = int(bucket["event_count"])
    level_counter = bucket.get("rule_levels", collections.Counter())
    rule_level_strategy = str(config.get("threat_level_strategy", "max")).lower()
    rule_level = select_rule_level(level_counter, rule_level_strategy)
    max_level = int(bucket["max_rule_level"])
    mode_level = select_rule_level(level_counter, "mode")
    median_level = select_rule_level(level_counter, "median")
    t_score = threat_score(rule_level)
    f_score = frequency_score(count)
    asset = bucket["asset"]
    a_score = int(asset["value"])
    r_score = round((a_score + t_score + f_score) / 3.0, 2)
    r_level = risk_level(r_score)
    action, sla, notify = recommended_action(r_level, a_score, t_score, f_score)
    previous_level = None
    level_history: List[Dict[str, str]] = []

    if isinstance(existing_doc, dict):
        existing_risk = existing_doc.get("risk", {})
        if isinstance(existing_risk, dict):
            previous = existing_risk.get("level")
            previous_level = str(previous) if previous not in (None, "") else None
            level_history = normalize_level_history(existing_risk.get("level_history"))

    level_changed = previous_level is not None and risk_rank(r_level) > risk_rank(previous_level)
    if not level_history:
        level_history.append({"level": r_level if previous_level is None else previous_level, "at": iso_z(bucket["first_seen"])})
    if level_changed and (not level_history or level_history[-1].get("level") != r_level):
        level_history.append({"level": r_level, "at": iso_z(bucket["last_seen"])})
    write_escalation_log = escalation_log_required(r_level, previous_level, config)

    doc_id = make_id(bucket["case_key"])
    groups = get_rule_groups(sample)

    limit_sample = int(config.get("evidence_sample_limit", 20))
    limit_top = int(config.get("evidence_top_limit", 10))

    doc = {
        "timestamp": bucket["bucket_start"],
        "document": {
            "type": "alarm_state",
        },
        "alarm": {
            "id": doc_id,
            "case_key": bucket["case_key"],
            "deduplication_mode": bucket["deduplication_mode"],
            "case_type": bucket["case_type"],
            "status": "open",
            "dedup_key_fields": bucket["dedup_key_fields"],
            "bucket_start": bucket["bucket_start"],
            "bucket_size": bucket_size_label(int(bucket["bucket_minutes"])),
            "first_seen": iso_z(bucket["first_seen"]),
            "last_seen": iso_z(bucket["last_seen"]),
            "event_count": count,
        },
        "agent": {
            "id": safe_str(first_value(sample, ["agent.id"], "000")),
            "name": safe_str(first_value(sample, ["agent.name"], "unknown")),
            "ip": normalize_observed(first_value(sample, ["agent.ip"], None)),
        },
        "rule": {
            "id": safe_str(first_value(sample, ["rule.id"], "unknown")),
            "level": rule_level,
            "level_strategy": rule_level_strategy,
            "max_level": max_level,
            "mode_level": mode_level,
            "median_level": median_level,
            "level_counts": rule_level_counts(level_counter),
            "description": safe_str(first_value(sample, ["rule.description"], "Unknown rule")),
            "groups": groups,
        },
        "source_observed": {
            "srcip_unique_count": len(bucket["srcip"]),
            "srcip_samples": sample_values(bucket["srcip"], limit_sample),
            "top_srcip": count_values(bucket["srcip"], limit_top),
        },
        "target_observed": {
            "dstip_unique_count": len(bucket["dstip"]),
            "dstip_samples": sample_values(bucket["dstip"], limit_sample),
            "top_dstip": count_values(bucket["dstip"], limit_top),
            "dstport_unique_count": len(bucket["dstport"]),
            "dstport_samples": sample_values(bucket["dstport"], limit_sample),
            "proto_unique_count": len(bucket["proto"]),
            "proto_samples": sample_values(bucket["proto"], limit_sample),
        },
        "entity_observed": {
            "url_unique_count": len(bucket["url"]),
            "url_samples": sample_values(bucket["url"], limit_sample),
            "top_url": count_values(bucket["url"], limit_top),
            "user_unique_count": len(bucket["user"]),
            "user_samples": sample_values(bucket["user"], limit_sample),
            "user_agent_unique_count": len(bucket["user_agent"]),
            "user_agent_samples": sample_values(bucket["user_agent"], limit_sample),
            "file_path_unique_count": len(bucket["file_path"]),
            "file_path_samples": sample_values(bucket["file_path"], limit_sample),
            "file_hash_unique_count": len(bucket["file_hash"]),
            "file_hash_samples": sample_values(bucket["file_hash"], limit_sample),
            "cve_unique_count": len(bucket["cve"]),
            "cve_samples": sample_values(bucket["cve"], limit_sample),
            "sca_check_unique_count": len(bucket["sca_check"]),
            "sca_check_samples": sample_values(bucket["sca_check"], limit_sample),
        },
        "asset": {
            "value": a_score,
            "category": asset["category"],
            "type": asset["type"],
            "owner": asset["owner"],
            "environment": asset["environment"],
            "source": asset["source"],
        },
        "risk": {
            "asset_value": a_score,
            "threat_score": t_score,
            "frequency_count_1h": count,
            "frequency_score": f_score,
            "score": r_score,
            "level": r_level,
            "previous_level": previous_level,
            "level_changed": level_changed,
            "escalation_log_required": write_escalation_log,
            "level_history": level_history,
            "formula": "(A+B+C)/3",
        },
        "source": {
            "index": bucket["sample_source_index"],
            "raw_alert_count": count,
            "sample_document_id": bucket["sample_document_id"],
        },
        "soc": {
            "recommended_action": action,
            "sla": sla,
            "notification": write_escalation_log,
            "escalation_log": write_escalation_log,
        },
    }

    if doc["agent"]["ip"] is None:
        del doc["agent"]["ip"]

    return doc_id, doc


def build_escalation_doc(state_doc: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
    risk = state_doc["risk"]
    level = risk["level"]
    previous_level = risk.get("previous_level")
    alarm_id = state_doc["alarm"]["id"]
    event_id = make_id(f"escalation|{alarm_id}|{level}")
    now = iso_z(utc_now())

    doc = {
        "timestamp": state_doc["alarm"]["last_seen"],
        "document": {
            "type": "alarm_escalation",
        },
        "event": {
            "kind": "alert",
            "category": ["siem_alarm"],
            "type": ["change"],
            "action": "risk_level_escalated",
            "created": now,
        },
        "escalation": {
            "id": event_id,
            "state_alarm_id": alarm_id,
            "level": level,
            "previous_level": previous_level,
            "reason": "initial_eligible_level" if previous_level is None else "risk_level_increased",
        },
        "alarm": state_doc["alarm"],
        "agent": state_doc["agent"],
        "rule": state_doc["rule"],
        "source_observed": state_doc["source_observed"],
        "target_observed": state_doc["target_observed"],
        "entity_observed": state_doc["entity_observed"],
        "asset": state_doc["asset"],
        "risk": risk,
        "source": state_doc["source"],
        "soc": {
            "recommended_action": state_doc["soc"]["recommended_action"],
            "sla": state_doc["soc"]["sla"],
            "notification": True,
            "escalation_log": True,
        },
    }
    return event_id, doc


def template(config: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    destination_prefix = (config or {}).get("destination_index_prefix", "siem-alarm")
    keyword = {"type": "keyword", "ignore_above": 2048}
    return {
        "index_patterns": [f"{destination_prefix}-*"],
        "priority": 300,
        "version": 1,
        "_meta": {
            "managed_by": "siem-alarm-scoring",
            "schema_version": "1",
        },
        "template": {
            "settings": {
                "number_of_shards": 1,
                "number_of_replicas": 0,
                "refresh_interval": "30s",
            },
            "mappings": {
                "dynamic": True,
                "properties": {
                    "timestamp": {"type": "date"},
                    "document": {
                        "properties": {
                            "type": {"type": "keyword"},
                        }
                    },
                    "event": {
                        "properties": {
                            "kind": {"type": "keyword"},
                            "category": {"type": "keyword"},
                            "type": {"type": "keyword"},
                            "action": {"type": "keyword"},
                            "created": {"type": "date"},
                        }
                    },
                    "escalation": {
                        "properties": {
                            "id": {"type": "keyword"},
                            "state_alarm_id": {"type": "keyword"},
                            "level": {"type": "keyword"},
                            "previous_level": {"type": "keyword"},
                            "reason": {"type": "keyword"},
                        }
                    },
                    "alarm": {
                        "properties": {
                            "id": {"type": "keyword"},
                            "case_key": {"type": "keyword"},
                            "deduplication_mode": {"type": "keyword"},
                            "case_type": {"type": "keyword"},
                            "status": {"type": "keyword"},
                            "dedup_key_fields": {"type": "keyword"},
                            "bucket_start": {"type": "date"},
                            "bucket_size": {"type": "keyword"},
                            "first_seen": {"type": "date"},
                            "last_seen": {"type": "date"},
                            "event_count": {"type": "integer"},
                        }
                    },
                    "agent": {
                        "properties": {
                            "id": {"type": "keyword"},
                            "name": {"type": "keyword"},
                            "ip": {"type": "keyword"},
                        }
                    },
                    "rule": {
                        "properties": {
                            "id": {"type": "keyword"},
                            "level": {"type": "integer"},
                            "level_strategy": {"type": "keyword"},
                            "max_level": {"type": "integer"},
                            "mode_level": {"type": "integer"},
                            "median_level": {"type": "integer"},
                            "level_counts": {
                                "properties": {
                                    "level": {"type": "integer"},
                                    "count": {"type": "integer"},
                                }
                            },
                            "description": {
                                "type": "text",
                                "fields": {"keyword": {"type": "keyword", "ignore_above": 1024}},
                            },
                            "groups": {"type": "keyword"},
                        }
                    },
                    "source_observed": {
                        "properties": {
                            "srcip_unique_count": {"type": "integer"},
                            "srcip_samples": keyword,
                            "top_srcip": {
                                "properties": {
                                    "value": keyword,
                                    "count": {"type": "integer"},
                                }
                            },
                        }
                    },
                    "target_observed": {
                        "properties": {
                            "dstip_unique_count": {"type": "integer"},
                            "dstip_samples": keyword,
                            "top_dstip": {
                                "properties": {
                                    "value": keyword,
                                    "count": {"type": "integer"},
                                }
                            },
                            "dstport_unique_count": {"type": "integer"},
                            "dstport_samples": {"type": "keyword"},
                            "proto_unique_count": {"type": "integer"},
                            "proto_samples": {"type": "keyword"},
                        }
                    },
                    "entity_observed": {
                        "properties": {
                            "url_unique_count": {"type": "integer"},
                            "url_samples": keyword,
                            "top_url": {
                                "properties": {
                                    "value": keyword,
                                    "count": {"type": "integer"},
                                }
                            },
                            "user_unique_count": {"type": "integer"},
                            "user_samples": keyword,
                            "user_agent_unique_count": {"type": "integer"},
                            "user_agent_samples": keyword,
                            "file_path_unique_count": {"type": "integer"},
                            "file_path_samples": keyword,
                            "file_hash_unique_count": {"type": "integer"},
                            "file_hash_samples": {"type": "keyword"},
                            "cve_unique_count": {"type": "integer"},
                            "cve_samples": {"type": "keyword"},
                            "sca_check_unique_count": {"type": "integer"},
                            "sca_check_samples": {"type": "keyword"},
                        }
                    },
                    "asset": {
                        "properties": {
                            "value": {"type": "integer"},
                            "category": {"type": "keyword"},
                            "type": {"type": "keyword"},
                            "owner": {"type": "keyword"},
                            "environment": {"type": "keyword"},
                            "source": {"type": "keyword"},
                        }
                    },
                    "risk": {
                        "properties": {
                            "asset_value": {"type": "integer"},
                            "threat_score": {"type": "integer"},
                            "frequency_count_1h": {"type": "integer"},
                            "frequency_score": {"type": "integer"},
                            "score": {"type": "float"},
                            "level": {"type": "keyword"},
                            "previous_level": {"type": "keyword"},
                            "level_changed": {"type": "boolean"},
                            "escalation_log_required": {"type": "boolean"},
                            "level_history": {
                                "type": "nested",
                                "properties": {
                                    "level": {"type": "keyword"},
                                    "at": {"type": "date"},
                                },
                            },
                            "formula": {"type": "keyword"},
                        }
                    },
                    "source": {
                        "properties": {
                            "index": {"type": "keyword"},
                            "raw_alert_count": {"type": "integer"},
                            "sample_document_id": {"type": "keyword"},
                        }
                    },
                    "soc": {
                        "properties": {
                            "recommended_action": {"type": "keyword"},
                            "sla": {"type": "keyword"},
                            "notification": {"type": "boolean"},
                            "escalation_log": {"type": "boolean"},
                        }
                    },
                },
            },
        },
    }


def run_once(config: Dict[str, Any], gte_override: Optional[str] = None, lte_override: Optional[str] = None) -> int:
    client = OpenSearchClient(
        config["opensearch_url"],
        config["username"],
        config["password"],
        bool(config.get("verify_ssl", True)),
        config.get("ca_cert"),
        int(config.get("timeout", 60)),
        int(config.get("retry_attempts", 4)),
        float(config.get("retry_backoff_seconds", 1.0)),
    )

    if config.get("install_template", False):
        logging.info("Installing/updating index template: %s", config.get("template_name", "siem-alarm-template"))
        client.put_template(config.get("template_name", "siem-alarm-template"), template(config))

    assets = load_json(config.get("assets_file", "/opt/wazuh-risk-scoring/assets.json"), {})
    bucket_minutes = int(config.get("bucket_minutes", 60))
    lookback_minutes = int(config.get("lookback_minutes", bucket_minutes))
    lookback_overlap_minutes = int(config.get("lookback_overlap_minutes", 7))
    if gte_override:
        if not parse_dt(gte_override):
            raise RuntimeError(f"Invalid --from datetime: {gte_override}")
        if lte_override and not parse_dt(lte_override):
            raise RuntimeError(f"Invalid --to datetime: {lte_override}")
        gte = gte_override
        lte = lte_override or iso_z(utc_now())
        upper_inclusive = False
        logging.info("Manual window override enabled: gte=%s lt=%s", gte, lte)
    else:
        now = utc_now()
        current_bucket_start = bucket_start(now, bucket_minutes)
        if bool(config.get("process_current_bucket_only", True)):
            minutes_after_boundary = (now - current_bucket_start).total_seconds() / 60.0
            if lookback_overlap_minutes > 0 and minutes_after_boundary <= lookback_overlap_minutes:
                gte = iso_z(current_bucket_start - dt.timedelta(minutes=bucket_minutes))
            else:
                gte = iso_z(current_bucket_start)
        else:
            gte = iso_z(now - dt.timedelta(minutes=lookback_minutes))
        lte = iso_z(now)
        upper_inclusive = True

    logging.info(
        "Querying raw alerts from %s gte=%s %s=%s",
        config.get("source_index", "wazuh-alerts-*"),
        gte,
        "lte" if upper_inclusive else "lt",
        lte,
    )
    alerts = fetch_alerts(client, config, gte, lte, upper_inclusive)
    buckets = aggregate(alerts, assets, config)
    logging.info("Aggregated buckets: %d", len(buckets))

    written = 0
    destination_indices = set()
    for bucket in buckets.values():
        destination_index = destination_index_for_bucket(config, bucket["bucket_start"])
        destination_indices.add(destination_index)
        doc_id = make_id(bucket["case_key"])
        existing_doc = client.get_doc(destination_index, doc_id)
        doc_id, doc = build_doc(bucket, config, existing_doc)
        if doc.get("risk", {}).get("escalation_log_required"):
            escalation_id, escalation_doc = build_escalation_doc(doc)
            created = client.create_doc_if_absent(destination_index, escalation_id, escalation_doc)
            if created:
                written += 1
                logging.info("Created escalation document: %s", escalation_id)
            else:
                logging.info("Escalation document already exists: %s", escalation_id)
        # State is written after the immutable escalation event. If this write
        # fails, the next run retries the same deterministic escalation ID and
        # then advances state without losing the event.
        client.index_doc(destination_index, doc_id, doc)
        written += 1

    logging.info("Written/updated documents: %d indices=%s", written, sorted(destination_indices))
    return written


def load_config(path: str) -> Dict[str, Any]:
    config = load_json(path, None)
    if not isinstance(config, dict):
        raise RuntimeError(f"Invalid config file: {path}")
    for key in ["opensearch_url", "username"]:
        if not config.get(key):
            raise RuntimeError(f"Missing required config key: {key}")

    opensearch_url = str(config["opensearch_url"])
    if not opensearch_url.startswith("https://"):
        raise RuntimeError("opensearch_url must use https://")

    password_env = str(config.get("password_env", "WAZUH_PASS"))
    if not re.fullmatch(r"[A-Z_][A-Z0-9_]*", password_env):
        raise RuntimeError("password_env must be a valid uppercase environment variable name")

    password = config.get("password")
    if not password or str(password).startswith(("GANTI_", "CHANGE_")):
        password = os.environ.get(password_env)
    if not password or str(password).startswith(("GANTI_", "CHANGE_")):
        raise RuntimeError(
            f"Indexer password is missing; set environment variable {password_env} "
            "or provide a non-placeholder password"
        )
    config = dict(config)
    config["password"] = str(password)

    integer_defaults = {
        "timeout": 60,
        "retry_attempts": 4,
        "bucket_minutes": 60,
        "lookback_minutes": 60,
        "lookback_overlap_minutes": 7,
        "max_alerts_per_run": 50000,
        "page_size": 1000,
        "evidence_sample_limit": 20,
        "evidence_top_limit": 10,
    }
    integer_ranges = {
        "timeout": (1, 600),
        "retry_attempts": (1, 10),
        "bucket_minutes": (1, 1440),
        "lookback_minutes": (1, 10080),
        "lookback_overlap_minutes": (0, 1440),
        "max_alerts_per_run": (1, 10_000_000),
        "page_size": (1, 10000),
        "evidence_sample_limit": (1, 1000),
        "evidence_top_limit": (1, 1000),
    }
    for key, (minimum, maximum) in integer_ranges.items():
        try:
            value = int(config.get(key, integer_defaults[key]))
        except (TypeError, ValueError) as exc:
            raise RuntimeError(f"Config {key} must be an integer") from exc
        if not minimum <= value <= maximum:
            raise RuntimeError(f"Config {key} must be between {minimum} and {maximum}")
        config[key] = value

    try:
        retry_backoff = float(config.get("retry_backoff_seconds", 1.0))
    except (TypeError, ValueError) as exc:
        raise RuntimeError("retry_backoff_seconds must be numeric") from exc
    if not 0.1 <= retry_backoff <= 60.0:
        raise RuntimeError("retry_backoff_seconds must be between 0.1 and 60")
    config["retry_backoff_seconds"] = retry_backoff

    for key, default in {
        "verify_ssl": True,
        "install_template": False,
        "process_current_bucket_only": True,
        "escalation_log_enabled": True,
    }.items():
        value = config.get(key, default)
        if not isinstance(value, bool):
            raise RuntimeError(f"Config {key} must be true or false")
        config[key] = value

    bucket_minutes = config["bucket_minutes"]
    if 1440 % bucket_minutes != 0:
        raise RuntimeError("bucket_minutes must divide evenly into 1440 minutes")

    prefix = str(config.get("destination_index_prefix", "siem-alarm"))
    if not re.fullmatch(r"[a-z0-9][a-z0-9._-]*", prefix):
        raise RuntimeError("destination_index_prefix must be lowercase and OpenSearch-safe")
    config["destination_index_prefix"] = prefix

    mode = str(config.get("deduplication_mode", "coarse"))
    allowed_modes = {"coarse", "target_aware", "target_port_aware", "file_aware"}
    if mode not in allowed_modes:
        raise RuntimeError(f"deduplication_mode must be one of {sorted(allowed_modes)}")
    config["deduplication_mode"] = mode

    rule_overrides = config.get("rule_overrides", {})
    if not isinstance(rule_overrides, dict):
        raise RuntimeError("rule_overrides must be an object")
    for rule_id, override in rule_overrides.items():
        if not isinstance(override, dict):
            raise RuntimeError(f"rule_overrides.{rule_id} must be an object")
        override_mode = str(override.get("deduplication_mode", mode))
        if override_mode not in allowed_modes:
            raise RuntimeError(
                f"rule_overrides.{rule_id}.deduplication_mode must be one of {sorted(allowed_modes)}"
            )

    strategy = str(config.get("threat_level_strategy", "max")).lower()
    if strategy not in {"max", "mode", "median"}:
        raise RuntimeError("threat_level_strategy must be max, mode, or median")
    config["threat_level_strategy"] = strategy

    configured_levels = config.get("escalation_log_levels", ["Medium", "High", "Critical"])
    valid_levels = {"Information", "Low", "Medium", "High", "Critical"}
    if not isinstance(configured_levels, list) or not configured_levels:
        raise RuntimeError("escalation_log_levels must be a non-empty array")
    if any(str(level) not in valid_levels for level in configured_levels):
        raise RuntimeError(f"escalation_log_levels must only contain {sorted(valid_levels)}")
    config["escalation_log_levels"] = [str(level) for level in configured_levels]

    min_rule_level = config.get("min_rule_level")
    if min_rule_level is not None:
        try:
            min_rule_level = int(min_rule_level)
        except (TypeError, ValueError) as exc:
            raise RuntimeError("min_rule_level must be null or an integer") from exc
        if not 0 <= min_rule_level <= 15:
            raise RuntimeError("min_rule_level must be between 0 and 15")
        config["min_rule_level"] = min_rule_level

    for key in ["excluded_rule_ids", "excluded_rule_groups"]:
        if not isinstance(config.get(key, []), list):
            raise RuntimeError(f"{key} must be an array")

    for key in ["log_file", "assets_file", "lock_file"]:
        value = str(config.get(key, ""))
        if value and not os.path.isabs(value):
            raise RuntimeError(f"{key} must be an absolute path")

    if not config["verify_ssl"]:
        raise RuntimeError("verify_ssl=false is not allowed; Wazuh Indexer TLS verification is mandatory")
    ca_cert = config.get("ca_cert")
    if not ca_cert:
        raise RuntimeError("ca_cert is required for the Wazuh Indexer root CA")
    if not os.path.isfile(str(ca_cert)):
        raise RuntimeError(f"CA certificate not found: {ca_cert}")
    return config


def main() -> int:
    parser = argparse.ArgumentParser(description="Final SIEM alarm aggregation and risk scoring for Wazuh")
    parser.add_argument("--config", default="/opt/wazuh-risk-scoring/config.siem_alarm.json")
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--loop", action="store_true")
    parser.add_argument("--interval", type=int, default=300)
    parser.add_argument("--from", dest="from_time", help="Manual backfill start time, e.g. 2026-05-22T10:00:00Z")
    parser.add_argument("--to", dest="to_time", help="Manual backfill end time, defaults to now if omitted")
    parser.add_argument(
        "--install-template-only",
        action="store_true",
        help="Install/update the destination index template and exit",
    )
    args = parser.parse_args()

    config = load_config(args.config)
    setup_logging(config.get("log_file", "/opt/wazuh-risk-scoring/logs/siem_alarm_scoring.log"), config.get("log_level", "INFO"))

    if args.loop and (args.from_time or args.to_time):
        logging.error("--from/--to cannot be used with --loop")
        return 2
    if args.to_time and not args.from_time:
        logging.error("--to requires --from")
        return 2

    if args.from_time and args.to_time:
        parsed_from = parse_dt(args.from_time)
        parsed_to = parse_dt(args.to_time)
        if parsed_from is None or parsed_to is None or parsed_from >= parsed_to:
            logging.error("--from must be earlier than --to and both must include a timezone")
            return 2

    lock_file = str(config.get("lock_file", "/opt/wazuh-risk-scoring/logs/scoring.lock"))

    if args.install_template_only:
        try:
            with process_lock(lock_file):
                client = OpenSearchClient(
                    config["opensearch_url"],
                    config["username"],
                    config["password"],
                    bool(config.get("verify_ssl", True)),
                    config.get("ca_cert"),
                    int(config.get("timeout", 60)),
                    int(config.get("retry_attempts", 4)),
                    float(config.get("retry_backoff_seconds", 1.0)),
                )
                name = config.get("template_name", "siem-alarm-template")
                client.put_template(name, template(config))
                logging.info("Installed/updated index template: %s", name)
            return 0
        except Exception:
            logging.exception("Template installation failed")
            return 1

    if args.loop:
        while True:
            try:
                with process_lock(lock_file):
                    run_once(config)
            except Exception:
                logging.exception("Run failed")
            time.sleep(args.interval)
        return 0

    try:
        with process_lock(lock_file):
            run_once(config, args.from_time, args.to_time)
        return 0
    except Exception:
        logging.exception("Run failed")
        return 1


if __name__ == "__main__":
    sys.exit(main())
