#!/usr/bin/env python3
"""
siem_alarm_scoring_final.py

Final SOC alarm aggregation and risk scoring engine for Wazuh 4.14.7 AIO.

Core design:
- Read raw alerts from wazuh-alerts-*.
- Preserve wazuh-alerts-* as raw evidence.
- Write aggregated alarms to siem-alarm-YYYY.MM.DD.
- Read exact daily indexes with bounded, complete bucket snapshots.
- Batch existing-state reads with per-index _mget.
- Write create-only escalation events before idempotent state via bounded _bulk.
- Advance an atomic local checkpoint only after every planned window succeeds.
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


# Keep the payload sent by Wazuh Indexer intentionally small. Operators can
# extend this allow-list through source_includes for fields produced by custom
# decoders. The raw document remains available in wazuh-alerts-* as evidence.
DEFAULT_SOURCE_INCLUDES = [
    "timestamp",
    "agent.id",
    "agent.name",
    "agent.ip",
    "agent.labels",
    "rule.id",
    "rule.level",
    "rule.description",
    "rule.groups",
    "rule.group",
    "decoder.name",
    "srcip",
    "dstip",
    "dstport",
    "proto",
    "protocol",
    "source.ip",
    "destination.ip",
    "destination.port",
    "network.transport",
    "url.path",
    "http.request.referrer",
    "user.name",
    "user_agent.original",
    "file.path",
    "file.hash.sha256",
    "syscheck.path",
    "syscheck.sha256",
    "syscheck.sha256_after",
    "rootcheck.file",
    "vulnerability.cve",
    "sca.check.id",
    "data.srcip",
    "data.src_ip",
    "data.dstip",
    "data.dest_ip",
    "data.dstport",
    "data.dest_port",
    "data.proto",
    "data.protocol",
    "data.url",
    "data.user",
    "data.dstuser",
    "data.srcuser",
    "data.file",
    "data.sha256",
    "data.hash",
    "data.http.url",
    "data.http.hostname",
    "data.http.user_agent",
    "data.http_user_agent",
    "data.source.ip",
    "data.destination.ip",
    "data.destination.port",
    "data.vulnerability.cve",
    "data.sca.check.id",
    "data.win.eventdata.IpAddress",
    "data.win.eventdata.ipAddress",
    "data.win.eventdata.TargetUserName",
    "data.win.eventdata.SubjectUserName",
]

BULK_RETRYABLE_STATUSES = {429, 502, 503, 504}


def utc_now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def iso_z(value: dt.datetime) -> str:
    return value.astimezone(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def parse_dt(value: Any) -> Optional[dt.datetime]:
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    try:
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        # Wazuh's native alert timestamp commonly uses ±HHMM (for example
        # +0000 or +0300). Normalize it for consistent Python 3.9+ parsing.
        text = re.sub(r"([+-][0-9]{2})([0-9]{2})$", r"\1:\2", text)
        parsed = dt.datetime.fromisoformat(text)
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

    def request(
        self,
        method: str,
        path: str,
        body: Optional[Any] = None,
        params: Optional[Dict[str, Any]] = None,
        content_type: str = "application/json",
        attempts: Optional[int] = None,
    ) -> Dict[str, Any]:
        url = f"{self.base_url}/{path.lstrip('/')}"
        if params:
            url += "?" + urllib.parse.urlencode(params)
        if isinstance(body, bytes):
            data = body
        elif isinstance(body, str):
            data = body.encode("utf-8")
        else:
            data = json.dumps(body, ensure_ascii=False).encode("utf-8") if body is not None else None
        headers = dict(self.headers)
        headers["Content-Type"] = content_type
        req = urllib.request.Request(url, data=data, headers=headers, method=method.upper())
        request_attempts = self.retry_attempts if attempts is None else max(1, int(attempts))
        for attempt in range(1, request_attempts + 1):
            try:
                with urllib.request.urlopen(req, context=self.ctx, timeout=self.timeout) as response:
                    raw = response.read().decode("utf-8")
                    return json.loads(raw) if raw else {}
            except urllib.error.HTTPError as exc:
                error_body = exc.read().decode("utf-8", errors="replace")
                error = OpenSearchHTTPError(exc.code, method, url, error_body)
                if exc.code not in self.RETRYABLE_HTTP_STATUSES or attempt == request_attempts:
                    raise error from exc
                retry_after = exc.headers.get("Retry-After") if exc.headers else None
                self._wait_before_retry(attempt, request_attempts, error, retry_after)
            except urllib.error.URLError as exc:
                error = RuntimeError(f"OpenSearch connection error {method} {url}: {exc}")
                if attempt == request_attempts:
                    raise error from exc
                self._wait_before_retry(attempt, request_attempts, error)
        raise RuntimeError(f"OpenSearch request exhausted retries: {method} {url}")

    def _wait_before_retry(
        self,
        attempt: int,
        attempts: int,
        error: Exception,
        retry_after: Optional[str] = None,
    ) -> None:
        delay = self.retry_backoff_seconds * (2 ** (attempt - 1))
        if retry_after:
            try:
                delay = max(delay, float(retry_after))
            except ValueError:
                pass
        delay += random.uniform(0, min(1.0, delay * 0.25)) if delay else 0.0
        logging.warning(
            "OpenSearch request failed (attempt %d/%d): %s; retrying in %.2fs",
            attempt,
            attempts,
            error,
            delay,
        )
        time.sleep(delay)

    def put_template(self, name: str, template: Dict[str, Any]) -> Dict[str, Any]:
        return self.request("PUT", f"_index_template/{name}", template)

    def search(self, index: str, body: Dict[str, Any], params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        return self.request("POST", f"{index}/_search", body, params)

    def scroll(self, scroll_id: str, keepalive: str) -> Dict[str, Any]:
        # A lost scroll response is ambiguous: retrying the same cursor can
        # advance the context twice. The caller restarts the whole read bucket.
        return self.request(
            "POST",
            "_search/scroll",
            {"scroll": keepalive, "scroll_id": scroll_id},
            attempts=1,
        )

    def clear_scroll(self, scroll_id: str) -> None:
        try:
            self.request("DELETE", "_search/scroll", {"scroll_id": [scroll_id]}, attempts=1)
        except Exception as exc:
            logging.debug("clear_scroll failed: %s", exc)

    def mget(self, index: str, ids: List[str]) -> Dict[str, Any]:
        return self.request(
            "POST",
            f"{index}/_mget",
            {"ids": ids},
            {
                "_source_includes": "risk.level,risk.level_history",
                "realtime": "true",
            },
        )

    def bulk(self, index: str, payload: bytes) -> Dict[str, Any]:
        return self.request(
            "POST",
            f"{index}/_bulk",
            payload,
            {"refresh": "false"},
            content_type="application/x-ndjson",
        )


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


ASSET_ENTRY_KEYS = {
    "agent_name",
    "asset_value",
    "value",
    "asset_category",
    "category",
    "asset_type",
    "type",
    "asset_owner",
    "owner",
    "environment",
    "asset_environment",
}


def parse_asset_value(value: Any, context: str) -> int:
    if isinstance(value, bool):
        raise RuntimeError(f"{context} must be an integer from 1 to 5, not a boolean")
    if isinstance(value, int):
        parsed = value
    elif isinstance(value, str) and re.fullmatch(r"[1-5]", value.strip()):
        parsed = int(value.strip())
    else:
        raise RuntimeError(f"{context} must be an integer from 1 to 5")
    if not 1 <= parsed <= 5:
        raise RuntimeError(f"{context} must be between 1 and 5")
    return parsed


def validate_assets(assets: Any, source: str = "asset inventory") -> Dict[str, Any]:
    if not isinstance(assets, dict):
        raise RuntimeError(f"{source} must contain one top-level JSON object")

    alias_pairs = [
        ("asset_value", "value"),
        ("asset_category", "category"),
        ("asset_type", "type"),
        ("asset_owner", "owner"),
        ("environment", "asset_environment"),
    ]
    text_fields = {
        "agent_name",
        "asset_category",
        "category",
        "asset_type",
        "type",
        "asset_owner",
        "owner",
        "environment",
        "asset_environment",
    }

    for lookup_key, entry in assets.items():
        if (
            not isinstance(lookup_key, str)
            or not lookup_key.strip()
            or lookup_key != lookup_key.strip()
        ):
            raise RuntimeError(f"{source} contains an empty, padded, or non-string lookup key")
        context = f"{source}[{lookup_key!r}]"
        if not isinstance(entry, dict):
            raise RuntimeError(f"{context} must be a JSON object")
        unknown = sorted(set(entry) - ASSET_ENTRY_KEYS)
        if unknown:
            raise RuntimeError(f"{context} contains unsupported field(s): {', '.join(unknown)}")
        for primary, alias in alias_pairs:
            if primary in entry and alias in entry:
                raise RuntimeError(f"{context} must not define both {primary} and {alias}")
        if "asset_value" not in entry and "value" not in entry:
            raise RuntimeError(f"{context} must define asset_value")

        value = parse_asset_value(entry.get("asset_value", entry.get("value")), f"{context}.asset_value")
        category = entry.get("asset_category", entry.get("category"))
        if category is not None and category != asset_category(value):
            raise RuntimeError(
                f"{context}.asset_category must be {asset_category(value)!r} for asset_value={value}"
            )
        for field_name in text_fields:
            if field_name in entry and (
                not isinstance(entry[field_name], str) or not entry[field_name].strip()
            ):
                raise RuntimeError(f"{context}.{field_name} must be a non-empty string")
    return assets


def load_asset_inventory(path: Any) -> Dict[str, Any]:
    asset_path = str(path or "").strip()
    if not asset_path:
        raise RuntimeError("assets_file must point to the root-owned asset inventory")
    if not os.path.isfile(asset_path):
        raise RuntimeError(f"Asset inventory is missing or not a regular file: {asset_path}")
    return validate_assets(load_json(asset_path, None), asset_path)


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
    for path in ["agent.id", "rule.id"]:
        if first_value(alert, [path], None) in (None, "", "-", "null", "None"):
            errors.append(f"{path} is required")
    raw_level = first_value(alert, ["rule.level"], None)
    try:
        level = int(str(raw_level))
        if not 0 <= level <= 16:
            errors.append("rule.level must be between 0 and 16")
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
        "agent.labels.asset.value", "agent.labels.asset_value"
    ])
    if value is None:
        return None
    asset_value = parse_asset_value(value, "agent.labels.asset.value")
    category = safe_str(first_value(alert, [
        "agent.labels.asset.category", "agent.labels.asset_category"
    ], asset_category(asset_value)))
    if category != asset_category(asset_value):
        raise RuntimeError(
            "agent.labels.asset.category must be "
            f"{asset_category(asset_value)!r} for agent.labels.asset.value={asset_value}"
        )
    return {
        "value": asset_value,
        "category": category,
        "type": safe_str(first_value(alert, [
            "agent.labels.asset.type", "agent.labels.asset_type"
        ], "Unknown")),
        "owner": safe_str(first_value(alert, [
            "agent.labels.asset.owner", "agent.labels.asset_owner"
        ], "Unknown")),
        "environment": safe_str(first_value(alert, [
            "agent.labels.asset.environment",
            "agent.labels.environment"
        ], "Unknown")),
        "source": "agent_label",
    }


def get_asset(
    alert: Dict[str, Any],
    assets: Dict[str, Any],
    warned_missing: Optional[set] = None,
) -> Dict[str, Any]:
    agent_id = safe_str(first_value(alert, ["agent.id"], "000"))
    agent_name = safe_str(first_value(alert, ["agent.name"], "unknown"))
    entry = assets.get(agent_id) if isinstance(assets, dict) else None
    matched_by_id = isinstance(entry, dict)
    if not entry and isinstance(assets, dict):
        entry = assets.get(agent_name)

    if isinstance(entry, dict):
        expected_name = entry.get("agent_name")
        if matched_by_id and expected_name is not None and expected_name != agent_name:
            raise RuntimeError(
                f"Asset inventory mismatch for agent.id={agent_id}: expected agent_name={expected_name!r}, "
                f"alert contains {agent_name!r}. Review re-enrollment or stale inventory before continuing."
            )
        value = parse_asset_value(
            entry.get("asset_value", entry.get("value")),
            f"asset inventory entry for agent.id={agent_id}",
        )
        return {
            "value": value,
            "category": safe_str(entry.get("asset_category", entry.get("category", asset_category(value)))),
            "type": safe_str(entry.get("asset_type", entry.get("type", "Unknown"))),
            "owner": safe_str(entry.get("asset_owner", entry.get("owner", "Unknown"))),
            "environment": safe_str(entry.get("environment", entry.get("asset_environment", "Unknown"))),
            "source": "assets_json",
        }

    # Only Wazuh's official agent.labels namespace is trusted as a fallback.
    # Root-level labels/asset fields can originate in decoded event payloads.
    labelled = read_asset_from_labels(alert)
    if labelled:
        return labelled

    warning_key = (agent_id, agent_name)
    if warned_missing is None or warning_key not in warned_missing:
        logging.warning("No asset metadata for agent.id=%s agent.name=%s. Defaulting to Medium.", agent_id, agent_name)
        if warned_missing is not None:
            warned_missing.add(warning_key)
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
    filters = [{"range": {"timestamp": {"gte": gte, upper_op: lte}}}]
    must_not = []

    min_level = config.get("min_rule_level")
    if min_level is not None:
        filters.append({"range": {"rule.level": {"gte": int(min_level)}}})

    excluded_rule_ids = [str(x) for x in config.get("excluded_rule_ids", [])]
    if excluded_rule_ids:
        must_not.append({"terms": {"rule.id": excluded_rule_ids}})

    excluded_groups = [str(x) for x in config.get("excluded_rule_groups", [])]
    if excluded_groups:
        must_not.append({"terms": {"rule.groups": excluded_groups}})

    return {"bool": {"filter": filters, "must_not": must_not}}


def configured_source_includes(config: Dict[str, Any]) -> List[str]:
    configured = config.get("source_includes", [])
    if configured is None:
        configured = []
    if not isinstance(configured, list) or any(not isinstance(item, str) or not item.strip() for item in configured):
        raise RuntimeError("source_includes must be an array of non-empty field names")
    return sorted(set(DEFAULT_SOURCE_INCLUDES).union(item.strip() for item in configured))


def source_index_for_window(
    config: Dict[str, Any],
    gte: str,
    lte: str,
    upper_inclusive: bool = False,
) -> str:
    pattern = str(config.get("source_index", "wazuh-alerts-4.x-{date}")).strip()
    if "{date}" not in pattern:
        return pattern
    start = parse_dt(gte)
    end = parse_dt(lte)
    if start is None or end is None:
        raise RuntimeError(f"Cannot resolve source index for invalid window: {gte} .. {lte}")
    start = start.astimezone(dt.timezone.utc)
    end = end.astimezone(dt.timezone.utc)
    if end < start or (end == start and not upper_inclusive):
        raise RuntimeError(f"Cannot resolve source index for empty or reversed window: {gte} .. {lte}")
    effective_end = end if upper_inclusive else end - dt.timedelta(microseconds=1)
    names: List[str] = []
    cursor = start.date()
    last_date = effective_end.date()
    while cursor <= last_date:
        names.append(pattern.replace("{date}", cursor.strftime("%Y.%m.%d")))
        cursor += dt.timedelta(days=1)
    return ",".join(names)


def exact_total_hits(response: Dict[str, Any], context: str) -> int:
    hits = response.get("hits")
    if not isinstance(hits, dict):
        raise RuntimeError(f"OpenSearch returned malformed hits during {context}")
    total = hits.get("total")
    if isinstance(total, int):
        return total
    if isinstance(total, dict):
        relation = total.get("relation", "eq")
        value = total.get("value")
        if relation != "eq" or not isinstance(value, int) or value < 0:
            raise RuntimeError(f"OpenSearch did not return an exact hit total during {context}: {total}")
        return value
    raise RuntimeError(f"OpenSearch omitted the exact hit total during {context}")


def fetch_alerts(client: OpenSearchClient, config: Dict[str, Any], gte: str, lte: str, upper_inclusive: bool = True) -> Iterable[Tuple[str, str, Dict[str, Any]]]:
    max_alerts = int(config.get("max_alerts_per_bucket", config.get("max_alerts_per_run", 100000)))
    request_timeout = int(config.get("timeout", 60))
    body = {
        "size": int(config.get("page_size", 1000)),
        "query": build_query(config, gte, lte, upper_inclusive),
        "sort": ["_doc"],
        # Exact below the guard, early lower-bound once the guard is exceeded.
        # This avoids counting millions of matches merely to reject the bucket.
        "track_total_hits": max_alerts + 1 if max_alerts > 0 else True,
        "timeout": f"{max(1, request_timeout - 5)}s",
        "_source": {"includes": configured_source_includes(config)},
    }
    keepalive = config.get("scroll_keepalive", "2m")
    emitted = 0
    source_index = source_index_for_window(config, gte, lte, upper_inclusive)
    response = client.search(
        source_index,
        body,
        {"scroll": keepalive, "ignore_unavailable": "true", "allow_no_indices": "true"},
    )
    validate_search_response(response, "initial alert search")
    scroll_id = response.get("_scroll_id")

    try:
        shards = response.get("_shards", {})
        resolved_shards = to_int(shards.get("total"), 0) if isinstance(shards, dict) else 0
        if resolved_shards < 1:
            raise RuntimeError(
                f"No concrete Wazuh alert index resolved for source={source_index}; "
                "bucket aborted so an empty snapshot cannot advance the checkpoint"
            )
        total_value = response.get("hits", {}).get("total")
        if isinstance(total_value, dict) and total_value.get("relation") == "gte":
            lower_bound = total_value.get("value")
            if isinstance(lower_bound, int) and max_alerts > 0 and lower_bound > max_alerts:
                raise RuntimeError(
                    f"max_alerts_per_bucket exceeded (at least {lower_bound}>{max_alerts}); "
                    f"bucket aborted before any write for gte={gte} "
                    f"{'lte' if upper_inclusive else 'lt'}={lte}"
                )
        expected = exact_total_hits(response, "initial alert search")
        if max_alerts > 0 and expected > max_alerts:
            raise RuntimeError(
                f"max_alerts_per_bucket exceeded ({expected}>{max_alerts}); bucket aborted before any write "
                f"for gte={gte} {'lte' if upper_inclusive else 'lt'}={lte}"
            )
        while emitted < expected:
            hits = response.get("hits", {}).get("hits")
            if not isinstance(hits, list):
                raise RuntimeError("OpenSearch returned malformed alert hits")
            if not hits:
                raise RuntimeError(
                    f"Incomplete scroll: expected {expected} alerts but received {emitted} for gte={gte} lt/lte={lte}"
                )
            for hit in hits:
                if not isinstance(hit, dict) or not isinstance(hit.get("_source"), dict):
                    raise RuntimeError("OpenSearch returned an alert hit without a valid _source")
                emitted += 1
                yield hit.get("_index", ""), hit.get("_id", ""), hit.get("_source", {})
            if emitted > expected:
                raise RuntimeError(
                    f"Scroll returned more alerts than its exact total ({emitted}>{expected}) for gte={gte} lt/lte={lte}"
                )
            if emitted == expected:
                break
            if not scroll_id:
                raise RuntimeError(
                    f"Incomplete scroll: cursor missing after {emitted}/{expected} alerts for gte={gte} lt/lte={lte}"
                )
            response = client.scroll(scroll_id, keepalive)
            validate_search_response(response, "alert scroll")
            next_scroll_id = response.get("_scroll_id")
            if not next_scroll_id:
                raise RuntimeError(
                    f"Incomplete scroll: continuation cursor missing after {emitted}/{expected} alerts"
                )
            scroll_id = next_scroll_id
        if emitted != expected:
            raise RuntimeError(f"Incomplete scroll: expected {expected} alerts but emitted {emitted}")
        logging.info(
            "Raw snapshot read complete: processed=%d expected=%d source=%s gte=%s %s=%s",
            emitted,
            expected,
            source_index,
            gte,
            "lte" if upper_inclusive else "lt",
            lte,
        )
    finally:
        if scroll_id:
            client.clear_scroll(scroll_id)


def count_values(counter: collections.Counter, limit: int) -> List[Dict[str, Any]]:
    ordered = sorted(counter.items(), key=lambda item: (-int(item[1]), str(item[0])))
    return [{"value": str(k), "count": int(v)} for k, v in ordered[:limit]]


def sample_values(counter: collections.Counter, limit: int) -> List[str]:
    ordered = sorted(counter.items(), key=lambda item: (-int(item[1]), str(item[0])))
    return [str(k) for k, _ in ordered[:limit]]


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
        highest_frequency = max(counter.values())
        return int(max(value for value, count in counter.items() if count == highest_frequency))
    if strategy == "median":
        return weighted_median(counter)
    return int(max(counter.keys()))


def rule_level_counts(counter: collections.Counter) -> List[Dict[str, int]]:
    return [{"level": int(level), "count": int(count)} for level, count in sorted(counter.items())]


def aggregate(alerts: Iterable[Tuple[str, str, Dict[str, Any]]], assets: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    validate_assets(assets)
    buckets: Dict[str, Dict[str, Any]] = {}
    bucket_minutes = int(config.get("bucket_minutes", 60))
    max_cases = int(config.get("max_cases_per_bucket", 20000))
    skipped = 0
    warned_missing_assets: set = set()

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
            if len(buckets) >= max_cases:
                raise RuntimeError(
                    f"max_cases_per_bucket exceeded ({len(buckets) + 1}>{max_cases}); "
                    "snapshot aborted before state writes. Review deduplication mode/noisy rules or "
                    "raise the limit only after a measured load test."
                )
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
                "sample_sort_key": (ts, str(source_index), str(doc_id)),
                "case_type": classify_case_type(alert),
                "max_rule_level": to_int(first_value(alert, ["rule.level"], 0), 0),
                "rule_levels": collections.Counter(),
                "asset": get_asset(alert, assets, warned_missing_assets),
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
        sample_sort_key = (ts, str(source_index), str(doc_id))
        if sample_sort_key < bucket["sample_sort_key"]:
            bucket["sample_sort_key"] = sample_sort_key
            bucket["sample_source_index"] = source_index
            bucket["sample_document_id"] = doc_id
            bucket["sample_alert"] = alert
            bucket["case_type"] = classify_case_type(alert)
            bucket["asset"] = get_asset(alert, assets, warned_missing_assets)
        current_rule_level = to_int(first_value(alert, ["rule.level"], 0), 0)
        bucket["max_rule_level"] = max(bucket["max_rule_level"], current_rule_level)
        bucket["rule_levels"][current_rule_level] += 1

        for field in ["srcip", "dstip", "dstport", "proto", "url", "user", "user_agent", "file_path", "file_hash", "cve", "sca_check"]:
            value = observed.get(field)
            if value:
                bucket[field][value] += 1

    if skipped:
        raise RuntimeError(
            f"Bucket contains {skipped} malformed alert(s); snapshot aborted before state writes "
            "(details logged for the first 10)"
        )
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
            # Bucket lifecycle only; this is not an analyst incident workflow status.
            "status": str(bucket.get("lifecycle_status", "open")),
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


def chunked(items: List[Any], size: int) -> Iterable[List[Any]]:
    for offset in range(0, len(items), size):
        yield items[offset:offset + size]


def load_existing_states(
    client: OpenSearchClient,
    references: List[Tuple[str, str]],
    config: Dict[str, Any],
) -> Dict[Tuple[str, str], Optional[Dict[str, Any]]]:
    unique_references = sorted(set(references))
    batch_size = int(config.get("mget_batch_size", 1000))
    retry_attempts = int(config.get("retry_attempts", 4))
    retry_backoff = float(config.get("retry_backoff_seconds", 1.0))
    states: Dict[Tuple[str, str], Optional[Dict[str, Any]]] = {}
    by_index: Dict[str, List[str]] = collections.defaultdict(list)
    for index, doc_id in unique_references:
        by_index[index].append(doc_id)

    for index in sorted(by_index):
        for id_batch in chunked(by_index[index], batch_size):
            pending_ids = list(id_batch)
            for attempt in range(1, retry_attempts + 1):
                batch = [(index, doc_id) for doc_id in pending_ids]
                requested = set(batch)
                try:
                    response = client.mget(index, pending_ids)
                except OpenSearchHTTPError as exc:
                    if exc.status == 404 and "index_not_found_exception" in exc.body:
                        for key in batch:
                            states[key] = None
                        pending_ids = []
                        break
                    raise
                returned = response.get("docs")
                if not isinstance(returned, list) or len(returned) != len(batch):
                    raise RuntimeError(
                        f"Malformed _mget response: expected {len(batch)} items, received "
                        f"{len(returned) if isinstance(returned, list) else 'non-array'}"
                    )
                seen = set()
                retry_ids: List[str] = []
                for item in returned:
                    if not isinstance(item, dict):
                        raise RuntimeError("Malformed _mget response item")
                    key = (str(item.get("_index", "")), str(item.get("_id", "")))
                    if key not in requested or key in seen:
                        raise RuntimeError(f"Unexpected or duplicate _mget response item: {key}")
                    seen.add(key)
                    error = item.get("error")
                    if error:
                        status = to_int(item.get("status"), 0)
                        error_type = error.get("type") if isinstance(error, dict) else None
                        if status == 404 and error_type == "index_not_found_exception":
                            states[key] = None
                            continue
                        if status in BULK_RETRYABLE_STATUSES and attempt < retry_attempts:
                            retry_ids.append(key[1])
                            continue
                        raise RuntimeError(f"_mget failed for index={key[0]} id={key[1]}: {error}")
                    if item.get("found") is False:
                        states[key] = None
                        continue
                    if item.get("found") is not True or not isinstance(item.get("_source"), dict):
                        raise RuntimeError(f"Malformed _mget document for index={key[0]} id={key[1]}")
                    states[key] = item["_source"]
                if seen != requested:
                    raise RuntimeError(f"_mget omitted {len(requested - seen)} requested document(s)")
                if not retry_ids:
                    pending_ids = []
                    break
                delay = retry_backoff * (2 ** (attempt - 1))
                delay += random.uniform(0, min(1.0, delay * 0.25)) if delay else 0.0
                logging.warning(
                    "Retrying %d failed _mget item(s) after %.2fs (attempt %d/%d)",
                    len(retry_ids),
                    delay,
                    attempt + 1,
                    retry_attempts,
                )
                time.sleep(delay)
                pending_ids = retry_ids
            if pending_ids:
                raise RuntimeError(f"_mget exhausted retries for {len(pending_ids)} document(s) in {index}")
    return states


def bulk_operation_key(operation: Dict[str, Any]) -> Tuple[str, str, str]:
    return (
        str(operation["action"]),
        str(operation["index"]),
        str(operation["id"]),
    )


def encode_bulk_operation(operation: Dict[str, Any]) -> bytes:
    cached = operation.get("_encoded")
    if isinstance(cached, bytes):
        return cached
    action = str(operation["action"])
    if action not in {"create", "index"}:
        raise RuntimeError(f"Unsupported bulk action: {action}")
    metadata = {action: {"_id": operation["id"]}}
    metadata_line = json.dumps(metadata, ensure_ascii=False, separators=(",", ":"))
    document_line = json.dumps(operation["document"], ensure_ascii=False, separators=(",", ":"))
    encoded = f"{metadata_line}\n{document_line}\n".encode("utf-8")
    # Cache the exact NDJSON bytes. Retries then resend the same frozen
    # snapshot and large documents are serialized only once per run.
    operation["_encoded"] = encoded
    return encoded


def build_bulk_batches(operations: List[Dict[str, Any]], config: Dict[str, Any]) -> List[List[Dict[str, Any]]]:
    max_actions = int(config.get("bulk_max_actions", 1000))
    max_bytes = int(config.get("bulk_max_bytes", 5 * 1024 * 1024))
    batches: List[List[Dict[str, Any]]] = []
    current: List[Dict[str, Any]] = []
    current_bytes = 0
    keys = set()

    for operation in operations:
        key = bulk_operation_key(operation)
        if key in keys:
            raise RuntimeError(f"Duplicate bulk operation: action={key[0]} index={key[1]} id={key[2]}")
        keys.add(key)
        operation_bytes = len(encode_bulk_operation(operation))
        if operation_bytes > max_bytes:
            raise RuntimeError(
                f"Bulk document exceeds bulk_max_bytes ({operation_bytes}>{max_bytes}): "
                f"index={key[1]} id={key[2]}"
            )
        if current and (len(current) >= max_actions or current_bytes + operation_bytes > max_bytes):
            batches.append(current)
            current = []
            current_bytes = 0
        current.append(operation)
        current_bytes += operation_bytes
    if current:
        batches.append(current)
    return batches


def parse_bulk_response(
    response: Dict[str, Any],
    operations: List[Dict[str, Any]],
) -> Dict[Tuple[str, str, str], Tuple[int, Any]]:
    items = response.get("items")
    if not isinstance(items, list) or len(items) != len(operations):
        raise RuntimeError(
            f"Malformed _bulk response: expected {len(operations)} items, received "
            f"{len(items) if isinstance(items, list) else 'non-array'}"
        )
    expected = {bulk_operation_key(operation) for operation in operations}
    parsed: Dict[Tuple[str, str, str], Tuple[int, Any]] = {}
    for item in items:
        if not isinstance(item, dict) or len(item) != 1:
            raise RuntimeError("Malformed _bulk response item")
        action, result = next(iter(item.items()))
        if not isinstance(result, dict):
            raise RuntimeError("Malformed _bulk action result")
        key = (str(action), str(result.get("_index", "")), str(result.get("_id", "")))
        status = result.get("status")
        if key not in expected or key in parsed or not isinstance(status, int):
            raise RuntimeError(f"Unexpected, duplicate, or malformed _bulk response item: {key}")
        parsed[key] = (status, result.get("error"))
    if set(parsed) != expected:
        raise RuntimeError(f"_bulk response omitted {len(expected - set(parsed))} operation(s)")
    return parsed


def execute_bulk_operations(
    client: OpenSearchClient,
    operations: List[Dict[str, Any]],
    config: Dict[str, Any],
) -> Tuple[Dict[Tuple[str, str, str], int], Dict[Tuple[str, str, str], str]]:
    accepted: Dict[Tuple[str, str, str], int] = {}
    failures: Dict[Tuple[str, str, str], str] = {}
    retry_attempts = int(config.get("retry_attempts", 4))
    retry_backoff = float(config.get("retry_backoff_seconds", 1.0))
    by_index: Dict[str, List[Dict[str, Any]]] = collections.defaultdict(list)
    for operation in operations:
        by_index[str(operation["index"])].append(operation)

    for index in sorted(by_index):
        for batch in build_bulk_batches(by_index[index], config):
            pending = list(batch)
            for attempt in range(1, retry_attempts + 1):
                payload = b"".join(encode_bulk_operation(operation) for operation in pending)
                response = client.bulk(index, payload)
                outcomes = parse_bulk_response(response, pending)
                retry_operations: List[Dict[str, Any]] = []
                for operation in pending:
                    key = bulk_operation_key(operation)
                    status, error = outcomes[key]
                    if 200 <= status < 300 or (key[0] == "create" and status == 409):
                        accepted[key] = status
                    elif status in BULK_RETRYABLE_STATUSES and attempt < retry_attempts:
                        retry_operations.append(operation)
                    else:
                        failures[key] = f"status={status} error={error}"
                if not retry_operations:
                    break
                delay = retry_backoff * (2 ** (attempt - 1))
                delay += random.uniform(0, min(1.0, delay * 0.25)) if delay else 0.0
                logging.warning(
                    "Retrying %d failed _bulk item(s) after %.2fs (attempt %d/%d)",
                    len(retry_operations),
                    delay,
                    attempt + 1,
                    retry_attempts,
                )
                time.sleep(delay)
                pending = retry_operations
    expected = {bulk_operation_key(operation) for operation in operations}
    covered = set(accepted).union(failures)
    if covered != expected or set(accepted).intersection(failures):
        raise RuntimeError("Internal _bulk accounting error: not every operation has exactly one outcome")
    return accepted, failures


def format_bulk_failures(failures: Dict[Tuple[str, str, str], str]) -> str:
    details = []
    for (action, index, doc_id), error in sorted(failures.items()):
        details.append(f"{action} {index}/{doc_id}: {error}")
    return "; ".join(details[:20]) + (f"; ... {len(details) - 20} more" if len(details) > 20 else "")


def process_bucket_rows_bulk(
    client: OpenSearchClient,
    config: Dict[str, Any],
    bucket_rows: List[Tuple[str, str, Dict[str, Any]]],
) -> int:
    references = [(index, doc_id) for index, doc_id, _ in bucket_rows]
    existing_states = load_existing_states(client, references, config)
    state_operations: List[Dict[str, Any]] = []
    escalation_operations: List[Dict[str, Any]] = []
    escalation_for_state: Dict[Tuple[str, str, str], Tuple[str, str, str]] = {}

    for destination_index, expected_doc_id, bucket in bucket_rows:
        existing_doc = existing_states[(destination_index, expected_doc_id)]
        doc_id, document = build_doc(bucket, config, existing_doc)
        state_operation = {
            "action": "index",
            "index": destination_index,
            "id": doc_id,
            "document": document,
        }
        state_operations.append(state_operation)
        state_key = bulk_operation_key(state_operation)
        if document.get("risk", {}).get("escalation_log_required"):
            escalation_id, escalation_document = build_escalation_doc(document)
            escalation_operation = {
                "action": "create",
                "index": destination_index,
                "id": escalation_id,
                "document": escalation_document,
            }
            escalation_operations.append(escalation_operation)
            escalation_for_state[state_key] = bulk_operation_key(escalation_operation)

    # Validate both phases and all document sizes before the first write.
    build_bulk_batches(escalation_operations, config)
    build_bulk_batches(state_operations, config)

    escalation_accepted, escalation_failures = execute_bulk_operations(
        client, escalation_operations, config
    )
    safe_state_operations = []
    for operation in state_operations:
        state_key = bulk_operation_key(operation)
        escalation_key = escalation_for_state.get(state_key)
        if escalation_key is None or escalation_key in escalation_accepted:
            safe_state_operations.append(operation)

    state_accepted, state_failures = execute_bulk_operations(client, safe_state_operations, config)
    all_failures = dict(escalation_failures)
    all_failures.update(state_failures)
    if all_failures:
        raise RuntimeError(f"One or more _bulk items failed; checkpoint not advanced: {format_bulk_failures(all_failures)}")

    created_events = sum(1 for status in escalation_accepted.values() if 200 <= status < 300)
    return created_events + len(state_accepted)


def process_buckets_bulk(
    client: OpenSearchClient,
    config: Dict[str, Any],
    buckets: Dict[str, Dict[str, Any]],
) -> int:
    if not buckets:
        return 0
    bucket_rows: List[Tuple[str, str, Dict[str, Any]]] = []
    for bucket in sorted(buckets.values(), key=lambda item: item["case_key"]):
        destination_index = destination_index_for_bucket(config, bucket["bucket_start"])
        doc_id = make_id(bucket["case_key"])
        bucket_rows.append((destination_index, doc_id, bucket))

    # Bound the additional memory used by materialized state/escalation JSON.
    # A failed later batch leaves earlier deterministic writes safe to replay;
    # the checkpoint still advances only after every batch succeeds.
    processing_batch_size = max(
        1,
        min(
            int(config.get("mget_batch_size", 1000)),
            int(config.get("bulk_max_actions", 1000)),
        ),
    )
    written = 0
    for row_batch in chunked(bucket_rows, processing_batch_size):
        written += process_bucket_rows_bulk(client, config, row_batch)
    return written


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


def stable_hash(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def case_identity_hash(config: Dict[str, Any]) -> str:
    return stable_hash(
        {
            "bucket_minutes": int(config.get("bucket_minutes", 60)),
            "source_index": config.get("source_index", "wazuh-alerts-4.x-{date}"),
            "min_rule_level": config.get("min_rule_level"),
            "excluded_rule_ids": sorted(str(item) for item in config.get("excluded_rule_ids", [])),
            "excluded_rule_groups": sorted(str(item) for item in config.get("excluded_rule_groups", [])),
            "deduplication_mode": config.get("deduplication_mode", "coarse"),
            "rule_overrides": config.get("rule_overrides", {}),
            "destination_index_prefix": config.get("destination_index_prefix", "siem-alarm"),
        }
    )


def scoring_config_hash(config: Dict[str, Any], assets: Dict[str, Any]) -> str:
    return stable_hash(
        {
            "threat_level_strategy": config.get("threat_level_strategy", "max"),
            "escalation_log_enabled": config.get("escalation_log_enabled", True),
            "escalation_log_levels": sorted(str(item) for item in config.get("escalation_log_levels", [])),
            "evidence_sample_limit": int(config.get("evidence_sample_limit", 20)),
            "evidence_top_limit": int(config.get("evidence_top_limit", 10)),
            "assets": assets,
        }
    )


def load_checkpoint(config: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    path = str(config.get("checkpoint_file", "")).strip()
    if not path or not os.path.exists(path):
        return None
    checkpoint = load_json(path, None)
    if not isinstance(checkpoint, dict) or checkpoint.get("schema_version") != 1:
        raise RuntimeError(f"Invalid checkpoint schema: {path}")
    marker = parse_dt(checkpoint.get("last_completed_bucket_end"))
    bucket_minutes = int(config.get("bucket_minutes", 60))
    if marker is None or marker != bucket_start(marker, bucket_minutes):
        raise RuntimeError(f"Invalid or unaligned checkpoint marker: {path}")
    expected_hash = case_identity_hash(config)
    checkpoint_hash = checkpoint.get("case_identity_hash")
    if checkpoint_hash != expected_hash:
        raise RuntimeError(
            "Checkpoint case identity does not match this configuration. Use a new destination prefix, "
            "or complete a controlled migration/backfill before replacing the checkpoint."
        )
    return checkpoint


def save_checkpoint(
    config: Dict[str, Any],
    marker: dt.datetime,
    assets: Dict[str, Any],
    run_metrics: Dict[str, Any],
) -> None:
    path = str(config.get("checkpoint_file", "")).strip()
    if not path:
        return
    directory = os.path.dirname(os.path.abspath(path))
    os.makedirs(directory, exist_ok=True)
    temporary_path = f"{path}.tmp.{os.getpid()}"
    record = {
        "schema_version": 1,
        "last_completed_bucket_end": iso_z(marker),
        "case_identity_hash": case_identity_hash(config),
        "scoring_config_hash": scoring_config_hash(config, assets),
        "updated_at": iso_z(utc_now()),
        "last_run": run_metrics,
    }
    try:
        with open(temporary_path, "w", encoding="utf-8") as handle:
            json.dump(record, handle, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary_path, 0o600)
        os.replace(temporary_path, path)
        if hasattr(os, "O_DIRECTORY"):
            directory_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
    finally:
        if os.path.exists(temporary_path):
            os.unlink(temporary_path)


def split_window(
    start: dt.datetime,
    end: dt.datetime,
    bucket_minutes: int,
    kind: str,
) -> List[Dict[str, str]]:
    windows: List[Dict[str, str]] = []
    cursor = start.astimezone(dt.timezone.utc)
    end = end.astimezone(dt.timezone.utc)
    bucket_delta = dt.timedelta(minutes=bucket_minutes)
    while cursor < end:
        next_boundary = bucket_start(cursor, bucket_minutes) + bucket_delta
        segment_end = min(end, next_boundary)
        windows.append({"kind": kind, "gte": iso_z(cursor), "lte": iso_z(segment_end)})
        cursor = segment_end
    return windows


def plan_run_windows(
    config: Dict[str, Any],
    now: Optional[dt.datetime] = None,
    gte_override: Optional[str] = None,
    lte_override: Optional[str] = None,
) -> Tuple[List[Dict[str, str]], Optional[dt.datetime]]:
    bucket_minutes = int(config.get("bucket_minutes", 60))
    bucket_delta = dt.timedelta(minutes=bucket_minutes)
    cutoff = (now or utc_now()).astimezone(dt.timezone.utc).replace(microsecond=0)
    checkpoint_path = str(config.get("checkpoint_file", "")).strip()
    checkpoint = load_checkpoint(config) if checkpoint_path else None

    if gte_override:
        start = parse_dt(gte_override)
        end = parse_dt(lte_override) if lte_override else cutoff
        if start is None or end is None or start >= end:
            raise RuntimeError("Manual --from/--to window must be valid, timezone-aware, and increasing")
        if start.astimezone(dt.timezone.utc) != bucket_start(start, bucket_minutes):
            raise RuntimeError("Manual --from must align to an aggregation bucket boundary")
        if lte_override and end.astimezone(dt.timezone.utc) != bucket_start(end, bucket_minutes):
            raise RuntimeError("Manual --to must align to a bucket boundary; omit --to only for the current bucket")
        return split_window(start, end, bucket_minutes, "manual"), None

    if not bool(config.get("process_current_bucket_only", True)):
        lookback = int(config.get("lookback_minutes", bucket_minutes))
        start = bucket_start(cutoff - dt.timedelta(minutes=lookback), bucket_minutes)
        windows = split_window(start, cutoff, bucket_minutes, "rolling")
        return windows, None

    current_start = bucket_start(cutoff, bucket_minutes)
    windows: List[Dict[str, str]] = []
    if current_start < cutoff:
        windows.append({"kind": "current", "gte": iso_z(current_start), "lte": iso_z(cutoff)})

    if not checkpoint_path:
        return windows, None

    finalization_delay = int(config.get("lookback_overlap_minutes", 7))
    eligible_end = bucket_start(cutoff - dt.timedelta(minutes=finalization_delay), bucket_minutes)
    if checkpoint:
        cursor = parse_dt(checkpoint["last_completed_bucket_end"])
        assert cursor is not None
        if cursor > eligible_end:
            raise RuntimeError(
                f"Checkpoint marker {iso_z(cursor)} is ahead of eligible closed-bucket end {iso_z(eligible_end)}"
            )
    else:
        # Bootstrap only the most recent finalized bucket; never replay an
        # unbounded history merely because this is the first deployment.
        cursor = eligible_end - bucket_delta

    max_catchup = int(config.get("max_catchup_buckets_per_run", 2))
    catchup_windows: List[Dict[str, str]] = []
    while cursor < eligible_end and len(catchup_windows) < max_catchup:
        catchup_windows.append(
            {
                "kind": "closed",
                "gte": iso_z(cursor),
                "lte": iso_z(cursor + bucket_delta),
            }
        )
        cursor += bucket_delta
    windows.extend(catchup_windows)
    return windows, cursor


def lifecycle_status_for_window(
    window: Dict[str, str],
    bucket_minutes: int,
    now: Optional[dt.datetime] = None,
) -> str:
    if window.get("kind") == "closed":
        return "finalized"
    end = parse_dt(window.get("lte"))
    cutoff = (now or utc_now()).astimezone(dt.timezone.utc)
    if (
        window.get("kind") in {"manual", "rolling"}
        and end is not None
        and end == bucket_start(end, bucket_minutes)
        and end <= bucket_start(cutoff, bucket_minutes)
    ):
        return "finalized"
    return "open"


def run_once(config: Dict[str, Any], gte_override: Optional[str] = None, lte_override: Optional[str] = None) -> int:
    run_started = time.monotonic()
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

    assets = load_asset_inventory(config.get("assets_file", "/opt/wazuh-risk-scoring/assets.json"))
    windows, checkpoint_target = plan_run_windows(
        config,
        gte_override=gte_override,
        lte_override=lte_override,
    )
    written = 0
    total_buckets = 0
    lifecycle_now = utc_now()
    for window in windows:
        source_index = source_index_for_window(config, window["gte"], window["lte"], False)
        logging.info(
            "Processing %s snapshot source=%s gte=%s lt=%s",
            window["kind"],
            source_index,
            window["gte"],
            window["lte"],
        )
        alerts = fetch_alerts(client, config, window["gte"], window["lte"], False)
        buckets = aggregate(alerts, assets, config)
        lifecycle_status = lifecycle_status_for_window(
            window,
            int(config.get("bucket_minutes", 60)),
            lifecycle_now,
        )
        for bucket in buckets.values():
            bucket["lifecycle_status"] = lifecycle_status
        total_buckets += len(buckets)
        written += process_buckets_bulk(client, config, buckets)
        logging.info("Completed %s snapshot: aggregate_buckets=%d", window["kind"], len(buckets))

    if checkpoint_target is not None:
        duration_seconds = round(time.monotonic() - run_started, 3)
        save_checkpoint(
            config,
            checkpoint_target,
            assets,
            {
                "windows": len(windows),
                "aggregate_buckets": total_buckets,
                "written_or_updated": written,
                "duration_seconds": duration_seconds,
                "completed": True,
            },
        )
    duration_seconds = round(time.monotonic() - run_started, 3)
    logging.info(
        "Run complete: windows=%d aggregate_buckets=%d written_or_updated=%d duration_seconds=%.3f",
        len(windows),
        total_buckets,
        written,
        duration_seconds,
    )
    return written


def load_config(path: str) -> Dict[str, Any]:
    config = load_json(path, None)
    if not isinstance(config, dict):
        raise RuntimeError(f"Invalid config file: {path}")
    for key in ["opensearch_url", "username"]:
        if not config.get(key):
            raise RuntimeError(f"Missing required config key: {key}")

    if str(config["username"]).lower() == "admin":
        raise RuntimeError("Indexer admin is not allowed for runtime; use the dedicated siem_alarm_service user")
    if "password" in config:
        raise RuntimeError("Inline password is not allowed; use password_env and the protected EnvironmentFile")

    opensearch_url = str(config["opensearch_url"])
    if not opensearch_url.startswith("https://"):
        raise RuntimeError("opensearch_url must use https://")

    password_env = str(config.get("password_env", "WAZUH_PASS"))
    if not re.fullmatch(r"[A-Z_][A-Z0-9_]*", password_env):
        raise RuntimeError("password_env must be a valid uppercase environment variable name")

    password = os.environ.get(password_env)
    if not password or str(password).startswith(("GANTI_", "CHANGE_")):
        raise RuntimeError(
            f"Indexer password is missing; set environment variable {password_env} "
            "through the protected EnvironmentFile"
        )
    config = dict(config)
    config["password"] = str(password)

    if "max_alerts_per_bucket" not in config and "max_alerts_per_run" in config:
        config["max_alerts_per_bucket"] = config["max_alerts_per_run"]
        logging.warning("max_alerts_per_run is deprecated; use max_alerts_per_bucket")

    integer_defaults = {
        "timeout": 60,
        "retry_attempts": 4,
        "bucket_minutes": 60,
        "lookback_minutes": 60,
        "lookback_overlap_minutes": 7,
        "max_alerts_per_bucket": 100000,
        "max_cases_per_bucket": 20000,
        "page_size": 1000,
        "mget_batch_size": 1000,
        "bulk_max_actions": 1000,
        "bulk_max_bytes": 5 * 1024 * 1024,
        "max_catchup_buckets_per_run": 2,
        "evidence_sample_limit": 20,
        "evidence_top_limit": 10,
    }
    integer_ranges = {
        "timeout": (1, 600),
        "retry_attempts": (1, 10),
        "bucket_minutes": (1, 1440),
        "lookback_minutes": (1, 10080),
        "lookback_overlap_minutes": (0, 1440),
        "max_alerts_per_bucket": (1, 10_000_000),
        "max_cases_per_bucket": (1, 1_000_000),
        "page_size": (1, 10000),
        "mget_batch_size": (1, 10000),
        "bulk_max_actions": (1, 10000),
        "bulk_max_bytes": (1024, 100 * 1024 * 1024),
        "max_catchup_buckets_per_run": (1, 24),
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

    source_index = str(config.get("source_index", "wazuh-alerts-4.x-{date}")).strip()
    if not source_index or source_index.lower() != source_index:
        raise RuntimeError("source_index must be non-empty and lowercase")
    if source_index.count("{date}") != 1:
        raise RuntimeError("source_index must contain exactly one {date} placeholder")
    resolved_source = source_index.replace("{date}", "2026.08.24")
    if not re.fullmatch(r"[a-z0-9][a-z0-9._-]*", resolved_source):
        raise RuntimeError("source_index must resolve to one exact lowercase daily index name")
    config["source_index"] = source_index
    configured_source_includes(config)

    scroll_keepalive = str(config.get("scroll_keepalive", "2m"))
    if not re.fullmatch(r"[1-9][0-9]*(?:ms|s|m|h)", scroll_keepalive):
        raise RuntimeError("scroll_keepalive must be a positive OpenSearch duration such as 2m")
    config["scroll_keepalive"] = scroll_keepalive

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
        if not 0 <= min_rule_level <= 16:
            raise RuntimeError("min_rule_level must be between 0 and 16")
        config["min_rule_level"] = min_rule_level

    for key in ["excluded_rule_ids", "excluded_rule_groups"]:
        if not isinstance(config.get(key, []), list):
            raise RuntimeError(f"{key} must be an array")

    for key in ["log_file", "assets_file", "lock_file", "checkpoint_file"]:
        value = str(config.get(key, ""))
        if value and not os.path.isabs(value):
            raise RuntimeError(f"{key} must be an absolute path")
        if value:
            config[key] = value

    if config["process_current_bucket_only"] and not str(config.get("checkpoint_file", "")).strip():
        logging.warning("checkpoint_file is not configured; bounded outage catch-up is disabled")

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
    parser.add_argument(
        "--validate-assets-only",
        metavar="PATH",
        help="Validate an assets.json file without connecting to the Indexer",
    )
    args = parser.parse_args()

    if args.validate_assets_only:
        if args.once or args.loop or args.from_time or args.to_time or args.install_template_only:
            parser.error("--validate-assets-only cannot be combined with runtime actions")
        try:
            assets = load_asset_inventory(args.validate_assets_only)
            print(f"[+] Asset inventory valid: {args.validate_assets_only} ({len(assets)} entries)")
            return 0
        except Exception as exc:
            print(f"[!] Asset inventory invalid: {exc}", file=sys.stderr)
            return 1

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
