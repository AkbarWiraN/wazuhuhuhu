#!/usr/bin/env python3
"""
siem_alarm_scoring_final.py

Final SOC alarm aggregation and risk scoring engine for Wazuh 4.14.x AIO.

Core design:
- Read raw alerts from wazuh-alerts-*.
- Preserve wazuh-alerts-* as raw evidence.
- Write aggregated alarms to siem-alarm-YYYY.MM.DD.
- Default same-alert definition is deliberately coarse:
    agent.id + rule.id + timestamp_bucket_1h
- srcip/dstip/dstport/proto/url/user/file fields are evidence only, not default split keys.
- source.raw_alert_count == alarm.event_count == risk.frequency_count_1h.

Dependencies:
- Python 3 standard library only.

Example:
sudo python3 /opt/wazuh-risk-scoring/siem_alarm_scoring_final.py \
  --config /opt/wazuh-risk-scoring/config.siem_alarm.json \
  --once
"""

from __future__ import annotations

import argparse
import base64
import collections
import datetime as dt
import hashlib
import json
import logging
import os
import re
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, Iterable, List, Optional, Tuple


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
        return dt.datetime.fromisoformat(text.replace("Z", "+00:00"))
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


class OpenSearchClient:
    def __init__(self, base_url: str, username: str, password: str, verify_ssl: bool = False, ca_cert: Optional[str] = None, timeout: int = 60):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
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
        try:
            with urllib.request.urlopen(req, context=self.ctx, timeout=self.timeout) as response:
                raw = response.read().decode("utf-8")
                return json.loads(raw) if raw else {}
        except urllib.error.HTTPError as exc:
            error_body = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"OpenSearch HTTP {exc.code} {method} {url}: {error_body}") from exc
        except urllib.error.URLError as exc:
            raise RuntimeError(f"OpenSearch connection error {method} {url}: {exc}") from exc

    def put_template(self, name: str, template: Dict[str, Any]) -> Dict[str, Any]:
        return self.request("PUT", f"_index_template/{name}", template)

    def index_doc(self, index: str, doc_id: str, doc: Dict[str, Any]) -> Dict[str, Any]:
        quoted = urllib.parse.quote(doc_id, safe="")
        return self.request("PUT", f"{index}/_doc/{quoted}", doc)

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


def asset_category(value: int) -> str:
    return {5: "Critical", 4: "High", 3: "Medium", 2: "Low", 1: "Minimal"}.get(value, "Medium")


def load_json(path: str, default: Any) -> Any:
    if not path or not os.path.exists(path):
        return default
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def setup_logging(log_file: str, level: str) -> None:
    os.makedirs(os.path.dirname(log_file), exist_ok=True)
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(message)s",
        handlers=[logging.FileHandler(log_file), logging.StreamHandler(sys.stdout)],
    )


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
    return hashlib.sha256(case_key.encode("utf-8")).hexdigest()[:32]


def build_query(config: Dict[str, Any], gte: str, lte: str) -> Dict[str, Any]:
    must = [{"range": {"timestamp": {"gte": gte, "lte": lte}}}]
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


def fetch_alerts(client: OpenSearchClient, config: Dict[str, Any], gte: str, lte: str) -> Iterable[Tuple[str, str, Dict[str, Any]]]:
    body = {
        "size": int(config.get("page_size", 1000)),
        "query": build_query(config, gte, lte),
        "sort": [{"timestamp": {"order": "asc"}}],
        "_source": True,
    }
    keepalive = config.get("scroll_keepalive", "2m")
    response = client.search(config.get("source_index", "wazuh-alerts-*"), body, {"scroll": keepalive})
    scroll_id = response.get("_scroll_id")

    try:
        while True:
            hits = response.get("hits", {}).get("hits", [])
            if not hits:
                break
            for hit in hits:
                yield hit.get("_index", ""), hit.get("_id", ""), hit.get("_source", {})
            if not scroll_id:
                break
            response = client.scroll(scroll_id, keepalive)
            scroll_id = response.get("_scroll_id", scroll_id)
    finally:
        if scroll_id:
            client.clear_scroll(scroll_id)


def count_values(counter: collections.Counter, limit: int) -> List[Dict[str, Any]]:
    return [{"value": str(k), "count": int(v)} for k, v in counter.most_common(limit)]


def sample_values(counter: collections.Counter, limit: int) -> List[str]:
    return [str(k) for k, _ in counter.most_common(limit)]


def aggregate(alerts: Iterable[Tuple[str, str, Dict[str, Any]]], assets: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    buckets: Dict[str, Dict[str, Any]] = {}
    bucket_minutes = int(config.get("bucket_minutes", 60))

    for source_index, doc_id, alert in alerts:
        ts = parse_dt(first_value(alert, ["timestamp"], None)) or utc_now()
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
        bucket["max_rule_level"] = max(bucket["max_rule_level"], to_int(first_value(alert, ["rule.level"], 0), 0))

        for field in ["srcip", "dstip", "dstport", "proto", "url", "user", "user_agent", "file_path", "file_hash", "cve", "sca_check"]:
            value = observed.get(field)
            if value:
                bucket[field][value] += 1

    return buckets


def build_doc(bucket: Dict[str, Any], config: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
    sample = bucket["sample_alert"]
    count = int(bucket["event_count"])
    rule_level = int(bucket["max_rule_level"])
    t_score = threat_score(rule_level)
    f_score = frequency_score(count)
    asset = bucket["asset"]
    a_score = int(asset["value"])
    r_score = round((a_score + t_score + f_score) / 3.0, 2)
    r_level = risk_level(r_score)
    action, sla, notify = recommended_action(r_level, a_score, t_score, f_score)

    doc_id = make_id(bucket["case_key"])
    groups = get_rule_groups(sample)

    limit_sample = int(config.get("evidence_sample_limit", 20))
    limit_top = int(config.get("evidence_top_limit", 10))

    doc = {
        "timestamp": bucket["bucket_start"],
        "alarm": {
            "id": doc_id,
            "case_key": bucket["case_key"],
            "deduplication_mode": bucket["deduplication_mode"],
            "case_type": bucket["case_type"],
            "status": "open",
            "dedup_key_fields": bucket["dedup_key_fields"],
            "bucket_start": bucket["bucket_start"],
            "bucket_size": f"{bucket['bucket_minutes']}m",
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
            "notification": notify,
        },
    }

    if doc["agent"]["ip"] is None:
        del doc["agent"]["ip"]

    return doc_id, doc


def template() -> Dict[str, Any]:
    keyword = {"type": "keyword", "ignore_above": 2048}
    return {
        "index_patterns": ["siem-alarm-*"],
        "priority": 300,
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
                        }
                    },
                },
            },
        },
    }


def run_once(config: Dict[str, Any]) -> int:
    client = OpenSearchClient(
        config["opensearch_url"],
        config["username"],
        config["password"],
        bool(config.get("verify_ssl", False)),
        config.get("ca_cert"),
        int(config.get("timeout", 60)),
    )

    if config.get("install_template", True):
        logging.info("Installing/updating index template: %s", config.get("template_name", "siem-alarm-template"))
        client.put_template(config.get("template_name", "siem-alarm-template"), template())

    assets = load_json(config.get("assets_file", "/opt/wazuh-risk-scoring/assets.json"), {})
    lookback_minutes = int(config.get("lookback_minutes", 60))
    now = utc_now()
    gte = iso_z(now - dt.timedelta(minutes=lookback_minutes))
    lte = iso_z(now)

    logging.info("Querying raw alerts from %s gte=%s lte=%s", config.get("source_index", "wazuh-alerts-*"), gte, lte)
    alerts = fetch_alerts(client, config, gte, lte)
    buckets = aggregate(alerts, assets, config)
    logging.info("Aggregated buckets: %d", len(buckets))

    destination_index = f"{config.get('destination_index_prefix', 'siem-alarm')}-{utc_now().strftime('%Y.%m.%d')}"
    written = 0
    for bucket in buckets.values():
        doc_id, doc = build_doc(bucket, config)
        client.index_doc(destination_index, doc_id, doc)
        written += 1

    logging.info("Written/updated documents: %d index=%s", written, destination_index)
    return written


def load_config(path: str) -> Dict[str, Any]:
    config = load_json(path, None)
    if not isinstance(config, dict):
        raise RuntimeError(f"Invalid config file: {path}")
    for key in ["opensearch_url", "username", "password"]:
        if not config.get(key):
            raise RuntimeError(f"Missing required config key: {key}")
    return config


def main() -> int:
    parser = argparse.ArgumentParser(description="Final SIEM alarm aggregation and risk scoring for Wazuh")
    parser.add_argument("--config", default="/opt/wazuh-risk-scoring/config.siem_alarm.json")
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--loop", action="store_true")
    parser.add_argument("--interval", type=int, default=300)
    args = parser.parse_args()

    config = load_config(args.config)
    setup_logging(config.get("log_file", "/opt/wazuh-risk-scoring/logs/siem_alarm_scoring.log"), config.get("log_level", "INFO"))

    if args.loop:
        while True:
            try:
                run_once(config)
            except Exception:
                logging.exception("Run failed")
            time.sleep(args.interval)
        return 0

    try:
        run_once(config)
        return 0
    except Exception:
        logging.exception("Run failed")
        return 1


if __name__ == "__main__":
    sys.exit(main())
