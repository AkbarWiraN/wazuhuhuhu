#!/usr/bin/env python3
"""
wazuh_field_audit_final.py

Field audit utility for wazuh-alerts-* before production use of siem-alarm-*.

Purpose:
- Sample raw alerts.
- List actual fields from your Wazuh environment.
- Show candidate fields for srcip, dstip, dstport, proto, url, user, file, CVE, SCA.
- Help detect field differences in built-in and custom Wazuh rules.

Dependency:
- Python 3 standard library only.
"""

from __future__ import annotations

import argparse
import base64
import collections
import datetime as dt
import getpass
import json
import os
import random
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, List


ALIASES = {
    "srcip": ["data.srcip", "data.src_ip", "srcip", "source.ip", "data.source.ip", "data.win.eventdata.IpAddress"],
    "dstip": ["data.dstip", "data.dest_ip", "data.destination.ip", "dstip", "destination.ip", "agent.ip"],
    "dstport": ["data.dstport", "data.dest_port", "data.destination.port", "destination.port", "dstport"],
    "proto": ["data.proto", "data.protocol", "network.transport", "proto", "protocol"],
    "url": ["data.url", "url.path", "http.request.referrer", "data.http.url", "data.http.hostname"],
    "user": ["data.user", "user.name", "data.dstuser", "data.srcuser", "data.win.eventdata.TargetUserName"],
    "file_path": ["syscheck.path", "file.path", "data.file", "rootcheck.file"],
    "file_hash": ["syscheck.sha256_after", "syscheck.sha256", "file.hash.sha256", "data.sha256", "data.hash"],
    "cve": ["vulnerability.cve", "data.vulnerability.cve"],
    "sca_check": ["sca.check.id", "data.sca.check.id"],
}


def flatten(data: Any, prefix: str = "") -> Dict[str, Any]:
    output = {}
    if isinstance(data, dict):
        for k, v in data.items():
            key = f"{prefix}.{k}" if prefix else str(k)
            output.update(flatten(v, key))
    else:
        output[prefix] = data
    return output


def get_path(data: Dict[str, Any], path: str, default: Any = None) -> Any:
    if path in data:
        return data[path]
    cur: Any = data
    for part in path.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return default
    return cur


class Client:
    RETRYABLE_HTTP_STATUSES = {429, 502, 503, 504}

    def __init__(
        self,
        url: str,
        username: str,
        password: str,
        verify_ssl: bool,
        ca_cert: str | None = None,
        retry_attempts: int = 4,
    ):
        self.url = url.rstrip("/")
        self.retry_attempts = max(1, retry_attempts)
        token = base64.b64encode(f"{username}:{password}".encode()).decode()
        self.headers = {
            "Authorization": f"Basic {token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        self.ctx = ssl.create_default_context(cafile=ca_cert) if verify_ssl else ssl._create_unverified_context()

    def request(self, method: str, path: str, body: Dict[str, Any] | None = None) -> Dict[str, Any]:
        url = f"{self.url}/{path.lstrip('/')}"
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(url, data=data, headers=self.headers, method=method.upper())
        for attempt in range(1, self.retry_attempts + 1):
            try:
                with urllib.request.urlopen(req, context=self.ctx, timeout=60) as response:
                    raw = response.read().decode("utf-8")
                    return json.loads(raw) if raw else {}
            except urllib.error.HTTPError as exc:
                body_text = exc.read().decode(errors="replace")
                if exc.code not in self.RETRYABLE_HTTP_STATUSES or attempt == self.retry_attempts:
                    raise RuntimeError(f"HTTP {exc.code}: {body_text}") from exc
                delay = (2 ** (attempt - 1)) + random.uniform(0, 0.25)
                print(f"[!] HTTP {exc.code}; retrying in {delay:.2f}s", file=sys.stderr)
                time.sleep(delay)
            except urllib.error.URLError as exc:
                if attempt == self.retry_attempts:
                    raise RuntimeError(f"Connection failed: {exc}") from exc
                delay = (2 ** (attempt - 1)) + random.uniform(0, 0.25)
                print(f"[!] Connection failed; retrying in {delay:.2f}s", file=sys.stderr)
                time.sleep(delay)
        raise RuntimeError("Indexer request exhausted retries")


def main() -> int:
    parser = argparse.ArgumentParser(description="Audit actual Wazuh alert fields")
    parser.add_argument("--url", default="https://127.0.0.1:9200")
    parser.add_argument("--user", default="siem_alarm_service")
    parser.add_argument("--password")
    parser.add_argument("--index", default="wazuh-alerts-*")
    parser.add_argument("--hours", type=int, default=24)
    parser.add_argument("--limit", type=int, default=3000)
    tls_group = parser.add_mutually_exclusive_group()
    tls_group.add_argument("--verify-ssl", dest="verify_ssl", action="store_true")
    tls_group.add_argument("--insecure", dest="verify_ssl", action="store_false")
    parser.set_defaults(verify_ssl=True)
    parser.add_argument("--ca-cert", help="CA certificate used with --verify-ssl")
    parser.add_argument("--retry-attempts", type=int, default=4)
    parser.add_argument(
        "--output",
        default="/opt/wazuh-risk-scoring/logs/wazuh_field_audit_report.json",
    )
    args = parser.parse_args()

    if args.hours <= 0:
        parser.error("--hours must be greater than zero")
    if not 1 <= args.limit <= 10000:
        parser.error("--limit must be between 1 and 10000")
    if not 1 <= args.retry_attempts <= 10:
        parser.error("--retry-attempts must be between 1 and 10")
    if args.verify_ssl and args.ca_cert and not os.path.isfile(args.ca_cert):
        parser.error(f"CA certificate not found: {args.ca_cert}")

    password = args.password or os.environ.get("WAZUH_PASS")
    if not password:
        password = getpass.getpass("Indexer password: ")

    client = Client(args.url, args.user, password, args.verify_ssl, args.ca_cert, args.retry_attempts)
    gte = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=args.hours)).isoformat().replace("+00:00", "Z")

    body = {
        "size": args.limit,
        "query": {"range": {"timestamp": {"gte": gte, "lte": "now"}}},
        "sort": [{"timestamp": {"order": "desc"}}],
        "_source": True,
    }
    response = client.request("POST", f"{args.index}/_search", body)
    if response.get("timed_out") is True:
        raise RuntimeError("Indexer search timed out")
    shards = response.get("_shards", {})
    if isinstance(shards, dict) and int(shards.get("failed", 0)) > 0:
        raise RuntimeError(f"Indexer search has failed shards: {shards.get('failures', [])}")
    hits = response.get("hits", {}).get("hits", [])

    all_fields = collections.Counter()
    rule_counter = collections.Counter()
    group_counter = collections.Counter()
    alias_hits = {name: collections.Counter() for name in ALIASES}
    rules: Dict[str, Dict[str, Any]] = {}

    for hit in hits:
        src = hit.get("_source", {})
        flat = flatten(src)
        all_fields.update(flat.keys())

        rule_id = str(get_path(src, "rule.id", "unknown"))
        rule_desc = str(get_path(src, "rule.description", ""))
        rule_level = get_path(src, "rule.level", None)
        groups = get_path(src, "rule.groups", []) or []
        if isinstance(groups, str):
            groups = [groups]

        rule_counter[rule_id] += 1
        for group in groups:
            group_counter[str(group)] += 1

        if rule_id not in rules:
            rules[rule_id] = {
                "rule_id": rule_id,
                "description": rule_desc,
                "level": rule_level,
                "groups": sorted(set(map(str, groups))),
                "count": 0,
                "fields": collections.Counter(),
                "alias_hits": {name: collections.Counter() for name in ALIASES},
            }

        rules[rule_id]["count"] += 1
        rules[rule_id]["fields"].update(flat.keys())

        for name, paths in ALIASES.items():
            for path in paths:
                if path in flat:
                    alias_hits[name][path] += 1
                    rules[rule_id]["alias_hits"][name][path] += 1

    report_rules = []
    for rule in rules.values():
        report_rules.append({
            "rule_id": rule["rule_id"],
            "description": rule["description"],
            "level": rule["level"],
            "groups": rule["groups"],
            "count": rule["count"],
            "top_fields": rule["fields"].most_common(100),
            "alias_hits": {k: v.most_common() for k, v in rule["alias_hits"].items() if v},
        })

    report = {
        "summary": {
            "sample_count": len(hits),
            "index": args.index,
            "hours": args.hours,
        },
        "top_fields": all_fields.most_common(300),
        "top_rules": rule_counter.most_common(100),
        "top_rule_groups": group_counter.most_common(100),
        "candidate_alias_hits": {k: v.most_common() for k, v in alias_hits.items()},
        "rules": sorted(report_rules, key=lambda x: x["count"], reverse=True),
    }

    output_directory = os.path.dirname(os.path.abspath(args.output))
    os.makedirs(output_directory, exist_ok=True)
    output_flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    if hasattr(os, "O_NOFOLLOW"):
        output_flags |= os.O_NOFOLLOW
    output_fd = os.open(args.output, output_flags, 0o600)
    if hasattr(os, "fchmod"):
        os.fchmod(output_fd, 0o600)
    else:  # pragma: no cover - the production target is Linux.
        os.chmod(args.output, 0o600)
    with os.fdopen(output_fd, "w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2, ensure_ascii=False)

    print(f"[+] Sampled alerts: {len(hits)}")
    print(f"[+] Output: {args.output}")
    print("[+] Top fields:")
    for field, count in all_fields.most_common(30):
        print(f"    {field}: {count}")
    print("[+] Candidate alias hits:")
    for name, counter in alias_hits.items():
        print(f"    {name}: {dict(counter.most_common())}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
