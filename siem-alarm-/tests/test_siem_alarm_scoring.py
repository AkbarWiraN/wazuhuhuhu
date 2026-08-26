import importlib.util
import datetime as dt
import json
import pathlib
import tempfile
import unittest
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "siem_alarm_scoring_final.py"
SPEC = importlib.util.spec_from_file_location("siem_alarm_scoring_final", MODULE_PATH)
assert SPEC and SPEC.loader
scoring = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(scoring)


def alert(number: int = 0) -> dict:
    return {
        "timestamp": f"2026-05-22T10:{number % 60:02d}:20Z",
        "agent": {"id": "003", "name": "sensor-003", "ip": "10.0.0.3"},
        "rule": {
            "id": "2010935",
            "level": 12,
            "description": "Test detection",
            "groups": ["ids"],
        },
    }


def base_config() -> dict:
    return {
        "opensearch_url": "https://127.0.0.1:9200",
        "username": "siem_alarm_service",
        "password": "unit-test-password",
        "verify_ssl": False,
        "install_template": False,
        "source_index": "wazuh-alerts-4.x-{date}",
        "destination_index_prefix": "siem-alarm",
        "bucket_minutes": 60,
        "lookback_minutes": 60,
        "lookback_overlap_minutes": 7,
        "process_current_bucket_only": True,
        "max_alerts_per_bucket": 50000,
        "max_alerts_per_run": 50000,
        "page_size": 1000,
        "scroll_keepalive": "2m",
        "mget_batch_size": 1000,
        "bulk_max_actions": 1000,
        "bulk_max_bytes": 5 * 1024 * 1024,
        "retry_attempts": 2,
        "retry_backoff_seconds": 0.1,
        "escalation_log_enabled": True,
        "escalation_log_levels": ["Medium", "High", "Critical"],
        "threat_level_strategy": "max",
        "assets_file": "",
    }


def case_alert(
    rule_id: str,
    timestamp: str = "2026-05-22T10:00:20Z",
    *,
    level: int = 12,
    description: str = "Test detection",
    srcip=None,
) -> dict:
    item = {
        "timestamp": timestamp,
        "agent": {"id": "003", "name": "sensor-003", "ip": "10.0.0.3"},
        "rule": {
            "id": rule_id,
            "level": level,
            "description": description,
            "groups": ["ids"],
        },
    }
    if srcip is not None:
        item["data"] = {"srcip": srcip}
    return item


def search_response(hits, total, scroll_id="scroll-1", shard_total=1):
    response = {
        "timed_out": False,
        "_shards": {"total": shard_total, "successful": shard_total, "failed": 0},
        "hits": {"total": {"value": total, "relation": "eq"}, "hits": hits},
    }
    if scroll_id is not None:
        response["_scroll_id"] = scroll_id
    return response


def search_hit(doc_id: str, document: dict) -> dict:
    return {"_index": "wazuh-alerts-test", "_id": doc_id, "_source": document}


class RecordingSearchClient:
    def __init__(self, pages):
        self.pages = list(pages)
        self.search_calls = []
        self.scroll_calls = []
        self.clear_calls = []

    def search(self, index, body, params=None):
        self.search_calls.append((index, body, params))
        if not self.pages:
            raise AssertionError("unexpected initial search")
        return self.pages.pop(0)

    def scroll(self, scroll_id, keepalive):
        self.scroll_calls.append((scroll_id, keepalive))
        if not self.pages:
            raise AssertionError("unexpected scroll")
        return self.pages.pop(0)

    def clear_scroll(self, scroll_id):
        self.clear_calls.append(scroll_id)


def decode_bulk_payload(payload: bytes, index=None):
    lines = payload.decode("utf-8").splitlines()
    if len(lines) % 2:
        raise AssertionError("bulk payload must contain metadata/document pairs")
    operations = []
    for offset in range(0, len(lines), 2):
        metadata = json.loads(lines[offset])
        action, target = next(iter(metadata.items()))
        operations.append(
            {
                "action": action,
                "index": target.get("_index", index),
                "id": target["_id"],
                "document": json.loads(lines[offset + 1]),
            }
        )
    return operations


class RecordingBulkClient:
    def __init__(self, *, states=None, events=None, statuses=None, mget_errors=None):
        self.states = dict(states or {})
        self.events = dict(events or {})
        self.statuses = {key: list(value) for key, value in (statuses or {}).items()}
        self.mget_errors = dict(mget_errors or {})
        self.mget_calls = []
        self.bulk_calls = []
        self.fail_after_create_apply_once = False

    def mget(self, index, ids):
        self.mget_calls.append((index, list(ids)))
        response = []
        # Deliberately reverse the response: production code must match by ID.
        for doc_id in reversed(ids):
            key = (index, doc_id)
            if key in self.mget_errors:
                status, error = self.mget_errors[key]
                response.append(
                    {
                        "_index": key[0],
                        "_id": key[1],
                        "status": status,
                        "error": error,
                    }
                )
            elif key in self.states:
                response.append(
                    {
                        "_index": key[0],
                        "_id": key[1],
                        "found": True,
                        "_source": self.states[key],
                    }
                )
            else:
                response.append({"_index": key[0], "_id": key[1], "found": False})
        return {"docs": response}

    def bulk(self, index, payload):
        operations = decode_bulk_payload(payload, index)
        self.bulk_calls.append(operations)
        items = []
        for operation in operations:
            action = operation["action"]
            index = operation["index"]
            doc_id = operation["id"]
            key = (action, doc_id)
            scripted = self.statuses.get(key, [])
            if scripted:
                status = scripted.pop(0)
            elif action == "create" and (index, doc_id) in self.events:
                status = 409
            else:
                status = 201 if action == "create" else 200

            if 200 <= status < 300:
                if action == "create":
                    self.events[(index, doc_id)] = operation["document"]
                else:
                    self.states[(index, doc_id)] = operation["document"]

            result = {"_index": index, "_id": doc_id, "status": status}
            if status >= 300:
                result["error"] = {"type": "simulated", "reason": f"status {status}"}
            items.append({action: result})

        if self.fail_after_create_apply_once and operations and all(
            operation["action"] == "create" for operation in operations
        ):
            self.fail_after_create_apply_once = False
            raise RuntimeError("simulated lost bulk response")
        return {"errors": any(next(iter(item.values()))["status"] >= 300 for item in items), "items": items}

    def get_doc(self, *args, **kwargs):
        raise AssertionError("V2 must use _mget, not individual GET")

    def index_doc(self, *args, **kwargs):
        raise AssertionError("V2 must use _bulk, not individual index requests")

    def create_doc_if_absent(self, *args, **kwargs):
        raise AssertionError("V2 must use _bulk create, not individual create requests")


def aggregate_cases(rule_ids, config=None, count_per_rule=3):
    config = config or base_config()
    rows = []
    for rule_offset, rule_id in enumerate(rule_ids):
        for count in range(count_per_rule):
            minute = rule_offset * 10 + count
            item = case_alert(rule_id, f"2026-05-22T10:{minute:02d}:20Z")
            rows.append(("wazuh-alerts-test", f"{rule_id}-{count}", item))
    return scoring.aggregate(rows, {"003": {"asset_value": 3}}, config)


def escalation_details(bucket, config):
    destination_index = scoring.destination_index_for_bucket(config, bucket["bucket_start"])
    _, state_document = scoring.build_doc(bucket, config, None)
    event_id, event_document = scoring.build_escalation_doc(state_document)
    return destination_index, event_id, event_document


class ScoringTests(unittest.TestCase):
    def test_parse_dt_accepts_native_wazuh_timezone_offsets(self) -> None:
        utc_value = scoring.parse_dt("2026-08-25T10:15:20.123+0000")
        west_value = scoring.parse_dt("2026-08-25T05:15:20.123-0500")
        self.assertIsNotNone(utc_value)
        self.assertIsNotNone(west_value)
        self.assertEqual(utc_value.astimezone(dt.timezone.utc), west_value.astimezone(dt.timezone.utc))

    def test_embedded_template_matches_review_file(self) -> None:
        review_template = json.loads(
            (ROOT / "siem_alarm_template_final.json").read_text(encoding="utf-8")
        )
        self.assertEqual(scoring.template(), review_template)

    def test_template_follows_destination_prefix(self) -> None:
        generated = scoring.template({"destination_index_prefix": "custom-alarm"})
        self.assertEqual(generated["index_patterns"], ["custom-alarm-*"])

    def test_ism_policy_only_targets_siem_alarm_after_90_days(self) -> None:
        policy = json.loads(
            (ROOT / "siem_alarm_ism_policy.json").read_text(encoding="utf-8")
        )["policy"]
        self.assertEqual(policy["ism_template"]["index_patterns"], ["siem-alarm-*"])
        delete_transition = policy["states"][0]["transitions"][0]
        self.assertEqual(delete_transition["state_name"], "delete")
        self.assertEqual(delete_transition["conditions"]["min_index_age"], "90d")

    def test_installer_is_pinned_to_wazuh_4_14_7(self) -> None:
        installer = (ROOT / "setup_siem_alarm_final.sh").read_text(encoding="utf-8")
        self.assertIn('EXPECTED_WAZUH_VERSION="4.14.7"', installer)
        self.assertIn('EXPECTED_FILEBEAT_VERSION="7.10.2"', installer)
        self.assertIn("sys.version_info >= (3, 8)", installer)
        self.assertIn("python3 >= 3.8 is required", installer)
        self.assertIn("TimeoutStartSec=240s", installer)
        self.assertNotIn("RuntimeMaxSec=", installer)
        self.assertIn("filebeat test output", installer)
        self.assertIn("final_checklist_siem_alarm_wazuh_4_14_7.md", installer)
        self.assertIn("printf '{}\\n' >\"${BASE_DIR}/assets.json\"", installer)
        self.assertIn("Wants=network-online.target\n", installer)
        self.assertNotIn("Wants=network-online.target wazuh-indexer.service", installer)

    def test_asset_inventory_is_strict_and_category_must_match(self) -> None:
        valid = {
            "003": {
                "agent_name": "sensor-003",
                "asset_value": 5,
                "asset_category": "Critical",
                "asset_type": "IDS Sensor",
                "asset_owner": "SOC",
                "environment": "Production",
            }
        }
        self.assertIs(scoring.validate_assets(valid), valid)

        invalid_cases = [
            ([{"asset_value": 3}], "top-level JSON object"),
            ({"003": "Critical"}, "must be a JSON object"),
            ({"003": {}}, "must define asset_value"),
            ({"003": {"asset_value": "abc"}}, "integer from 1 to 5"),
            ({"003": {"asset_value": 6}}, "between 1 and 5"),
            ({"003": {"asset_value": 5, "asset_category": "Low"}}, "must be 'Critical'"),
            ({"003": {"asset_value": 3, "asset_valeu": 5}}, "unsupported field"),
        ]
        for inventory, message in invalid_cases:
            with self.subTest(inventory=inventory):
                with self.assertRaisesRegex(RuntimeError, message):
                    scoring.validate_assets(inventory)

    def test_root_owned_inventory_precedes_labels_and_root_payload_is_ignored(self) -> None:
        item = alert()
        item["agent"]["labels"] = {
            "asset": {"value": "1", "category": "Minimal"}
        }
        item["labels"] = {"asset": {"value": "5", "category": "Critical"}}
        item["asset"] = {"value": "5", "category": "Critical"}

        inventory = {
            "003": {
                "agent_name": "sensor-003",
                "asset_value": 4,
                "asset_category": "High",
            }
        }
        selected = scoring.get_asset(item, inventory)
        self.assertEqual((selected["value"], selected["source"]), (4, "assets_json"))

        del item["agent"]["labels"]
        selected = scoring.get_asset(item, {})
        self.assertEqual((selected["value"], selected["source"]), (3, "default"))

    def test_agent_label_is_strict_fallback_and_stale_id_inventory_fails(self) -> None:
        item = alert()
        item["agent"]["labels"] = {
            "asset": {"value": "2", "category": "Low", "owner": "SOC"}
        }
        selected = scoring.get_asset(item, {})
        self.assertEqual((selected["value"], selected["source"]), (2, "agent_label"))

        item["agent"]["labels"]["asset"]["value"] = "99"
        with self.assertRaisesRegex(RuntimeError, "integer from 1 to 5"):
            scoring.get_asset(item, {})

        with self.assertRaisesRegex(RuntimeError, "stale inventory"):
            scoring.get_asset(
                alert(),
                {"003": {"agent_name": "old-name", "asset_value": 4}},
            )

    def test_progressive_risk_and_history(self) -> None:
        config = base_config()
        assets = {"003": {"asset_value": 5}}
        existing = None
        observed = []

        for count in [3, 15, 55, 120, 510, 530]:
            rows = [("wazuh-alerts-test", str(i), alert(i)) for i in range(count)]
            bucket = next(iter(scoring.aggregate(rows, assets, config).values()))
            _, document = scoring.build_doc(bucket, config, existing)
            observed.append(
                (
                    document["risk"]["level"],
                    document["risk"]["escalation_log_required"],
                )
            )
            existing = document

        self.assertEqual(
            observed,
            [
                ("Medium", True),
                ("High", True),
                ("High", False),
                ("High", False),
                ("Critical", True),
                ("Critical", False),
            ],
        )
        self.assertEqual(
            [item["level"] for item in existing["risk"]["level_history"]],
            ["Medium", "High", "Critical"],
        )

    def test_malformed_alert_fails_closed(self) -> None:
        malformed = alert()
        del malformed["agent"]["id"]
        with self.assertRaisesRegex(RuntimeError, "malformed alert"):
            scoring.aggregate(
                [("wazuh-alerts-test", "bad-id", malformed)], {}, base_config()
            )

    def test_rule_description_is_optional_but_case_cardinality_is_bounded(self) -> None:
        without_description = alert()
        del without_description["rule"]["description"]
        buckets = scoring.aggregate(
            [("wazuh-alerts-test", "no-description", without_description)],
            {"003": {"asset_value": 3}},
            base_config(),
        )
        _, document = scoring.build_doc(next(iter(buckets.values())), base_config())
        self.assertEqual(document["rule"]["description"], "Unknown rule")

        level_16 = alert()
        level_16["rule"]["level"] = 16
        level_16_buckets = scoring.aggregate(
            [("wazuh-alerts-test", "level-16", level_16)],
            {"003": {"asset_value": 3}},
            base_config(),
        )
        self.assertEqual(next(iter(level_16_buckets.values()))["max_rule_level"], 16)

        config = base_config()
        config["max_cases_per_bucket"] = 1
        rows = [
            ("wazuh-alerts-test", "one", case_alert("100001")),
            ("wazuh-alerts-test", "two", case_alert("100002")),
        ]
        with self.assertRaisesRegex(RuntimeError, "max_cases_per_bucket exceeded"):
            scoring.aggregate(rows, {"003": {"asset_value": 3}}, config)

    def test_failed_shard_response_is_rejected(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "failed shard"):
            scoring.validate_search_response(
                {"timed_out": False, "_shards": {"failed": 1, "failures": ["boom"]}},
                "unit test",
            )

    def test_plan_run_windows_splits_current_and_finalized_bucket(self) -> None:
        config = base_config()
        config["max_catchup_buckets_per_run"] = 2
        now = dt.datetime(2026, 5, 22, 11, 8, tzinfo=dt.timezone.utc)

        with tempfile.TemporaryDirectory() as temporary_directory:
            config["checkpoint_file"] = str(
                pathlib.Path(temporary_directory) / "checkpoint.json"
            )
            windows, checkpoint_target = scoring.plan_run_windows(config, now=now)

        self.assertEqual(
            windows,
            [
                {
                    "kind": "current",
                    "gte": "2026-05-22T11:00:00Z",
                    "lte": "2026-05-22T11:08:00Z",
                },
                {
                    "kind": "closed",
                    "gte": "2026-05-22T10:00:00Z",
                    "lte": "2026-05-22T11:00:00Z",
                },
            ],
        )
        self.assertEqual(checkpoint_target, dt.datetime(2026, 5, 22, 11, 0, tzinfo=dt.timezone.utc))
        self.assertEqual(windows[1]["lte"], windows[0]["gte"])

    def test_alarm_status_represents_bucket_lifecycle_not_incident_workflow(self) -> None:
        now = dt.datetime(2026, 5, 22, 11, 8, tzinfo=dt.timezone.utc)
        closed = {
            "kind": "closed",
            "gte": "2026-05-22T10:00:00Z",
            "lte": "2026-05-22T11:00:00Z",
        }
        current = {
            "kind": "current",
            "gte": "2026-05-22T11:00:00Z",
            "lte": "2026-05-22T11:08:00Z",
        }
        self.assertEqual(scoring.lifecycle_status_for_window(closed, 60, now), "finalized")
        self.assertEqual(scoring.lifecycle_status_for_window(current, 60, now), "open")

        bucket = next(
            iter(
                scoring.aggregate(
                    [("wazuh-alerts-test", "one", alert())],
                    {"003": {"asset_value": 3}},
                    base_config(),
                ).values()
            )
        )
        bucket["lifecycle_status"] = "finalized"
        _, document = scoring.build_doc(bucket, base_config())
        self.assertEqual(document["alarm"]["status"], "finalized")

    def test_checkpoint_catchup_is_bounded_and_contiguous(self) -> None:
        config = base_config()
        config["max_catchup_buckets_per_run"] = 2
        now = dt.datetime(2026, 5, 22, 11, 8, tzinfo=dt.timezone.utc)

        with tempfile.TemporaryDirectory() as temporary_directory:
            checkpoint_path = pathlib.Path(temporary_directory) / "checkpoint.json"
            config["checkpoint_file"] = str(checkpoint_path)
            checkpoint_path.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "last_completed_bucket_end": "2026-05-22T08:00:00Z",
                        "case_identity_hash": scoring.case_identity_hash(config),
                    }
                ),
                encoding="utf-8",
            )
            windows, checkpoint_target = scoring.plan_run_windows(config, now=now)

        self.assertEqual(
            windows[1:],
            [
                {
                    "kind": "closed",
                    "gte": "2026-05-22T08:00:00Z",
                    "lte": "2026-05-22T09:00:00Z",
                },
                {
                    "kind": "closed",
                    "gte": "2026-05-22T09:00:00Z",
                    "lte": "2026-05-22T10:00:00Z",
                },
            ],
        )
        self.assertEqual(checkpoint_target, dt.datetime(2026, 5, 22, 10, 0, tzinfo=dt.timezone.utc))

    def test_manual_window_requires_bucket_boundaries_and_index_dates_use_utc(self) -> None:
        config = base_config()

        with self.subTest("unaligned start"):
            with self.assertRaisesRegex(RuntimeError, "--from must align"):
                scoring.plan_run_windows(
                    config,
                    gte_override="2026-05-22T10:30:00Z",
                    lte_override="2026-05-22T11:00:00Z",
                )

        with self.subTest("unaligned end"):
            with self.assertRaisesRegex(RuntimeError, "--to must align"):
                scoring.plan_run_windows(
                    config,
                    gte_override="2026-05-22T10:00:00Z",
                    lte_override="2026-05-22T11:15:00Z",
                )

        # Both local timestamps are on 23 May in Jakarta, while the complete
        # half-open window still belongs to 22 May in UTC.
        resolved = scoring.source_index_for_window(
            config,
            "2026-05-23T00:30:00+07:00",
            "2026-05-23T01:30:00+07:00",
            False,
        )
        self.assertEqual(resolved, "wazuh-alerts-4.x-2026.05.22")

    def test_corrupt_or_mismatched_checkpoint_fails_closed(self) -> None:
        config = base_config()
        with tempfile.TemporaryDirectory() as temporary_directory:
            checkpoint_path = pathlib.Path(temporary_directory) / "checkpoint.json"
            config["checkpoint_file"] = str(checkpoint_path)

            checkpoint_path.write_text("{not-json", encoding="utf-8")
            with self.subTest("corrupt JSON"):
                with self.assertRaises((RuntimeError, json.JSONDecodeError)):
                    scoring.load_checkpoint(config)

            checkpoint_path.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "last_completed_bucket_end": "2026-05-22T10:00:00Z",
                        "case_identity_hash": "not-the-active-config-hash",
                    }
                ),
                encoding="utf-8",
            )
            with self.subTest("identity hash mismatch"):
                with self.assertRaisesRegex(RuntimeError, "does not match this configuration"):
                    scoring.load_checkpoint(config)

    def test_fetch_alerts_uses_allowlist_exact_total_and_multiple_pages(self) -> None:
        documents = [case_alert("100", f"2026-05-22T10:0{i}:20Z") for i in range(4)]
        client = RecordingSearchClient(
            [
                search_response(
                    [search_hit("0", documents[0]), search_hit("1", documents[1])],
                    4,
                    "scroll-1",
                ),
                search_response(
                    [search_hit("2", documents[2]), search_hit("3", documents[3])],
                    4,
                    "scroll-2",
                ),
            ]
        )
        config = base_config()
        config["page_size"] = 2
        config["source_includes"] = ["custom.indicator", "rule"]

        rows = list(
            scoring.fetch_alerts(
                client,
                config,
                "2026-05-22T10:00:00Z",
                "2026-05-22T11:00:00Z",
                False,
            )
        )

        self.assertEqual([row[1] for row in rows], ["0", "1", "2", "3"])
        self.assertEqual(client.scroll_calls, [("scroll-1", "2m")])
        self.assertEqual(client.clear_calls, ["scroll-2"])
        source_index, body, params = client.search_calls[0]
        self.assertEqual(source_index, "wazuh-alerts-4.x-2026.05.22")
        self.assertEqual(body["sort"], ["_doc"])
        self.assertEqual(body["track_total_hits"], config["max_alerts_per_bucket"] + 1)
        self.assertEqual(body["timeout"], "55s")
        self.assertEqual(body["size"], 2)
        includes = body["_source"]["includes"]
        self.assertEqual(includes, sorted(set(includes)))
        self.assertIn("custom.indicator", includes)
        self.assertNotIn("full_log", includes)
        self.assertEqual(params["ignore_unavailable"], "true")
        self.assertEqual(
            body["query"]["bool"]["filter"][0],
            {
                "range": {
                    "timestamp": {
                        "gte": "2026-05-22T10:00:00Z",
                        "lt": "2026-05-22T11:00:00Z",
                    }
                }
            },
        )

    def test_fetch_alerts_rejects_cap_before_pagination(self) -> None:
        capped_response = search_response([search_hit("0", alert(0))], 4, "scroll-cap")
        capped_response["hits"]["total"]["relation"] = "gte"
        client = RecordingSearchClient([capped_response])
        config = base_config()
        config["max_alerts_per_bucket"] = 3

        with self.assertRaisesRegex(RuntimeError, "max_alerts_per_bucket exceeded"):
            list(
                scoring.fetch_alerts(
                    client,
                    config,
                    "2026-05-22T10:00:00Z",
                    "2026-05-22T11:00:00Z",
                    False,
                )
            )

        self.assertEqual(client.scroll_calls, [])
        self.assertEqual(client.clear_calls, ["scroll-cap"])

    def test_fetch_alerts_rejects_missing_continuation_cursor(self) -> None:
        client = RecordingSearchClient(
            [
                search_response(
                    [search_hit("0", alert(0)), search_hit("1", alert(1))],
                    3,
                    None,
                )
            ]
        )

        with self.assertRaisesRegex(RuntimeError, "cursor missing"):
            list(
                scoring.fetch_alerts(
                    client,
                    base_config(),
                    "2026-05-22T10:00:00Z",
                    "2026-05-22T11:00:00Z",
                    False,
                )
            )

    def test_fetch_alerts_rejects_zero_resolved_shards(self) -> None:
        client = RecordingSearchClient(
            [search_response([], 0, "scroll-zero", shard_total=0)]
        )

        with self.assertRaisesRegex(RuntimeError, "No concrete Wazuh alert index"):
            list(
                scoring.fetch_alerts(
                    client,
                    base_config(),
                    "2026-05-22T10:00:00Z",
                    "2026-05-22T11:00:00Z",
                    False,
                )
            )

        self.assertEqual(client.clear_calls, ["scroll-zero"])

    def test_aggregation_is_deterministic_for_doc_order(self) -> None:
        config = base_config()
        config["threat_level_strategy"] = "mode"
        early = case_alert(
            "991",
            "2026-05-22T10:00:01Z",
            level=5,
            description="Earliest description",
            srcip="10.0.0.2",
        )
        late = case_alert(
            "991",
            "2026-05-22T10:00:02Z",
            level=12,
            description="Later description",
            srcip="10.0.0.1",
        )
        forward = [
            ("wazuh-alerts-test", "early", early),
            ("wazuh-alerts-test", "late", late),
        ]
        reverse = list(reversed(forward))
        assets = {"003": {"asset_value": 3}}

        first_bucket = next(iter(scoring.aggregate(forward, assets, config).values()))
        second_bucket = next(iter(scoring.aggregate(reverse, assets, config).values()))
        _, first_document = scoring.build_doc(first_bucket, config, None)
        _, second_document = scoring.build_doc(second_bucket, config, None)

        self.assertEqual(first_document, second_document)
        self.assertEqual(first_document["source"]["sample_document_id"], "early")
        self.assertEqual(first_document["rule"]["description"], "Earliest description")
        self.assertEqual(first_document["rule"]["level"], 12)
        self.assertEqual(
            first_document["source_observed"]["srcip_samples"],
            ["10.0.0.1", "10.0.0.2"],
        )

    def test_mget_chunks_shuffled_results_and_missing_states(self) -> None:
        references = [("siem-alarm-2026.05.22", f"doc-{number}") for number in range(5)]
        states = {
            references[number]: {
                "risk": {"level": "Medium", "level_history": [{"level": "Medium", "at": "x"}]}
            }
            for number in [0, 2, 4]
        }
        client = RecordingBulkClient(states=states)
        config = base_config()
        config["mget_batch_size"] = 2

        loaded = scoring.load_existing_states(client, references, config)

        self.assertEqual(len(client.mget_calls), 3)
        self.assertTrue(all(len(ids) <= 2 for _, ids in client.mget_calls))
        self.assertEqual(loaded[references[0]], states[references[0]])
        self.assertIsNone(loaded[references[1]])
        self.assertEqual(set(loaded), set(references))

    def test_opensearch_client_mget_uses_compatible_body_and_query_params(self) -> None:
        client = scoring.OpenSearchClient(
            "https://127.0.0.1:9200",
            "unit-user",
            "unit-password",
            verify_ssl=False,
        )
        client.request = mock.Mock(return_value={"docs": []})

        response = client.mget("siem-alarm-2026.05.22", ["state-1", "state-2"])

        self.assertEqual(response, {"docs": []})
        client.request.assert_called_once_with(
            "POST",
            "siem-alarm-2026.05.22/_mget",
            {"ids": ["state-1", "state-2"]},
            {
                "_source_includes": "risk.level,risk.level_history",
                "realtime": "true",
            },
        )

    def test_mget_item_error_fails_before_bulk(self) -> None:
        reference = ("siem-alarm-2026.05.22", "doc-error")
        client = RecordingBulkClient(
            mget_errors={reference: (503, {"type": "unavailable", "reason": "test"})}
        )

        with self.assertRaisesRegex(RuntimeError, "_mget failed"):
            scoring.load_existing_states(client, [reference], base_config())
        self.assertEqual(client.bulk_calls, [])

    def test_bulk_batches_use_utf8_byte_limit_and_reject_oversized_document(self) -> None:
        first = {
            "action": "index",
            "index": "siem-alarm-2026.05.22",
            "id": "utf8-1",
            "document": {"message": "alarm-é" * 20},
        }
        second = {
            "action": "index",
            "index": "siem-alarm-2026.05.22",
            "id": "utf8-2",
            "document": {"message": "alarm-é" * 20},
        }
        first_encoded = scoring.encode_bulk_operation(first)
        first_size = len(first_encoded)
        second_size = len(scoring.encode_bulk_operation(second))
        self.assertGreater(first_size, len(first_encoded.decode("utf-8")))

        config = base_config()
        config["bulk_max_actions"] = 100
        config["bulk_max_bytes"] = first_size + second_size - 1
        batches = scoring.build_bulk_batches([first, second], config)

        self.assertEqual([len(batch) for batch in batches], [1, 1])
        self.assertTrue(
            all(
                sum(len(scoring.encode_bulk_operation(operation)) for operation in batch)
                <= config["bulk_max_bytes"]
                for batch in batches
            )
        )

        oversized_config = dict(config)
        oversized_config["bulk_max_bytes"] = first_size - 1
        with self.assertRaisesRegex(RuntimeError, "exceeds bulk_max_bytes"):
            scoring.build_bulk_batches([first], oversized_config)

    def test_bulk_response_count_or_identity_mismatch_fails_closed(self) -> None:
        operation = {
            "action": "index",
            "index": "siem-alarm-2026.05.22",
            "id": "state-1",
            "document": {"alarm": {"id": "state-1"}},
        }

        with self.subTest("item count"):
            with self.assertRaisesRegex(RuntimeError, "expected 1 items"):
                scoring.parse_bulk_response({"items": []}, [operation])

        with self.subTest("wrong action"):
            response = {
                "items": [
                    {
                        "create": {
                            "_index": operation["index"],
                            "_id": operation["id"],
                            "status": 201,
                        }
                    }
                ]
            }
            with self.assertRaisesRegex(RuntimeError, "Unexpected, duplicate, or malformed"):
                scoring.parse_bulk_response(response, [operation])

    def test_bulk_writes_escalations_before_states(self) -> None:
        config = base_config()
        buckets = aggregate_cases(["1001", "1002"], config)
        client = RecordingBulkClient()

        written = scoring.process_buckets_bulk(client, config, buckets)

        self.assertEqual(written, 4)
        self.assertEqual(len(client.mget_calls), 1)
        self.assertEqual(len(client.bulk_calls), 2)
        self.assertTrue(all(operation["action"] == "create" for operation in client.bulk_calls[0]))
        self.assertTrue(all(operation["action"] == "index" for operation in client.bulk_calls[1]))
        self.assertEqual(len(client.events), 2)
        self.assertEqual(len(client.states), 2)
        self.assertTrue(
            all(not operation["index"].startswith("wazuh-alerts-") for call in client.bulk_calls for operation in call)
        )

    def test_case_materialization_is_bounded_by_batch_settings(self) -> None:
        config = base_config()
        config["mget_batch_size"] = 2
        config["bulk_max_actions"] = 3
        config["escalation_log_enabled"] = False
        buckets = aggregate_cases(["1101", "1102", "1103", "1104", "1105"], config)
        client = RecordingBulkClient()

        written = scoring.process_buckets_bulk(client, config, buckets)

        self.assertEqual(written, 5)
        self.assertEqual([len(ids) for _, ids in client.mget_calls], [2, 2, 1])
        self.assertEqual([len(call) for call in client.bulk_calls], [2, 2, 1])
        self.assertTrue(
            all(operation["action"] == "index" for call in client.bulk_calls for operation in call)
        )

    def test_bulk_create_conflict_is_accepted_before_state(self) -> None:
        config = base_config()
        buckets = aggregate_cases(["2001"], config)
        bucket = next(iter(buckets.values()))
        index, event_id, event_document = escalation_details(bucket, config)
        client = RecordingBulkClient(events={(index, event_id): event_document})

        written = scoring.process_buckets_bulk(client, config, buckets)

        self.assertEqual(written, 1)
        self.assertEqual(len(client.events), 1)
        self.assertEqual(len(client.states), 1)
        self.assertEqual(
            [operation["action"] for call in client.bulk_calls for operation in call],
            ["create", "index"],
        )

    def test_escalation_partial_failure_blocks_only_dependent_state(self) -> None:
        config = base_config()
        config["retry_attempts"] = 1
        buckets = aggregate_cases(["3001", "3002"], config)
        event_ids = {}
        for bucket in buckets.values():
            _, event_id, _ = escalation_details(bucket, config)
            event_ids[bucket["sample_alert"]["rule"]["id"]] = event_id
        client = RecordingBulkClient(statuses={("create", event_ids["3002"]): [400]})

        with self.assertRaisesRegex(RuntimeError, "checkpoint not advanced"):
            scoring.process_buckets_bulk(client, config, buckets)

        written_rules = {document["rule"]["id"] for document in client.states.values()}
        self.assertEqual(written_rules, {"3001"})
        self.assertEqual(len(client.bulk_calls), 2)
        self.assertEqual(
            {operation["id"] for operation in client.bulk_calls[1]},
            {
                scoring.make_id(bucket["case_key"])
                for bucket in buckets.values()
                if bucket["sample_alert"]["rule"]["id"] == "3001"
            },
        )

    def test_retryable_bulk_retries_only_failed_items(self) -> None:
        config = base_config()
        config["retry_attempts"] = 2
        buckets = aggregate_cases(["4001", "4002"], config)
        event_ids = {}
        for bucket in buckets.values():
            _, event_id, _ = escalation_details(bucket, config)
            event_ids[bucket["sample_alert"]["rule"]["id"]] = event_id
        client = RecordingBulkClient(statuses={("create", event_ids["4002"]): [429, 201]})

        with mock.patch.object(scoring.time, "sleep"):
            written = scoring.process_buckets_bulk(client, config, buckets)

        self.assertEqual(written, 4)
        self.assertEqual(len(client.bulk_calls), 3)
        self.assertEqual(
            [operation["id"] for operation in client.bulk_calls[1]],
            [event_ids["4002"]],
        )
        self.assertTrue(all(operation["action"] == "index" for operation in client.bulk_calls[2]))

    def test_crash_after_escalation_bulk_recovers_via_create_conflict(self) -> None:
        config = base_config()
        buckets = aggregate_cases(["5001"], config)
        client = RecordingBulkClient()
        client.fail_after_create_apply_once = True

        with self.assertRaisesRegex(RuntimeError, "lost bulk response"):
            scoring.process_buckets_bulk(client, config, buckets)
        self.assertEqual(len(client.events), 1)
        self.assertEqual(client.states, {})

        written = scoring.process_buckets_bulk(client, config, buckets)

        self.assertEqual(written, 1)
        self.assertEqual(len(client.events), 1)
        self.assertEqual(len(client.states), 1)
        state = next(iter(client.states.values()))
        self.assertEqual(state["alarm"]["event_count"], 3)
        self.assertEqual(len(state["risk"]["level_history"]), 1)

    def test_partial_state_failure_converges_on_rerun_without_duplicate_events(self) -> None:
        config = base_config()
        config["retry_attempts"] = 1
        buckets = aggregate_cases(["6001", "6002"], config)
        failed_state_id = next(
            scoring.make_id(bucket["case_key"])
            for bucket in buckets.values()
            if bucket["sample_alert"]["rule"]["id"] == "6002"
        )
        client = RecordingBulkClient(statuses={("index", failed_state_id): [400]})

        with self.assertRaisesRegex(RuntimeError, "checkpoint not advanced"):
            scoring.process_buckets_bulk(client, config, buckets)
        self.assertEqual(len(client.events), 2)
        self.assertEqual(len(client.states), 1)

        scoring.process_buckets_bulk(client, config, buckets)

        self.assertEqual(len(client.events), 2)
        self.assertEqual(len(client.states), 2)
        self.assertEqual(
            {document["alarm"]["event_count"] for document in client.states.values()},
            {3},
        )

    def test_load_config_rejects_placeholder_and_invalid_bucket(self) -> None:
        config = base_config()
        config.pop("password")
        config["password_env"] = "UNIT_TEST_WAZUH_PASS"
        config["bucket_minutes"] = 70
        with tempfile.TemporaryDirectory() as temporary_directory:
            ca_path = pathlib.Path(temporary_directory) / "root-ca.pem"
            ca_path.write_text("test CA placeholder", encoding="utf-8")
            config["verify_ssl"] = True
            config["ca_cert"] = str(ca_path)
            path = pathlib.Path(temporary_directory) / "config.json"
            path.write_text(json.dumps(config), encoding="utf-8")
            with mock.patch.dict(scoring.os.environ, {"UNIT_TEST_WAZUH_PASS": "secret"}):
                with self.assertRaisesRegex(RuntimeError, "divide evenly"):
                    scoring.load_config(str(path))

    def test_example_config_loads_after_secret_is_supplied(self) -> None:
        config = json.loads(
            (ROOT / "config.siem_alarm.example.json").read_text(encoding="utf-8")
        )
        config["min_rule_level"] = 16
        with tempfile.TemporaryDirectory() as temporary_directory:
            ca_path = pathlib.Path(temporary_directory) / "root-ca.pem"
            ca_path.write_text("test CA placeholder", encoding="utf-8")
            config["ca_cert"] = str(ca_path)
            path = pathlib.Path(temporary_directory) / "config.json"
            path.write_text(json.dumps(config), encoding="utf-8")
            with mock.patch.dict(scoring.os.environ, {"WAZUH_PASS": "secret"}):
                loaded = scoring.load_config(str(path))
        self.assertEqual(loaded["password"], "secret")
        self.assertFalse(loaded["install_template"])
        self.assertEqual(loaded["bucket_minutes"], 60)
        self.assertEqual(loaded["min_rule_level"], 16)

    def test_load_config_rejects_disabled_tls_verification(self) -> None:
        config = base_config()
        config.pop("password")
        config["password_env"] = "UNIT_TEST_WAZUH_PASS"
        with tempfile.TemporaryDirectory() as temporary_directory:
            path = pathlib.Path(temporary_directory) / "config.json"
            path.write_text(json.dumps(config), encoding="utf-8")
            with mock.patch.dict(scoring.os.environ, {"UNIT_TEST_WAZUH_PASS": "secret"}):
                with self.assertRaisesRegex(RuntimeError, "TLS verification is mandatory"):
                    scoring.load_config(str(path))

    def test_load_config_rejects_admin_and_inline_password(self) -> None:
        config = base_config()
        with tempfile.TemporaryDirectory() as temporary_directory:
            path = pathlib.Path(temporary_directory) / "config.json"
            path.write_text(json.dumps(config), encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "Inline password is not allowed"):
                scoring.load_config(str(path))

            config.pop("password")
            config["username"] = "admin"
            path.write_text(json.dumps(config), encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "admin is not allowed"):
                scoring.load_config(str(path))


if __name__ == "__main__":
    unittest.main()
