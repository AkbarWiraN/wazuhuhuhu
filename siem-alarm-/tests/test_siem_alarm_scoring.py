import importlib.util
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
        "source_index": "wazuh-alerts-*",
        "destination_index_prefix": "siem-alarm",
        "bucket_minutes": 60,
        "lookback_minutes": 60,
        "lookback_overlap_minutes": 7,
        "process_current_bucket_only": True,
        "max_alerts_per_run": 50000,
        "page_size": 1000,
        "scroll_keepalive": "2m",
        "escalation_log_enabled": True,
        "escalation_log_levels": ["Medium", "High", "Critical"],
        "threat_level_strategy": "max",
        "assets_file": "",
    }


class ScoringTests(unittest.TestCase):
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
        self.assertIn("filebeat test output", installer)
        self.assertIn("final_checklist_siem_alarm_wazuh_4_14_7.md", installer)

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

    def test_malformed_alert_is_skipped(self) -> None:
        malformed = alert()
        del malformed["agent"]["id"]
        buckets = scoring.aggregate(
            [("wazuh-alerts-test", "bad-id", malformed)], {}, base_config()
        )
        self.assertEqual(buckets, {})

    def test_failed_shard_response_is_rejected(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "failed shard"):
            scoring.validate_search_response(
                {"timed_out": False, "_shards": {"failed": 1, "failures": ["boom"]}},
                "unit test",
            )

    def test_escalation_is_created_before_state_and_recovers(self) -> None:
        class FakeClient:
            state = None
            escalations = {}
            calls = []
            fail_state_once = True

            def __init__(self, *args, **kwargs):
                pass

            def put_template(self, *args, **kwargs):
                raise AssertionError("runtime must not install templates")

            def search(self, index, body, params=None):
                return {
                    "timed_out": False,
                    "_shards": {"failed": 0},
                    "hits": {
                        "hits": [
                            {
                                "_index": "wazuh-alerts-test",
                                "_id": str(i),
                                "_source": alert(i),
                            }
                            for i in range(3)
                        ]
                    },
                }

            def scroll(self, *args, **kwargs):
                raise AssertionError("scroll should not be needed")

            def clear_scroll(self, *args, **kwargs):
                pass

            def get_doc(self, index, doc_id):
                return self.__class__.state

            def create_doc_if_absent(self, index, doc_id, document):
                self.__class__.calls.append("escalation")
                if doc_id in self.__class__.escalations:
                    return False
                self.__class__.escalations[doc_id] = document
                return True

            def index_doc(self, index, doc_id, document):
                self.__class__.calls.append("state")
                if self.__class__.fail_state_once:
                    self.__class__.fail_state_once = False
                    raise RuntimeError("simulated state write failure")
                self.__class__.state = document
                return {"result": "created"}

        config = base_config()
        with mock.patch.object(scoring, "OpenSearchClient", FakeClient):
            with self.assertRaisesRegex(RuntimeError, "simulated state write failure"):
                scoring.run_once(config)
            self.assertIsNone(FakeClient.state)
            self.assertEqual(len(FakeClient.escalations), 1)

            scoring.run_once(config)

        self.assertIsNotNone(FakeClient.state)
        self.assertEqual(len(FakeClient.escalations), 1)
        self.assertEqual(FakeClient.calls[:2], ["escalation", "state"])
        self.assertEqual(FakeClient.calls[2:], ["escalation", "state"])

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

    def test_load_config_rejects_disabled_tls_verification(self) -> None:
        config = base_config()
        with tempfile.TemporaryDirectory() as temporary_directory:
            path = pathlib.Path(temporary_directory) / "config.json"
            path.write_text(json.dumps(config), encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "TLS verification is mandatory"):
                scoring.load_config(str(path))


if __name__ == "__main__":
    unittest.main()
