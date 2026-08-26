import importlib.util
import json
import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "siem_alarm_scoring_final.py"
SPEC = importlib.util.spec_from_file_location("siem_alarm_scoring_final_docs", MODULE_PATH)
assert SPEC and SPEC.loader
scoring = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(scoring)


class DocumentationExamplesTest(unittest.TestCase):
    def test_default_rule_5710_dummy_dataset_matches_documented_result(self):
        raw_path = ROOT / "docs" / "examples" / "dummy_wazuh_alerts_rule_5710.json"
        result_path = ROOT / "docs" / "examples" / "dummy_aggregation_result_rule_5710.json"
        assets_path = ROOT / "assets.example.json"

        raw = json.loads(raw_path.read_text(encoding="utf-8"))["documents"]
        expected = json.loads(result_path.read_text(encoding="utf-8"))
        assets = json.loads(assets_path.read_text(encoding="utf-8"))
        config = {
            "bucket_minutes": 60,
            "max_cases_per_bucket": 20000,
            "threat_level_strategy": "max",
            "evidence_sample_limit": 20,
            "evidence_top_limit": 10,
            "escalation_log_enabled": True,
            "escalation_log_levels": ["Medium", "High", "Critical"],
        }
        rows = [(item["_index"], item["_id"], item["_source"]) for item in raw]

        first_bucket = next(iter(scoring.aggregate(rows[:5], assets, config).values()))
        _, first_state = scoring.build_doc(first_bucket, config)
        final_bucket = next(iter(scoring.aggregate(rows, assets, config).values()))
        state_id, final_state = scoring.build_doc(final_bucket, config, first_state)
        escalation_id, escalation = scoring.build_escalation_doc(final_state)

        self.assertEqual(final_bucket["case_key"], expected["bucket"]["case_key"])
        self.assertEqual(state_id, expected["bucket"]["state_id"])
        self.assertEqual(first_state["risk"]["level"], "Low")
        self.assertEqual(final_state["alarm"]["event_count"], 10)
        self.assertEqual(final_state["source_observed"]["srcip_unique_count"], 3)
        self.assertEqual(
            final_state["source_observed"]["top_srcip"],
            expected["run_2_after_10_raw_alerts"]["source_observed"]["top_srcip"],
        )
        self.assertEqual(final_state["risk"]["score"], 2.67)
        self.assertEqual(final_state["risk"]["level"], "Medium")
        self.assertTrue(final_state["risk"]["escalation_log_required"])
        self.assertEqual(escalation_id, expected["new_alarm_escalation"]["escalation"]["id"])
        self.assertEqual(escalation["escalation"]["reason"], "risk_level_increased")


if __name__ == "__main__":
    unittest.main()
