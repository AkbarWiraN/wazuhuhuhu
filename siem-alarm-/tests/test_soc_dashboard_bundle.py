import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
BUILDER_PATH = PROJECT_ROOT / "dashboards" / "build_soc_dashboard.py"
SPEC = importlib.util.spec_from_file_location("siem_alarm_soc_dashboard_builder", str(BUILDER_PATH))
BUILDER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BUILDER)
EXPORT_VALIDATOR_PATH = PROJECT_ROOT / "dashboards" / "validate_saved_objects_export.py"
VALIDATOR_SPEC = importlib.util.spec_from_file_location(
    "siem_alarm_soc_export_validator", str(EXPORT_VALIDATOR_PATH)
)
EXPORT_VALIDATOR = importlib.util.module_from_spec(VALIDATOR_SPEC)
VALIDATOR_SPEC.loader.exec_module(EXPORT_VALIDATOR)


class SocDashboardBundleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with (PROJECT_ROOT / "siem_alarm_template_final.json").open("r", encoding="utf-8") as handle:
            cls.template = json.load(handle)
        cls.records = BUILDER.build_records(cls.template)

    def test_committed_artifacts_are_reproducible(self):
        ndjson = BUILDER.render_ndjson(self.records)
        manifest = BUILDER.render_manifest(self.records, ndjson)
        export_request = BUILDER.render_export_request(self.records)

        self.assertEqual(
            ndjson,
            (PROJECT_ROOT / "dashboards" / "siem_alarm_soc_dashboard.ndjson").read_text(
                encoding="utf-8"
            ),
        )
        self.assertEqual(
            manifest,
            (PROJECT_ROOT / "dashboards" / "siem_alarm_soc_dashboard.manifest.json").read_text(
                encoding="utf-8"
            ),
        )
        self.assertEqual(
            export_request,
            (
                PROJECT_ROOT / "dashboards" / "siem_alarm_soc_dashboard.export-request.json"
            ).read_text(encoding="utf-8"),
        )

    def test_bundle_has_expected_object_inventory(self):
        counts = {}
        for record in self.records:
            counts[record["type"]] = counts.get(record["type"], 0) + 1
        self.assertEqual(
            counts,
            {"index-pattern": 1, "search": 5, "visualization": 19, "dashboard": 2},
        )
        self.assertEqual(len(self.records), 27)

    def test_data_view_is_self_contained_and_time_based(self):
        data_view = next(record for record in self.records if record["type"] == "index-pattern")
        self.assertEqual(data_view["id"], "siem-alarm-soc-v1-data-view")
        self.assertEqual(data_view["attributes"]["title"], "siem-alarm-*")
        self.assertEqual(data_view["attributes"]["timeFieldName"], "timestamp")

    def test_every_data_panel_pins_document_type(self):
        for record in self.records:
            if record["type"] not in ("search", "visualization"):
                continue
            if record["type"] == "visualization":
                vis_state = json.loads(record["attributes"]["visState"])
                if vis_state["type"] == "markdown":
                    continue
            search_source = json.loads(
                record["attributes"]["kibanaSavedObjectMeta"]["searchSourceJSON"]
            )
            self.assertIn("document.type", search_source["query"]["query"], record["id"])

    def test_raw_volume_is_never_summed_on_escalation_documents(self):
        for record in self.records:
            if record["type"] != "visualization":
                continue
            vis_state = json.loads(record["attributes"]["visState"])
            search_source = json.loads(
                record["attributes"]["kibanaSavedObjectMeta"]["searchSourceJSON"]
            )
            query = search_source.get("query", {}).get("query", "")
            for agg in vis_state.get("aggs", []):
                is_raw_sum = (
                    agg.get("type") == "sum"
                    and agg.get("params", {}).get("field") == "source.raw_alert_count"
                )
                if is_raw_sum:
                    self.assertIn('document.type: "alarm_state"', query)
                    self.assertNotIn('document.type: "alarm_escalation"', query)

    def test_internal_validator_accepts_bundle(self):
        BUILDER.validate_records(self.records, self.template)

    def test_backup_validator_requires_exact_object_set_and_export_details(self):
        manifest_path = PROJECT_ROOT / "dashboards" / "siem_alarm_soc_dashboard.manifest.json"
        lines = [BUILDER.compact(record) for record in self.records]
        lines.append(
            BUILDER.compact(
                {"exportedCount": 27, "missingRefCount": 0, "missingReferences": []}
            )
        )
        with tempfile.TemporaryDirectory() as directory:
            export_path = Path(directory) / "backup.ndjson"
            export_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
            count, digest = EXPORT_VALIDATOR.validate_export(export_path, manifest_path)
            self.assertEqual(count, 27)
            self.assertEqual(len(digest), 64)

            export_path.write_text("\n".join(lines[:-2] + lines[-1:]) + "\n", encoding="utf-8")
            with self.assertRaises(ValueError):
                EXPORT_VALIDATOR.validate_export(export_path, manifest_path)


if __name__ == "__main__":
    unittest.main()
