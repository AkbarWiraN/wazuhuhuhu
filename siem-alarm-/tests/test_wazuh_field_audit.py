import datetime as dt
import importlib.util
import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "wazuh_field_audit_final.py"
SPEC = importlib.util.spec_from_file_location("wazuh_field_audit_final", MODULE_PATH)
assert SPEC and SPEC.loader
field_audit = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(field_audit)


class FieldAuditTests(unittest.TestCase):
    def test_daily_pattern_resolves_only_dates_in_utc_window(self) -> None:
        start = dt.datetime(2026, 8, 24, 12, 0, tzinfo=dt.timezone.utc)
        end = dt.datetime(2026, 8, 25, 12, 0, tzinfo=dt.timezone.utc)
        self.assertEqual(
            field_audit.resolve_indices("wazuh-alerts-4.x-{date}", start, end),
            ["wazuh-alerts-4.x-2026.08.24", "wazuh-alerts-4.x-2026.08.25"],
        )

    def test_wildcard_and_unsafe_index_patterns_are_rejected(self) -> None:
        now = dt.datetime(2026, 8, 25, tzinfo=dt.timezone.utc)
        for pattern in ["wazuh-alerts-*", "Wazuh-{date}", "../../{date}"]:
            with self.subTest(pattern=pattern):
                with self.assertRaises(ValueError):
                    field_audit.resolve_indices(pattern, now, now)


if __name__ == "__main__":
    unittest.main()
