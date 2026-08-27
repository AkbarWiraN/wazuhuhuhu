#!/usr/bin/env python3
"""Fail-closed validation of an exact-ID Saved Objects backup export."""

import argparse
import hashlib
import json
import sys
from pathlib import Path


DEFAULT_MANIFEST = Path(__file__).resolve().parent / "siem_alarm_soc_dashboard.manifest.json"


def load_json_lines(path):
    records = []
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            try:
                records.append((line_number, json.loads(line)))
            except json.JSONDecodeError as exc:
                raise ValueError("invalid JSON on line %d: %s" % (line_number, exc))
    if not records:
        raise ValueError("backup export is empty")
    return records


def expected_keys_from_manifest(manifest):
    return {(item["type"], item["id"]) for item in manifest["object_ids"]}


def validate_export(export_path, manifest_path):
    with manifest_path.open("r", encoding="utf-8") as handle:
        manifest = json.load(handle)
    expected = expected_keys_from_manifest(manifest)
    expected_count = int(manifest["object_count"])
    if len(expected) != expected_count:
        raise ValueError("manifest object_count does not match its unique object ID set")

    objects = []
    export_details = []
    for line_number, record in load_json_lines(export_path):
        if "type" in record and "id" in record and "attributes" in record:
            objects.append((line_number, record))
        elif "exportedCount" in record:
            export_details.append((line_number, record))
        else:
            raise ValueError("unexpected record on line %d" % line_number)

    if len(export_details) != 1:
        raise ValueError("backup must contain exactly one export-details record")
    details = export_details[0][1]
    if details.get("exportedCount") != expected_count:
        raise ValueError(
            "exportedCount mismatch: expected %d, got %r"
            % (expected_count, details.get("exportedCount"))
        )
    if details.get("missingRefCount") != 0 or details.get("missingReferences") not in ([], None):
        raise ValueError("backup export reports missing references")

    actual_keys = [(record["type"], record["id"]) for _, record in objects]
    if len(actual_keys) != len(set(actual_keys)):
        raise ValueError("backup contains duplicate (type, id) records")
    actual = set(actual_keys)
    missing = sorted(expected - actual)
    unexpected = sorted(actual - expected)
    if missing or unexpected:
        raise ValueError("exact object set mismatch; missing=%r unexpected=%r" % (missing, unexpected))
    if len(objects) != expected_count:
        raise ValueError("backup object record count mismatch")

    digest = hashlib.sha256(export_path.read_bytes()).hexdigest()
    return expected_count, digest


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("export", type=Path, help="Saved Objects NDJSON export to validate")
    parser.add_argument(
        "--manifest",
        type=Path,
        default=DEFAULT_MANIFEST,
        help="bundle manifest containing the exact expected object set",
    )
    args = parser.parse_args(argv)
    try:
        count, digest = validate_export(args.export, args.manifest)
    except (OSError, KeyError, TypeError, ValueError) as exc:
        print("[-] Saved Objects backup invalid: %s" % exc, file=sys.stderr)
        return 1
    print("[+] Saved Objects backup valid: %d exact objects" % count)
    print("[+] SHA256: %s" % digest)
    return 0


if __name__ == "__main__":
    sys.exit(main())
