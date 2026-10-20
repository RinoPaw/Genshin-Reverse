"""Synthetic evidence boundaries for the 7.1 Gadget metadata token probe."""
from __future__ import annotations

import csv
import hashlib
import importlib.util
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/probe-7.1-chest-gadget-schema.py"
spec = importlib.util.spec_from_file_location("chest_gadget_schema_probe", SCRIPT)
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


def write_csv(path, header, records):
    with path.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=header)
        writer.writeheader()
        writer.writerows(records)


class TestChestGadgetSchema(unittest.TestCase):
    def test_owner_recovery_keeps_metadata_not_semantics(self):
        with TemporaryDirectory() as temp:
            directory = Path(temp)
            fields, methods = directory / "fields.csv", directory / "methods.csv"
            write_csv(fields,
                      ["field_index", "field_name", "field_type", "type_definition_index", "type_name"],
                      [
                          dict(field_index="20", field_name="NGDGAAEHPHB", field_type="bool",
                               type_definition_index="7", type_name="OBFUSCATED"),
                          dict(field_index="21", field_name="OTHER", field_type="int",
                               type_definition_index="7", type_name="OBFUSCATED"),
                          dict(field_index="22", field_name="MECPCDBEFBG", field_type="bool",
                               type_definition_index="8", type_name="OTHER_OWNER"),
                      ])
            write_csv(methods,
                      ["type_definition_index", "method_name", "method_index", "rva", "parameter_types"],
                      [
                          dict(type_definition_index="7", method_name="OPAQUE",
                               method_index="45", rva="0xAB", parameter_types="FNIAHJGHFAK"),
                          dict(type_definition_index="8", method_name="OTHER_METHOD",
                               method_index="46", rva="0xBC", parameter_types="int"),
                      ])
            report = probe.locate(fields, methods, check_sources=False)
            self.assertEqual(report["matchedOwnerCount"], 2)
            self.assertEqual(len(report["owners"]["7"]["fields"]), 2)
            self.assertTrue(report["owners"]["7"]["methods"][0]["binaryReaderSignatureCandidate"])
            self.assertEqual(report["tokenHits"]["OLOLLKJCHHI"], [])
            self.assertIn("WIRE_SCHEMA_UNRESOLVED", report["status"])

    def test_zero_hits_is_not_a_claim_of_client_absence(self):
        with TemporaryDirectory() as temp:
            d = Path(temp)
            fields, methods = d / "fields.csv", d / "methods.csv"
            write_csv(fields, ["type_definition_index", "field_name"], [
                {"type_definition_index": "1", "field_name": "unrelated"}])
            write_csv(methods, ["type_definition_index", "method_name"], [])
            report = probe.locate(fields, methods, check_sources=False)
            self.assertEqual(report["matchedOwnerCount"], 0)
            self.assertIn("NO_COMMUNITY_TOKENS", report["status"])

    def test_git_blob_separator_is_nul(self):
        with TemporaryDirectory() as temp:
            p = Path(temp) / "example"
            p.write_bytes(b"native evidence")
            data = p.read_bytes()
            expected = hashlib.sha1(b"blob " + str(len(data)).encode()
                                    + b"\\0" + data).hexdigest()
            self.assertEqual(probe.git_blob(p), expected)


if __name__ == "__main__":
    unittest.main()
