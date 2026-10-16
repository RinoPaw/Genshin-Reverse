from __future__ import annotations

import csv
import importlib.util
from pathlib import Path
import tempfile
import unittest

SOURCE = Path(__file__).resolve().parents[1] / "tools/probe_world_area_native_71.py"
spec = importlib.util.spec_from_file_location("world_area_native_probe_71", SOURCE)
native = importlib.util.module_from_spec(spec)
spec.loader.exec_module(native)


class WorldAreaNativeProbeTests(unittest.TestCase):
    def test_exact_type_signature_no_substring_fraud(self):
        self.assertTrue(native.matching_signature('["uint32", "GEAMLDNCCEP"]',
                                                  "GEAMLDNCCEP"))
        self.assertTrue(native.matching_signature("List<GEAMLDNCCEP>", "GEAMLDNCCEP"))
        self.assertFalse(native.matching_signature('["FAKEGEAMLDNCCEP"]', "GEAMLDNCCEP"))
        self.assertFalse(native.matching_signature("GEAMLDNCCEPExtra", "GEAMLDNCCEP"))
        self.assertFalse(native.matching_signature("", "GEAMLDNCCEP"))

    def test_requires_both_exact_native_type_identities(self):
        with tempfile.TemporaryDirectory() as directory:
            registry = Path(directory) / "registry.csv"
            fieldnames = ["cmd_id", "type_name", "type_definition_index", "get_cmd_id_rva",
                          "type_slot_rva", "status"]
            with registry.open("w", newline="", encoding="utf-8") as stream:
                writer = csv.DictWriter(stream, fieldnames)
                writer.writeheader()
                writer.writerow(dict(cmd_id=25407, type_name="GEAMLDNCCEP",
                                     type_definition_index=82921))
                writer.writerow(dict(cmd_id=6774, type_name="ICMCPHPFIKJ",
                                     type_definition_index=83231))
            self.assertEqual([25407, 6774],
                             [v["cmd_id"] for v in native.load_registry(registry)])
            content = registry.read_text(encoding="utf-8")
            registry.write_text(content.replace("82921", "82922"), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "unexpected 7.1 CmdId"):
                native.load_registry(registry)

    def test_metadata_joins_protocol_and_external_signatures(self):
        with tempfile.TemporaryDirectory() as directory:
            methods = Path(directory) / "methods.csv"
            fields = Path(directory) / "fields.csv"
            with methods.open("w", newline="", encoding="utf-8") as stream:
                writer = csv.DictWriter(stream, ["method_index", "type_definition_index",
                    "type_name", "method_name", "rva", "parameter_types", "return_type"])
                writer.writeheader()
                writer.writerow(dict(method_index=1, type_definition_index=82921,
                                     type_name="GEAMLDNCCEP", method_name=".ctor",
                                     rva="0x1234", parameter_types="[]"))
                writer.writerow(dict(method_index=2, type_definition_index=83231,
                                     type_name="ICMCPHPFIKJ", method_name=".ctor",
                                     rva="0x5678", parameter_types="[]"))
                writer.writerow(dict(method_index=3, type_definition_index=3,
                                     type_name="SENDER", method_name="CreateRequest",
                                     rva="0x9000", parameter_types='["GEAMLDNCCEP"]'))
                writer.writerow(dict(method_index=4, type_definition_index=4,
                                     type_name="NOT_A_SENDER", method_name="Wrong",
                                     rva="0x9001", parameter_types='["GEAMLDNCCEPExtra"]'))
            with fields.open("w", newline="", encoding="utf-8") as stream:
                writer = csv.DictWriter(stream, ["field_index", "type_definition_index",
                                                 "type_name", "field_name"])
                writer.writeheader()
                writer.writerow(dict(field_index=8, type_definition_index=82921,
                                     type_name="GEAMLDNCCEP", field_name="FOO"))
            report = native.stream_metadata(methods, fields)
            self.assertEqual(1, len(report["external_signature_references"]))
            self.assertEqual("SENDER", report["external_signature_references"][0]["type_name"])
            self.assertEqual("FOO", report["protocol_fields"]["GEAMLDNCCEP"][0]["field_name"])


if __name__ == "__main__":
    unittest.main()
