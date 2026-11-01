"""Tests for original-client native sector field mapping."""
import csv
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from genshinre.worldsector71 import OWNERS, TYPE_SIGNATURES, extract_metadata, verify_original_exe


class WorldSector71Tests(unittest.TestCase):
    def make_csv(self, folder: Path):
        types = folder / "types.csv"
        fields = folder / "fields.csv"
        methods = folder / "methods.csv"
        with types.open("w", newline="", encoding="utf-8") as file:
            writer = csv.DictWriter(file, fieldnames=("type_definition_index", "namespace", "type_name"))
            writer.writeheader()
            for idx, (name, _) in OWNERS.items():
                writer.writerow({"type_definition_index": idx, "namespace": "MoleMole", "type_name": name})
        with fields.open("w", newline="", encoding="utf-8") as file:
            writer = csv.DictWriter(file, fieldnames=(
                "field_index", "type_definition_index", "field_name", "field_type", "field_type_index"))
            writer.writeheader()
            index = 200
            for type_id, (_, required) in OWNERS.items():
                for name in required:
                    writer.writerow({
                        "field_index": index, "type_definition_index": type_id,
                        "field_name": name,
                        "field_type": TYPE_SIGNATURES.get((type_id, name), "kind_0x15"),
                        "field_type_index": index + 400,
                    })
                    index += 1
        with methods.open("w", newline="", encoding="utf-8") as file:
            writer = csv.DictWriter(file, fieldnames=("type_definition_index", "method_name", "rva"))
            writer.writeheader()
            writer.writerow({
                "type_definition_index": 58901, "method_name": "set_position",
                "rva": "0x12DA02C0",
            })
        return types, fields, methods

    def test_native_owner_fields_and_vector_layout(self):
        with TemporaryDirectory() as td:
            result = extract_metadata(*self.make_csv(Path(td)))
        owners = {r["typeName"]: r for r in result["owners"]}
        self.assertEqual(11, len(owners))
        stream = owners["SECTR_StreamObjectSerialize"]
        self.assertEqual("NFFDDFHHDHG", next(
            r["type"] for r in stream["fields"] if r["name"] == "_position"))
        self.assertEqual("uint64", next(
            r["type"] for r in owners["SECTR_LODFinInfo"]["fields"]
            if r["name"] == "colliderPathHash"))
        self.assertEqual("set_position", stream["methods"][0]["name"])

    def test_original_field_layout_mismatch_fails_closed(self):
        with TemporaryDirectory() as td:
            types, fields, methods = self.make_csv(Path(td))
            text = fields.read_text(encoding="utf-8")
            fields.write_text(text.replace("_position,NFFDDFHHDHG", "_position,float32"), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "native type changed"):
                extract_metadata(types, fields, methods)

    def test_wrong_executable_is_rejected(self):
        with TemporaryDirectory() as td:
            path = Path(td) / "GenshinImpact.exe"
            path.write_bytes(b"not the original Global 7.1 executable")
            with self.assertRaisesRegex(ValueError, "not the pinned Global 7.1"):
                verify_original_exe(path)

    def test_checked_in_source_evidence_preserves_unresolved_gate(self):
        path = (Path(__file__).resolve().parents[1] /
                "versions/7.1.0-global/analyses/world/7.1-native-sector-transform-and-collider-schema.json")
        data = json.loads(path.read_text(encoding="utf-8"))
        self.assertFalse(data["evidence"]["safeServerWorldHeightQuery"])
        self.assertEqual("CONFIRMED_NATIVE_FIELDS",
                         data["evidence"]["serializedWorldObjectTransforms"])


if __name__ == "__main__":
    unittest.main()
