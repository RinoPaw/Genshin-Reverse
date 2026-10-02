from __future__ import annotations

import csv
import json
import tempfile
import unittest
from pathlib import Path

from genshinre.fingerprint import fingerprint
from genshinre.registry import CANONICAL_COLUMNS, normalize_registry, query_registry
from genshinre.scaffold import scaffold
from genshinre.validate import validate_version
from genshinre.wire import parse_message


class FingerprintTests(unittest.TestCase):
    def test_detects_metadata_formats(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            mhy = root / "global-metadata.dat"
            mhy.write_bytes(b"MHY\x00" + b"\x00" * 28)
            self.assertEqual("mhy-obfuscated-metadata", fingerprint(mhy)["format"])

            il2cpp = root / "standard.dat"
            il2cpp.write_bytes(bytes.fromhex("af1bb1fa") + b"\x00" * 28)
            self.assertEqual("standard-il2cpp-metadata", fingerprint(il2cpp)["format"])


class WireTests(unittest.TestCase):
    def test_cmdid_186_payload_shape(self) -> None:
        fields = parse_message(bytes.fromhex("7202d027"))
        self.assertEqual(1, len(fields))
        self.assertEqual(14, fields[0]["field_number"])
        self.assertEqual(2, fields[0]["wire_type"])
        self.assertEqual("d027", fields[0]["value_hex"])
        self.assertEqual([5072], fields[0]["packed_varints"])


class RegistryTests(unittest.TestCase):
    def test_normalize_and_query(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            raw = root / "raw.csv"
            raw.write_text(
                "cmdid,type,typedef,type_cache,direction,get_cmd_id,confidence\n"
                "26105,HJDNCHODGOL,123,0x57f0000,1,0x10587260,CONFIRMED\n"
                "22899,ONKOPMILDMF,87483,0x057F6F60,0,,HIGH_CONFIDENCE\n",
                encoding="utf-8",
            )
            out = root / "registry"
            summary = normalize_registry(raw, out, {"0": "S2C", "1": "C2S"})
            self.assertEqual(2, summary["row_count"])
            rows = query_registry(out / "registry.csv", cmd_id=26105)
            self.assertEqual("HJDNCHODGOL", rows[0]["type_name"])
            self.assertEqual("C2S", rows[0]["direction"])

            with (out / "registry.csv").open("r", encoding="utf-8", newline="") as f:
                self.assertEqual(tuple(csv.DictReader(f).fieldnames or ()), CANONICAL_COLUMNS)

    def test_scaffold_validates_as_partial(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            target = scaffold(Path(td), "9.9.9", "global", "windows-x64")
            errors, warnings = validate_version(target, allow_partial=True)
            self.assertEqual([], errors)
            self.assertTrue(warnings)
            data = json.loads((target / "hashes.json").read_text(encoding="utf-8"))
            self.assertEqual("9.9.9", data["game_version"])

    def test_validate_accepts_static_identity_registry(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            target = Path(td)
            (target / "registry").mkdir(parents=True)
            (target / "hashes.json").write_text('{"samples": {}}\n', encoding="utf-8")
            (target / "registry" / "registry.csv").write_text(
                "index,cmd_id,type_name,type_definition_index,direction,direction_status,"
                "semantic_name,type_slot_rva,get_cmd_id_rva,get_cmd_id_method,load_rva,"
                "store_rva,xref_count,xref_method_count,status,evidence\n"
                "0,25567,DBNMIKBJIPE,66061,S2C,control-confirmed,ScenePointUnlockNotify,"
                "0x57E0000,0x1252BA60,AEGNNPENLNM,0x7F00000,0x7F00007,7,3,"
                "static-verified-identity,verified registry identity\n",
                encoding="utf-8",
            )
            errors, warnings = validate_version(target, allow_partial=True)
            self.assertEqual([], errors)
            self.assertTrue(warnings)

    def test_validate_checks_analysis_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            target = scaffold(Path(td), "9.9.9", "global", "windows-x64")
            analysis = target / "analyses" / "example"
            analysis.mkdir(parents=True)
            evidence = {
                "topic": "example",
                "state": "ACTIVE",
                "sample": {
                    "game_version": "9.9.9",
                    "region": "global",
                    "platform": "windows-x64",
                    "hashes_ref": "../../hashes.json",
                },
                "questions": ["What happens?"],
                "claims": [
                    {
                        "id": "example-claim",
                        "status": "CANDIDATE",
                        "statement": "A candidate statement.",
                        "evidence": [{"kind": "synthetic", "source": "unit-test"}],
                    }
                ],
                "artifacts": ["README.md"],
                "next_steps": ["Collect stronger evidence."],
            }
            evidence_path = analysis / "evidence.json"
            evidence_path.write_text(json.dumps(evidence), encoding="utf-8")

            errors, _ = validate_version(target, allow_partial=True)
            self.assertEqual([], errors)

            evidence["claims"][0]["status"] = "PROBABLE"
            evidence_path.write_text(json.dumps(evidence), encoding="utf-8")
            errors, _ = validate_version(target, allow_partial=True)
            self.assertTrue(any("bad status PROBABLE" in error for error in errors))


if __name__ == "__main__":
    unittest.main()
