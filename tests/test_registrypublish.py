from __future__ import annotations

import csv
import json
import tempfile
import unittest
from pathlib import Path

from genshinre.registrypublish import publish_canonical_registry_71


class RegistryPublishTests(unittest.TestCase):
    def _write_csv(self, path: Path, fields: tuple[str, ...], rows) -> None:
        with path.open("w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fields)
            writer.writeheader()
            writer.writerows(rows)

    def test_rejects_unclosed_native_paths_before_reading_inputs(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            comparison = root / "compare.json"
            direction = root / "direction.json"
            hashes = root / "hashes.json"
            comparison.write_text(json.dumps({"full_agreement": False}), encoding="utf-8")
            direction.write_text("{}", encoding="utf-8")
            hashes.write_text("{}", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "full row-by-row agreement"):
                publish_canonical_registry_71(
                    root / "missing-direct.csv",
                    root / "missing-usage.csv",
                    comparison,
                    direction,
                    root / "missing-known.csv",
                    root / "missing-getcmd.csv",
                    hashes,
                    root / "out",
                )

    def test_publishes_only_after_all_gates_pass(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            direct = root / "direct.csv"
            usage = root / "usage.csv"
            known = root / "known.csv"
            getcmd = root / "getcmd.csv"
            comparison = root / "compare.json"
            direction = root / "direction.json"
            hashes = root / "hashes.json"
            output = root / "out"

            direct_rows = []
            usage_rows = []
            for index in range(4896):
                cmd_id = index + 1
                flag = 1 if cmd_id % 2 else 0
                slot = 0x5000000 + index * 8
                tdi = 10000 + index
                direct_rows.append(
                    {
                        "index": index,
                        "cmd_id": cmd_id,
                        "registry_flag": flag,
                        "type_slot_rva": f"0x{slot:X}",
                    }
                )
                usage_rows.append(
                    {
                        "index": index,
                        "cmd_id": cmd_id,
                        "registry_flag": flag,
                        "type_slot_rvas": f"0x{slot:X}",
                        "type_definition_index": tdi,
                        "type_name": f"TYPE_{tdi}",
                    }
                )

            self._write_csv(
                direct,
                ("index", "cmd_id", "registry_flag", "type_slot_rva"),
                direct_rows,
            )
            self._write_csv(
                usage,
                ("index", "cmd_id", "registry_flag", "type_slot_rvas", "type_definition_index", "type_name"),
                usage_rows,
            )
            self._write_csv(
                known,
                ("semantic_name", "cmd_id"),
                [
                    {"semantic_name": "FooReq", "cmd_id": 1},
                    {"semantic_name": "FooRsp", "cmd_id": 2},
                ],
            )
            self._write_csv(
                getcmd,
                ("cmd_id", "type_definition_index", "get_cmd_id_rva"),
                [
                    {"cmd_id": 1, "type_definition_index": 10000, "get_cmd_id_rva": "0x1234"},
                    {"cmd_id": 2, "type_definition_index": 10001, "get_cmd_id_rva": "0x5678"},
                ],
            )
            comparison.write_text(
                json.dumps(
                    {
                        "full_agreement": True,
                        "status": "independent-native-paths-agree",
                        "complete_matches": 4896,
                    }
                ),
                encoding="utf-8",
            )
            direction.write_text(
                json.dumps(
                    {
                        "status": "direction-mapping-strongly-validated",
                        "perfect_req_rsp_suffix_agreement": True,
                        "perfect_req_rsp_pair_agreement": True,
                    }
                ),
                encoding="utf-8",
            )
            hashes.write_text(
                json.dumps(
                    {
                        "game_version": "7.1.0",
                        "region": "global",
                        "platform": "windows-x64",
                        "samples": {
                            "GenshinImpact.exe": {"sha256": "exe"},
                            "global-metadata.dat": {"sha256": "metadata"},
                        },
                    }
                ),
                encoding="utf-8",
            )

            result = publish_canonical_registry_71(
                direct,
                usage,
                comparison,
                direction,
                known,
                getcmd,
                hashes,
                output,
            )
            self.assertEqual(4896, result["row_count"])
            self.assertEqual(4896, result["unique_cmd_ids"])
            self.assertEqual(2, result["semantic_name_count"])
            self.assertEqual("canonical-static-registry", result["status"])

            with (output / "registry.csv").open("r", encoding="utf-8", newline="") as f:
                rows = list(csv.DictReader(f))
            self.assertEqual("1", rows[0]["cmd_id"])
            self.assertEqual("C2S", rows[0]["direction"])
            self.assertEqual("FooReq", rows[0]["semantic_name"])
            self.assertEqual("0x1234", rows[0]["get_cmd_id_rva"])
            self.assertEqual("2", rows[1]["cmd_id"])
            self.assertEqual("S2C", rows[1]["direction"])
            self.assertEqual("FooRsp", rows[1]["semantic_name"])


if __name__ == "__main__":
    unittest.main()
