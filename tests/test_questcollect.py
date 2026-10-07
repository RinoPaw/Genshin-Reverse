from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from genshinre.cli import build_parser
from genshinre.questcollect import QuestCollectionError, collect_quest_payloads


ROOT = Path(__file__).resolve().parents[1]


def _raw_export(payload: bytes) -> bytes:
    return len(payload).to_bytes(4, "little") + payload


class QuestCollectTests(unittest.TestCase):
    def test_cli_parses_quest_collect_contract(self) -> None:
        args = build_parser().parse_args(
            [
                "quest-collect",
                "assets.json",
                "exports",
                "payloads",
                "--coverage",
                "coverage.json",
            ]
        )
        self.assertEqual("quest-collect", args.command)
        self.assertEqual("assets.json", str(args.asset_manifest))
        self.assertEqual("exports", str(args.export_root))
        self.assertEqual("payloads", str(args.output_dir))
        self.assertEqual("coverage.json", str(args.coverage))

    def test_collects_gold_payloads_and_runs_batch_coverage(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            exports = root / "exports"
            manifest = {"assets": []}
            for index, main_id in enumerate((351, 375, 376, 388), start=1):
                payload = bytes.fromhex(
                    (ROOT / "tests" / "fixtures" / f"quest{main_id}.hex").read_text(
                        encoding="ascii"
                    )
                )
                block_id = 1000 + index
                exported_name = f"{main_id:08x}"
                raw = (
                    exports
                    / "0"
                    / str(block_id)
                    / "MiHoYoBinData"
                    / f"{exported_name}.dat"
                )
                raw.parent.mkdir(parents=True, exist_ok=True)
                raw.write_bytes(_raw_export(payload))
                manifest["assets"].append(
                    {
                        "mainId": main_id,
                        "groupId": 0,
                        "blockId": block_id,
                        "exportedName": exported_name,
                    }
                )

            manifest_path = root / "assets.json"
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            coverage_path = root / "coverage.json"
            result = collect_quest_payloads(
                manifest_path,
                exports,
                root / "payloads",
                coverage_path=coverage_path,
            )

            self.assertEqual(4, result["expected"])
            self.assertEqual(4, result["collected"])
            self.assertEqual(4, result["coverage"]["fullConsumed"])
            self.assertEqual(0, result["coverage"]["failed"])
            self.assertTrue(coverage_path.is_file())
            self.assertEqual(920, (root / "payloads" / "351").stat().st_size)

    def test_missing_export_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manifest = root / "assets.json"
            manifest.write_text(
                json.dumps(
                    {
                        "assets": [
                            {
                                "mainId": 351,
                                "groupId": 0,
                                "blockId": 24230448,
                                "exportedName": "da285d08",
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(QuestCollectionError, "missing Raw export"):
                collect_quest_payloads(manifest, root / "exports", root / "payloads")


if __name__ == "__main__":
    unittest.main()
