from __future__ import annotations

import struct
import unittest

from genshinre.assetindex import AssetBlockRef, AssetIndex, AssetNameHash, mihoyo_name_hash
from genshinre.cli import build_parser
from genshinre.questresources import (
    MainQuestIndexEntry,
    parse_main_quest_index,
    resolve_main_quest_assets,
)


MASK32 = 0xFFFFFFFF
MASK64 = 0xFFFFFFFFFFFFFFFF
HANDLE_351 = 0x14B93FDA285D0829


def _raw_export(payload: bytes) -> bytes:
    return len(payload).to_bytes(4, "little") + payload


def _encode_main_quest_index(rows: list[tuple[int, int]]) -> bytes:
    count = len(rows)
    encoded_count = (((count - 0x0A34766E) & MASK32) ^ 0x5785D208) & MASK32
    payload = bytearray(struct.pack("<I", encoded_count))
    for main_id, handle in rows:
        payload += struct.pack("<I", main_id ^ 0x92C938B5)
        payload += struct.pack("<Q", (handle - 0x2B6567EA) & MASK64)
    return _raw_export(bytes(payload))


class QuestResourceTests(unittest.TestCase):
    def test_cli_parses_quest_asset_manifest_contract(self) -> None:
        args = build_parser().parse_args(
            ["quest-assets", "design.dat", "MainQuestIndex.dat", "--output", "assets.json"]
        )
        self.assertEqual("quest-assets", args.command)
        self.assertEqual("design.dat", str(args.design_asset_index))
        self.assertEqual("MainQuestIndex.dat", str(args.main_quest_index))
        self.assertEqual("assets.json", str(args.output))

    def test_parse_main_quest_index_exact_351_anchor(self) -> None:
        rows = parse_main_quest_index(_encode_main_quest_index([(351, HANDLE_351)]))
        self.assertEqual(
            (MainQuestIndexEntry(index=0, main_id=351, handle=HANDLE_351),),
            rows,
        )

    def test_resolve_main_quest_351_handle_to_design_block(self) -> None:
        path_hash = mihoyo_name_hash("Data/_BinOutput/Quest/351")
        self.assertEqual(0xDA285D0829, path_hash)

        sub_asset_id = 77
        block_id = 24230448
        design = AssetIndex(
            names=(
                AssetNameHash(
                    path_hash_pre=path_hash & 0xFF,
                    path_hash_last=(path_hash >> 8) & MASK32,
                    sub_asset_id=sub_asset_id,
                ),
            ),
            block_groups={block_id: 0},
            block_refs=(
                AssetBlockRef(
                    asset_id=sub_asset_id,
                    block_id=block_id,
                    unknown0=0,
                    unknown1=0,
                ),
            ),
            sort_list=(),
        )

        locations = resolve_main_quest_assets(
            (MainQuestIndexEntry(index=0, main_id=351, handle=HANDLE_351),),
            design,
        )
        self.assertEqual(1, len(locations))
        item = locations[0]
        self.assertEqual(351, item.main_id)
        self.assertEqual("da285d08", item.exported_name)
        self.assertEqual(block_id, item.block_id)
        self.assertEqual(0, item.group_id)

    def test_main_quest_index_rejects_wrong_framing(self) -> None:
        raw = _encode_main_quest_index([(351, HANDLE_351)])
        payload = raw[4:] + b"\x00"
        with self.assertRaisesRegex(ValueError, "framing mismatch"):
            parse_main_quest_index(payload, raw_export=False)


if __name__ == "__main__":
    unittest.main()
