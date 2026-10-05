import struct
import unittest

from genshinre.assetindex import mihoyo_name_hash, parse_asset_index, unwrap_mihoyo_bin_data


def u32(value: int) -> bytes:
    return struct.pack("<I", value)


def raw_export(payload: bytes) -> bytes:
    return u32(len(payload)) + payload + b"\0"


class AssetIndexTest(unittest.TestCase):
    def test_quest_excel_hash_matches_7_1_design_index_identity(self):
        value = mihoyo_name_hash("Data/_ExcelBinOutput/QuestExcelConfigData")
        self.assertEqual(value, 0x3B87AE8396)
        self.assertEqual((value >> 8) & 0xFFFFFFFF, 0x3B87AE83)

    def test_parse_current_layout(self):
        payload = bytearray()
        payload += u32(0)  # types
        payload += u32(1)  # names
        payload += bytes([0x96]) + u32(0x3B87AE83)
        payload += bytes.fromhex("0000000000") + u32(178)
        payload += u32(0) + u32(0) + u32(537)  # deps + two header words
        payload += u32(0)  # preload
        payload += u32(0)  # shader preload
        payload += u32(1)  # groups
        payload += u32(0) + u32(1)
        payload += u32(25539185) + bytes.fromhex("0301")
        payload += u32(1)  # block infos
        payload += u32(25539185) + u32(1)
        payload += u32(178) + u32(0) + u32(0)
        payload += u32(0)  # sort list

        index = parse_asset_index(raw_export(bytes(payload)))
        name = index.name_for_hash(0x3B87AE8396)
        self.assertEqual(name.sub_asset_id, 178)
        self.assertEqual(name.exported_name, "3b87ae83")
        self.assertEqual(index.block_groups[25539185], 0)
        block_ref = index.block_ref_for_asset(name.sub_asset_id)
        self.assertEqual((block_ref.block_id, block_ref.unknown0, block_ref.unknown1), (25539185, 0, 0))

    def test_reject_nonzero_raw_export_padding(self):
        with self.assertRaisesRegex(ValueError, "padding"):
            unwrap_mihoyo_bin_data(u32(1) + b"x" + b"!")


if __name__ == "__main__":
    unittest.main()
