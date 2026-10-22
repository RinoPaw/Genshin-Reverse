"""Original Global 7.1 40-bit index / 32-bit exporter-name boundary."""
import importlib.util
from pathlib import Path
import unittest
from genshinre.assetindex import AssetBlockRef, AssetIndex, AssetNameHash

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "native_index_71", ROOT / "scripts/audit-7.1-original-worldarea-index-coverage.py")
m = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(m)


class OriginalWorldAreaIndexCoverage(unittest.TestCase):
    def test_export_name_omits_one_byte(self):
        a = AssetNameHash(0x11, 0x12345678, 1)
        b = AssetNameHash(0x12, 0x12345678, 2)
        self.assertNotEqual(a.value, b.value)
        self.assertEqual(a.exported_name, b.exported_name)

    def test_complete_category_classification(self):
        index = AssetIndex(
            names=(
                AssetNameHash(1, 0xAABBCCDD, 10),
                AssetNameHash(2, 0x10203040, 20),
                AssetNameHash(3, 0x55667788, 30),
                AssetNameHash(4, 0x11223344, 10),
                AssetNameHash(5, 0x11223344, 20),
                AssetNameHash(6, 0x34567890, 40),
            ),
            block_groups={24230448: 0, 321: 0},
            block_refs=(
                AssetBlockRef(10, 24230448, 0, 0),
                AssetBlockRef(20, 321, 0, 0),
                AssetBlockRef(30, 999, 0, 0),
            ), sort_list=())
        files = {"aabbccdd.dat": 15, "10203040.dat": 20,
                 "55667788.dat": 25, "11223344.dat": 30,
                 "deadbeef.dat": 35, "34567890.dat": 40}
        report = m.classify(index, files)
        groups = report["exportGroups"]
        self.assertEqual(groups["uniqueStemMappedToTargetBlockFiles"], 1)
        self.assertEqual(groups["ambiguousStemIncludingTargetBlockFiles"], 1)
        self.assertEqual(groups["stemMappedOnlyToOtherBlocksFiles"], 1)
        self.assertEqual(groups["stemWithUnresolvedBlockRefFiles"], 2)
        self.assertEqual(groups["notInThisDesignIndexFiles"], 1)
        self.assertEqual(report["indexHashCounts"]["ambiguousStems32"], 1)
        self.assertEqual(report["indexHashCounts"]["targetBlockHashRows40"], 2)
        self.assertEqual(sum(v for k, v in groups.items() if k.endswith("RawBytes")), 165)

    def test_raw_size_histogram(self):
        report = m.size_counts({"a": 4, "b": 20, "c": 70, "d": 5000})
        self.assertEqual(report["bins"],
                         {"4096to65535": 1, "64to255": 1, "8to63": 1, "lt8": 1})
        self.assertEqual(report["median"], 70)


if __name__ == "__main__":
    unittest.main()
