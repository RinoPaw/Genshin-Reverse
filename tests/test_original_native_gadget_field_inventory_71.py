"""Only original 7.1 client-decoded fields may enter the Gadget inventory."""
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "versions/7.1.0-global/analyses/progression/economy/7.1-reward-gadget-discriminator-inventory.json"
GADGET = ROOT / "genshinre/gadgetbin.py"
DOC = ROOT / "versions/7.1.0-global/analyses/progression/economy/7.1-reward-gadget-discriminators.md"

# The exact original native reader has eight inherited field slots and 22
# inner Gadget-specific memory offsets. Never translate them into invented
# gameplay names or import community/scene data under this inventory.
BASE = {"0x10", "0x18", "0x20", "0x28", "0x30", "0x34", "0x38", "0x40"}
INNER = {"0x48", "0x50", "0x58", "0x60", "0x68", "0x6C", "0x70", "0x74",
         "0x78", "0x79", "0x7A", "0x7B", "0x7C", "0x7D", "0x7E", "0x7F",
         "0x80", "0x84", "0x88", "0x90", "0x94", "0x98"}
BAD_SOURCE_KEYS = {"historicalScene", "historicalLua", "fork", "community",
                   "drop_tag", "chest_drop_id", "chestGrade", "rewardRegion"}


class NativeOnlyRewardGadgetInventoryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report = json.loads(DATA.read_text(encoding="utf-8"))

    def test_exact_source_pinned_and_native_offsets(self):
        report = self.report
        self.assertEqual(report["status"], "ORIGINAL_GLOBAL_7_1_CLIENT_NATIVE_GADGET_FIELDS_ONLY")
        self.assertEqual(report["sources"]["rawSha256"],
                         "a35e3f3ed04f950cb6302099d12aa71e23ece21d8fe578950347d9318f769e35")
        self.assertEqual(report["table"]["decodedRows"], 30599)
        self.assertEqual(report["table"]["unparsedBytes"], 0)
        self.assertEqual({x["candidateMemoryOffset"] for x in report["inheritedFields"]}, BASE)
        self.assertEqual({x["candidateMemoryOffset"] for x in report["gadgetFields"]}, INNER)
        self.assertTrue(all(0 < x["presentIn30599Rows"] <= 30599
                            for x in report["gadgetFields"]))

    def test_gadget_keys_are_not_conflated_with_gameplay_labels(self):
        report = self.report
        self.assertEqual(report["observationsDirectlyFromOriginal"]
                         ["offset0x6CNumeric26Population"], 309)
        self.assertEqual(len(report["observationsDirectlyFromOriginal"]
                             ["verifiedDefaultLockedBrambleFrozenLv1ThroughLv5"]), 20)
        self.assertTrue(all(x["preWrapperGadgetKey"] > 0 for x in
                            report["observationsDirectlyFromOriginal"]
                            ["verifiedDefaultLockedBrambleFrozenLv1ThroughLv5"]))
        data_keys = set(report)
        self.assertFalse(data_keys & BAD_SOURCE_KEYS)
        self.assertFalse(set(report["sources"]) & BAD_SOURCE_KEYS)
        doc = DOC.read_text(encoding="utf-8")
        self.assertIn("只展示经过原版客户端二进制", doc)
        self.assertIn("0x30", doc)
        self.assertIn("0x6C", doc)
        coverage = report["observationsDirectlyFromOriginal"]["type26OptionalBooleanWireCoverage"]
        self.assertTrue(all(set(x) == {"presentTrue", "presentFalse", "absentOnWire"}
                            and sum(x.values()) == 309 for x in coverage.values()))

    def test_authoritative_decoder_contains_same_native_field_slots(self):
        import ast
        module = ast.parse(GADGET.read_text(encoding="utf-8"))
        fields = {}
        for statement in module.body:
            if isinstance(statement, ast.Assign):
                for target in statement.targets:
                    if isinstance(target, ast.Name) and target.id in {"SCHEMA", "BASE_SCHEMA"}:
                        fields[target.id] = ast.literal_eval(statement.value)
        self.assertEqual({"0x%X" % item[0] for item in fields["SCHEMA"]}, INNER)
        self.assertEqual({"0x%X" % item[1] for item in fields["BASE_SCHEMA"]}, BASE)


if __name__ == "__main__":
    unittest.main()
