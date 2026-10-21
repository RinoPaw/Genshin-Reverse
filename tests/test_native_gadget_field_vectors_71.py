"""Source-bound native 7.1 Gadget field-vector report contracts."""
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / 'versions/7.1.0-global/analyses/progression/economy/7.1-native-gadget-field-vectors.json'
SHA = 'a35e3f3ed04f950cb6302099d12aa71e23ece21d8fe578950347d9318f769e35'


class NativeGadgetFieldVectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = json.loads(DATA.read_text(encoding='utf-8'))

    def test_source_and_exact_record_counts(self):
        doc = self.data
        self.assertEqual(doc['source']['rawSha256'], SHA)
        self.assertEqual(doc['source']['decoder'], 'genshinre/gadgetbin.py')
        self.assertEqual(doc['controls']['fullDecodedRows'], 30599)
        self.assertEqual(doc['controls']['numeric26Rows'], 309)
        self.assertEqual(len(doc['numeric26Records']), 309)
        self.assertEqual(doc['controls']['literalChestOutsideNumeric26Rows'], 31)
        self.assertEqual(len(doc['literalChestOutsideNumeric26Records']), 31)

    def test_raw_offsets_and_omissions(self):
        records = self.data['numeric26Records']
        self.assertEqual([r['preWrapperKeyAt0x30'] for r in records],
                         list(dict.fromkeys(r['preWrapperKeyAt0x30'] for r in records)))
        for row in records:
            self.assertEqual(row['gadgetByOffset']['0x6C'], 26)
            self.assertEqual(row['gadgetByOffset']['0x58'], row['literalAt0x58'])
            self.assertEqual(row['inheritedByOffset']['0x30'], row['preWrapperKeyAt0x30'])
        for row in self.data['literalChestOutsideNumeric26Records']:
            self.assertIn('Chest', row['literalAt0x58'])
            self.assertNotEqual(row['gadgetByOffset'].get('0x6C'), 26)

    def test_literal_groups_and_boolean_wire_presence(self):
        expected = {'literal_SceneObj_Chest_prefix': 162,
                    'literal_SearchPoint_prefix': 21, 'other_literal_names': 126}
        groups = self.data['numeric26LiteralGroups']
        self.assertEqual({k: v['rows'] for k, v in groups.items()}, expected)
        for group in groups.values():
            count = group['rows']
            for offset, field in group['nativeFieldCoverage'].items():
                self.assertEqual(field['present'] + field['absent'], count)
                if offset in {'0x78', '0x79', '0x7A', '0x7B',
                              '0x7C', '0x7D', '0x7E', '0x7F'}:
                    self.assertEqual(field['presentTrue'] + field['presentFalse'],
                                     field['present'])


if __name__ == '__main__':
    unittest.main()
