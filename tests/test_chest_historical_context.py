"""Synthetic regression tests for historical chest source comparison."""
import importlib.util
from pathlib import Path
import tempfile
import unittest
SCRIPT=Path(__file__).resolve().parents[1]/'scripts'/'audit-chest-historical-context.py'
spec=importlib.util.spec_from_file_location('chest_historical_context',SCRIPT)
audit=importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)

def r(level,tag,id,source='19'):
    return {'最小等级':str(level),'总索引':tag,'掉落ID':str(id),'掉落次数':'1','产出来源类型':source}
def node(id,child):
    return {'掉落ID':str(id),'随机方式':'1','掉落层级':'0','节点类型':'0',
            '产出来源类型':'19','子掉落1ID':str(child),'子掉落1权重':'10000','子掉落1数量区间':'1'}

class HistoricalContextTest(unittest.TestCase):
    def test_different_source_type_encoding_is_not_claimed_equal(self):
        result=audit.historical_pairs([r(1,'战斗低级蒙德',51010000,'11007')],
                                      [r(1,'战斗低级蒙德',51010000)])
        self.assertEqual((1,1,0),(result['sameLevelAndTag'],result['sameRootAndCount'],result['differentRootOrCount']))
        self.assertFalse(result['sourceTypeComparable'])
    def test_changed_id_and_duplicate_key(self):
        self.assertEqual(1,audit.historical_pairs([r(1,'a',1)],[r(1,'a',2)])['differentRootOrCount'])
        with self.assertRaises(ValueError): audit.historical_pairs([r(1,'a',1)]*2,[r(1,'a',2)])
    def test_arrangement_categories_are_separate(self):
        limits=[{'类别':'0','掉落标签':'a','布设上限':'1'},
                {'类别':'1','掉落标签':'b','布设上限':'2'}]
        report=audit.arrangement_audit([r(1,'a',10),r(1,'b',20)],limits)
        self.assertEqual((1,1),(report['tagsAlsoInLimit'],report['chestDropTagsAbsentFromLimit']))
        self.assertFalse(report['placementPolicyValidated'])
    def test_mondstadt_graphs_compare_by_expansion(self):
        rows=[r(1,'战斗低级蒙德',100),r(1,'解谜低级蒙德',200),
              r(26,'战斗低级蒙德',300),r(26,'解谜低级蒙德',400)]
        report=audit.table_audit(rows,[node(100,102),node(200,202),node(300,102),node(400,202)],[])
        self.assertEqual(4,report['rootsInTree'])
        self.assertFalse(report['sample'][0]['sameExpandedHistoricalGraph'])
        self.assertFalse(report['native71Verified'])
    def test_earlier_tree_distinguishes_payload_edits_from_source_codes(self):
        older = [node(51010500, 102)]
        newer = [node(51010500, 102)]
        older[0]['产出来源类型'] = '11007'
        older[0]['子掉落1数量区间'] = '30'
        newer[0]['产出来源类型'] = '19'
        newer[0]['子掉落1数量区间'] = '20'
        result = audit.compare_tree_revisions(older, newer)
        self.assertEqual(1, result['changedPayloadOrStructure'])
        self.assertEqual(1, result['changedSourceType'])
        self.assertEqual({'older':'30','newer':'20'},
                         result['example51010500']['子掉落1数量区间'])
        self.assertFalse(result['native71Verified'])
    def test_earlier_tree_duplicate_id_rejected(self):
        with self.assertRaisesRegex(ValueError, 'duplicate'):
            audit.compare_tree_revisions([node(1, 102),node(1, 202)],[node(1, 102)])

    def test_selected_roots_direct_diff_and_absence_are_separate(self):
        older = [node(100, 102), node(300, 102), node(51010000, 102)]
        newer = [node(100, 202), node(200, 102), node(51010000, 202)]
        selectors = [{'tag': tag, 'level': 1, 'root': ident}
                     for tag, ident in (('a', 100), ('b', 200), ('c', 300),
                                        ('d', 400), ('e', 51010000))]
        summary = audit.compare_tree_revisions(older, newer, selectors)['selectedRoots']
        self.assertEqual(
            (5, 2, 2, 0, 1, 1, 1),
            tuple(summary[k] for k in (
                'distinctSelectedRoots', 'sharedRoots', 'sharedRootsChanged',
                'sharedRootsUnchanged', 'earlierOnlyRoots', 'laterOnlyRoots',
                'absentInBothTrees')))
        self.assertEqual([400], summary['absentInBothIds'])
        self.assertEqual(2, summary['changedFieldCounts']['子掉落1ID'])
        self.assertEqual('202', summary['examples'][0]['changes'][0]['later'])
        self.assertFalse(summary['native71Verified'])

    def test_selected_roots_reject_ambiguous_source(self):
        selectors = [{'tag': 'a', 'level': 1, 'root': 100}] * 2
        with self.assertRaisesRegex(ValueError, 'Duplicate source'):
            audit.compare_tree_revisions([node(100, 102)], [node(100, 202)], selectors)
        with self.assertRaisesRegex(ValueError, 'Invalid selected root'):
            audit.compare_tree_revisions([node(100, 102)], [node(100, 202)],
                                         [{'tag': 'a', 'level': 1, 'root': 'abc'}])

    def test_bad_tsv_headers(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'a.tsv'
            path.write_text('a\tb\n1\t2\n',encoding='utf8')
            with self.assertRaises(ValueError): audit.tsv(path,audit.EARLY_COLUMNS)

    def test_complete_differences_keep_original_codes(self):
        earlier=[r(1,'same',10,'11007'),r(6,'changed',20,'11007'),r(11,'old-only',30,'11007')]
        later=[r(1,'same',10,'19'),r(6,'changed',40,'19'),r(20,'new-only',50,'19')]
        result=audit.historical_pairs(earlier,later,full=True)
        self.assertEqual((2,1,1,1,1),(
            result['sameLevelAndTag'],result['sameRootAndCount'],
            result['differentRootOrCount'],result['earlierOnlyKeys'],result['laterOnlyKeys']))
        self.assertEqual((20,40),(result['changedRows'][0]['earlierRoot'],
                                  result['changedRows'][0]['laterRoot']))
        self.assertEqual((1,1),(len(result['earlierOnlyRows']),len(result['laterOnlyRows'])))
        self.assertEqual([{'earlierCode':'11007','laterCode':'19','matchedKeys':2}],
                         result['sourceTypeTransitions'])
        self.assertFalse(result['sourceTypeComparable'])

if __name__=='__main__':
    unittest.main()
