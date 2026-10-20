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
    def test_bad_tsv_headers(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'a.tsv'
            path.write_text('a\tb\n1\t2\n',encoding='utf8')
            with self.assertRaises(ValueError): audit.tsv(path,audit.EARLY_COLUMNS)

if __name__=='__main__':
    unittest.main()
