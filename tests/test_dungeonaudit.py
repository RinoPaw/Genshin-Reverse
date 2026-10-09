import unittest
from fractions import Fraction
from genshinre.dungeonaudit import (
    analyze_group, audit_dungeon_rewards, runtime_preview_items, selection,
)


def dungeon(i, subtype='DUNGEON_SUB_TALENT', **kw):
    return {'id': i, 'type': 'DUNGEON_DAILY_FIGHT', 'subType': subtype,
            'passRewardPreviewID': i, **kw}


class DungeonRewardAuditTests(unittest.TestCase):
    def test_java_weight_fallback_and_errors(self):
        probabilities, issues = selection(3, [80, 20], 'COUNT')
        self.assertEqual(probabilities, [Fraction(1, 3)]*3)
        self.assertEqual(issues, ['COUNT_WEIGHTS_IGNORED'])
        self.assertEqual(selection(2, [0, 0], 'COUNT')[1], ['COUNT_INVALID_WEIGHTS'])
        self.assertEqual(selection(2, [0, 7], 'COUNT')[0], [0, 1])

    def test_count_endpoints_and_bonus(self):
        # Sparse counts are endpoint syntax in this implementation, not two candidates.
        group = analyze_group({'counts': [2, 4], 'items': [104301]}, True)
        self.assertEqual(group['baseCountMean'], 3)
        self.assertEqual(group['soloOriginalResinExpectedByItem'][0]
                         ['postBoostMeanIfMaterialOrItemDataMissing'], 9)
        self.assertEqual(group['issues'], [])
        group = analyze_group({'counts': [100], 'items': [102]}, True)
        self.assertEqual(group['soloOriginalResinExpectedByItem'][0]
                         ['postBoostMeanIfMaterialOrItemDataMissing'], 100)

    def test_empty_items_failure_vs_zero_roll(self):
        issue = 'EMPTY_ITEMS_GUARANTEED_DRAW_EXCEPTION'
        self.assertIn(issue, analyze_group({'counts': [2, 3], 'items': []}, False)['issues'])
        self.assertNotIn(issue, analyze_group({'counts': [0], 'items': []}, False)['issues'])
        self.assertNotIn(issue, analyze_group({'counts': [0, 1], 'items': []}, False)['issues'])

    def test_preview_onload_filter_and_conversion(self):
        self.assertEqual(runtime_preview_items([
            {}, {'id': 1001}, {'id': 1002, 'count': ''},
            {'id': 1003, 'count': '2.2'}, {'id': 1004, 'count': '1;4'},
            {'id': 1005, 'count': '0.33'},
        ]), [{'itemId': 1003, 'count': 3}, {'itemId': 1004, 'count': 4},
             {'itemId': 1005, 'count': 1}])

    def test_source_root_is_not_java_root(self):
        result = audit_dungeon_rewards([dungeon(1, IAOMJCLOIEL=10)],
            [{'id': 1, 'previewItems': [{'id': 102, 'count': '100'}, {'id': 104301}]}], [], {10})
        row = result['dungeons'][0]
        self.assertEqual(row['configuredPrimaryRoute'], 'PREVIEW_FALLBACK')
        self.assertEqual(row['javaStatueDrop'], 0)
        self.assertIn('PREVIEW_FALLBACK_OMITS_DOMAIN_MATERIALS', row['issues'])
        self.assertEqual(row['previewFallbackSoloRewardsBeforeBonus'], [{'itemId': 102, 'count': 100}])
        self.assertFalse(row['condensedResinFallbackDoublesRewards'])

    def test_material_domain_items_in_reliquary_proxy(self):
        result = audit_dungeon_rewards([
            dungeon(1, 'DUNGEON_SUB_WEAPON'), dungeon(2, 'DUNGEON_SUB_RELIQUARY')],
            [{'id': 1, 'previewItems': [{'id': 114001, 'count': '2'}]},
             {'id': 2, 'previewItems': [{'id': 202, 'count': '100'}]}],
            [{'dungeonId': 2, 'drops': [{'counts': [1], 'items': [114001]}]}], set())
        row = result['dungeons'][1]
        self.assertEqual(row['unexpectedMaterialItemIds'], [114001])
        self.assertIn('RELIQUARY_PROXY_CONTAINS_MATERIAL_DOMAIN_ITEMS', row['issues'])

    def test_initial_gate_precedes_proxy(self):
        result = audit_dungeon_rewards([dungeon(1)], [],
            [{'dungeonId': 1, 'drops': [{'counts': [1], 'items': [102]}]}], set())
        self.assertEqual(result['dungeons'][0]['configuredPrimaryRoute'], 'INITIAL_GATE_REJECT')

    def test_unaliased_statue_root_and_empty_loader_row(self):
        result = audit_dungeon_rewards([dungeon(1, statueDrop=10)], [],
            [{'dungeonId': 1, 'drops': []}], {10})
        self.assertEqual(result['dungeons'][0]['configuredPrimaryRoute'], 'RESOURCE_TABLE_CANDIDATE')

    def test_duplicate_inputs_rejected(self):
        with self.assertRaisesRegex(ValueError, 'duplicate'):
            audit_dungeon_rewards([dungeon(1), dungeon(1)], [], [], set())


class DungeonAuditSnapshotTests(unittest.TestCase):
    def test_published_findings_and_provenance(self):
        import json
        from pathlib import Path
        from genshinre.dungeonaudit import git_blob
        root = Path(__file__).resolve().parents[1]
        snapshot = json.loads((root/'versions/7.1.0-global/analyses/progression/economy/7.1-asta-dungeon-reward-audit.json').read_text())
        rows = snapshot['dungeons']
        self.assertEqual(len(rows), 373)
        def ids(issue):
            return {r['dungeonId'] for r in rows if issue in r['issues']}
        self.assertEqual(ids('EMPTY_ITEMS_GUARANTEED_DRAW_EXCEPTION'),
                         {5000, 5001, 5002, 5008, 5100, 5101})
        self.assertEqual(ids('RELIQUARY_PROXY_CONTAINS_MATERIAL_DOMAIN_ITEMS'),
                         {4480, 4484, 4665, 4683, 4687, 5018, 5022, 5050, 5060, 5064})
        self.assertEqual(len(ids('PREVIEW_FALLBACK_OMITS_DOMAIN_MATERIALS')), 16)
        models = snapshot['proxyGroupModels']
        self.assertTrue(all(k in models for r in rows for k in r.get('proxyGroupModelIds', [])))
        for path, expected in snapshot['generator']['toolGitBlobShas'].items():
            self.assertEqual(git_blob((root/path).read_bytes()), expected)


if __name__ == '__main__':
    unittest.main()
