"""Historical chest tag-name coverage is distinct from real 7.1 claim routing."""
from __future__ import annotations

import copy
import hashlib
import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/audit-chest-historical-tag-selector-coverage.py"
spec = importlib.util.spec_from_file_location("historical_chest_tag_selector", SCRIPT)
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)


def scene(tag, gid="70211101", oneoff="True", explore="True"):
    return {"source": "drop_tag", "drop_tag": tag, "gadget_id": gid,
            "chest_drop_id": "0", "is_oneoff": oneoff, "explore_chest": explore}


def selector(tag, threshold=1, root=51010000):
    return {"index": tag, "minLevel": threshold, "dropId": root,
            "sourceType": 19, "type": "战斗"}


class HistoricalChestTagSelectorTests(unittest.TestCase):
    def test_exact_lexical_families_are_exhaustive(self):
        names = {
            "战斗低级蒙德": "combat_or_puzzle",
            "雪山解谜高级蒙德": "combat_or_puzzle",
            "搜刮点解谜通用须弥": "search_point",
            "水上搜刮点璃月": "search_point",
            "一次性搜刮点峭壁璃月": "search_point",
            "摩拉石箱稻妻": "mora_container",
            "灵龛蒙德": "shrine",
            "书页章节1稻妻": "book_page",
            "渊下宫活动低级稻妻": "event",
            "雪山玉髓高级蒙德": "crimson_agate",
        }
        self.assertEqual({name: audit.family(name) for name in names}, names and {
            name: category for name, category in names.items()
        })
        with self.assertRaisesRegex(ValueError, "no prefix family"):
            audit.family("未认证自定义语义")

    def test_matched_selectors_are_names_not_automatic_claims(self):
        scenes = [scene("战斗低级蒙德"), scene("战斗低级蒙德"),
                  scene("搜刮点解谜通用须弥", oneoff="False", explore="False")]
        table = [selector("战斗低级蒙德", 1, 51010000),
                 selector("战斗低级蒙德", 6, 51010100),
                 selector("搜刮点解谜通用须弥", 1, 20000300)]
        result = audit.analyze(scenes, table, enforce_original=False)
        self.assertEqual(result["historicalTaggedInstances"], 3)
        self.assertEqual(result["historicalDistinctTags"], 2)
        self.assertEqual(result["sceneTagNamesWithForkSelector"], 2)
        self.assertEqual(result["matchingForkSelectorRows"], 3)
        self.assertEqual(result["matchingDistinctForkRoots"], 3)
        self.assertEqual(result["families"]["combat_or_puzzle"]["historicalInstances"], 2)
        self.assertEqual(result["families"]["search_point"]["taggedOneoffTrue"], 0)
        self.assertEqual(result["families"]["search_point"]["taggedExploreChestTrue"], 0)
        self.assertNotIn("officialRewardTier", result)

    def test_unmatched_tag_is_reported_and_not_automatically_matched(self):
        scenes = [scene("战斗低级蒙德"), scene("灵龛蒙德")]
        result = audit.analyze(scenes, [selector("战斗低级蒙德")], enforce_original=False)
        self.assertEqual(result["sceneTagNamesWithoutForkSelector"], ["灵龛蒙德"])
        self.assertEqual(result["families"]["shrine"]["matchedSelectorRows"], 0)

    def test_invalid_raw_mapping_fails_closed(self):
        scenes = [scene("战斗低级蒙德")]
        with self.assertRaisesRegex(ValueError, "duplicate ChestDrop minLevel"):
            audit.analyze(scenes, [selector("战斗低级蒙德"),
                                   selector("战斗低级蒙德")], enforce_original=False)
        bad = copy.deepcopy(scenes)
        bad[0]["chest_drop_id"] = "12"
        with self.assertRaisesRegex(ValueError, "missing tag or explicit"):
            audit.analyze(bad, [selector("战斗低级蒙德")], enforce_original=False)
        with self.assertRaisesRegex(ValueError, "name/level/root"):
            audit.analyze(scenes, [selector("战斗低级蒙德", threshold=0)],
                          enforce_original=False)

    def test_checksum_gate_blocks_source_drift(self):
        raw = b"sample source"
        sha = hashlib.sha256(raw).hexdigest()
        git_blob = hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
        audit.sha256_gate(raw, sha, "scene")
        audit.blob_gate(raw, git_blob, "tag table")
        with self.assertRaisesRegex(ValueError, "SHA-256"):
            audit.sha256_gate(raw+b"x", sha, "scene")
        with self.assertRaisesRegex(ValueError, "Git blob"):
            audit.blob_gate(raw+b"x", git_blob, "tag table")


if __name__ == "__main__":
    unittest.main()
