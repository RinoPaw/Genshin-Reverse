"""Separate historical Lua chest candidates from current fork claim routing."""
from __future__ import annotations

import copy
import hashlib
import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/audit-chest-historical-claim-routing.py"
spec = importlib.util.spec_from_file_location("chest_historical_routing", SCRIPT)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


def sample(kind: str, i: int) -> dict:
    return {
        "scene": "3", "file": f"Scripts/Scene/3/scene3_group12345{i}.lua",
        "config_id": str(100 + i), "gadget_id": "70211001",
        "source": kind, "drop_tag": "战斗低级蒙德" if kind == "drop_tag" else "",
        "chest_drop_id": "1000100" if kind == "explicit_id" else "0",
        "is_oneoff": "False" if kind == "no_metadata" else "True",
        "persistent": "True", "explore_chest": "False",
    }


def java_fixture() -> dict:
    return {
        "GadgetChest": """
            private void grantOrdinaryChestLoot(Player player) {
                if (meta.chest_drop_id > 0) {
                    if ((gadget.getScene().getSceneType() == SceneType.SCENE_DUNGEON
                            || gadget.getGroupId() == 0
                            || dropSystem.hasQuestItemDrop(meta.chest_drop_id))
                        && dropSystem.handleChestDrop(
                            meta.chest_drop_id, Math.max(1, meta.drop_count), gadget)) {
                        return;
                    }
                }
                WorldChestLootHelper.grant(player, gadget);
            }
            protected boolean grantBossChestFallback(Player player, SceneGadget meta) {
            """,
        "DropSystem": """
            public boolean handleChestDrop(String dropTag, int level, GameEntity bornFrom) {
                int dropId = queryDropData(dropTag, level, chestReward);
                return true;
            }
            """,
        "WorldChestLootHelper": """
            public static Tier resolveTier() {
                if (containsLv(string, 5) || containsLv(string, 4) ||
                    containsLv(string, 3) || containsLv(string, 2) ||
                    containsLv(string, 1)) return COMMON;
                if (sceneGadget.drop_tag != null) return COMMON;
            }
            public static enum Tier {
                COMMON(66, 20, 3, 1000, 2, 2, 1, 0),
                EXQUISITE(166, 25, 5, 1500, 2, 3, 2, 1),
                PRECIOUS(366, 30, 8, 2000, 3, 3, 3, 2),
                LUXURIOUS(566, 30, 10, 2500, 4, 2, 4, 3);
            }
            """,
    }


class HistoricalChestClaimRoutingTests(unittest.TestCase):
    def test_distinct_source_provenance_classes_and_scene_counts(self):
        rows = [sample(kind, i) for i, kind in
                enumerate(("drop_tag", "explicit_id", "no_metadata"))]
        report = mod.make_report(rows, {}, java_fixture(), full=False)
        dist = report["historicalCandidateDistribution"]
        self.assertEqual(dist["sourceCounts"],
                         {"drop_tag": 1, "explicit_id": 1, "no_metadata": 1})
        self.assertEqual(dist["scene3Counts"]["explicit_id"], 1)
        self.assertEqual(dist["distinctHistoricalDropTags"], 1)
        self.assertEqual(dist["distinctHistoricalExplicitRoots"], 1)
        self.assertEqual(dist["oneoffCounts"]["no_metadata"]["False"], 1)
        self.assertFalse(report["forkImplementation"]["ordinaryClaimDirectlyCallsTagTable"])
        self.assertEqual(report["forkImplementation"]["hardcodedFallbackPrimogems"]["COMMON"], 66)

    def test_wrong_classification_or_duplicate_is_rejected(self):
        rows = [sample("drop_tag", 0), sample("explicit_id", 1)]
        bad = copy.deepcopy(rows)
        bad[0]["chest_drop_id"] = "10"
        with self.assertRaisesRegex(ValueError, "inconsistent"):
            mod.checked_scene(bad, {}, full=False)
        bad = copy.deepcopy(rows)
        bad[1]["file"] = bad[0]["file"]
        bad[1]["config_id"] = bad[0]["config_id"]
        with self.assertRaisesRegex(ValueError, "duplicate"):
            mod.checked_scene(bad, {}, full=False)

    def test_claim_path_mutation_is_detected(self):
        code = java_fixture()
        altered = copy.deepcopy(code)
        altered["GadgetChest"] = altered["GadgetChest"].replace(
            "WorldChestLootHelper.grant(player, gadget)", "other.grant(player, gadget)")
        with self.assertRaisesRegex(ValueError, "claim path changed"):
            mod.checked_java(altered)
        altered = copy.deepcopy(code)
        altered["GadgetChest"] = altered["GadgetChest"].replace(
            "WorldChestLootHelper.grant", "dropSystem.handleChestDrop(meta.drop_tag); WorldChestLootHelper.grant")
        with self.assertRaisesRegex(ValueError, "claim path changed"):
            mod.checked_java(altered)
        altered = copy.deepcopy(code)
        altered["WorldChestLootHelper"] = altered["WorldChestLootHelper"].replace(
            "COMMON(66,", "COMMON(2,")
        with self.assertRaisesRegex(ValueError, "Primogem quantities changed"):
            mod.checked_java(altered)

    def test_exact_source_fingerprints_reject_mutations(self):
        original = b"original source byte evidence"
        sha = hashlib.sha256(original).hexdigest()
        blob = hashlib.sha1(b"blob " + str(len(original)).encode() + b"\0" + original).hexdigest()
        mod.require_sha256(original, sha, "source")
        mod.require_blob(original, blob, "source")
        with self.assertRaisesRegex(ValueError, "SHA-256"):
            mod.require_sha256(original + b" ", sha, "source")
        with self.assertRaisesRegex(ValueError, "Git blob"):
            mod.require_blob(original + b" ", blob, "source")


if __name__ == "__main__":
    unittest.main()
