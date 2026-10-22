"""Provenance and regression gates for pinned AstaPS chest level data flow."""
from importlib import util
import hashlib
import json
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[1]
modspec=util.spec_from_file_location("chest_level_ownership",ROOT/"scripts/audit-7.1-chest-level-source-ownership.py")
module=util.module_from_spec(modspec)
modspec.loader.exec_module(module)


class ChestLevelOwnershipTests(unittest.TestCase):
    def test_git_blob_identity(self):
        raw=b"hello"
        expected=hashlib.sha1(b"blob 5"+bytes([0])+raw).hexdigest()
        self.assertEqual(module.git_blob_sha1(raw),expected)
        self.assertEqual(module.SOURCES["rewardExperiment"]["files"]["WorldChestLootHelper"],
                         "bae74426492f8eacea73298185dba63a52790eea")

    def test_missing_pinned_source_is_rejected(self):
        with self.assertRaisesRegex(ValueError,"missing or extra"):
            module.check_source("upstreamMain",{"SceneObject":b"public int level;"})

    def test_modified_blob_is_rejected_before_semantic_inference(self):
        files={k:b"changed" for k in module.SOURCES["upstreamMain"]["files"]}
        with self.assertRaisesRegex(ValueError,"Git blob mismatch"):
            module.check_source("upstreamMain",files)

    def test_published_ownership_conclusion_does_not_claim_original_level(self):
        report=json.loads((ROOT/"versions/7.1.0-global/analyses/progression/economy/7.1-chest-level-source-ownership.json").read_text(encoding="utf-8"))
        self.assertEqual(report["originalClientExeSha256"],module.ORIGINAL_CLIENT_EXE_SHA256)
        self.assertEqual(report["evidenceKind"],"FORK_SOURCE_NOT_ORIGINAL_CLIENT")
        self.assertEqual({k:v["commit"] for k,v in report["snapshots"].items()},
                         {k:v["commit"] for k,v in module.SOURCES.items()})
        for snapshot,ref in module.SOURCES.items():
            self.assertEqual({k:v["sha1"] for k,v in report["snapshots"][snapshot]["fileGitBlobs"].items()},ref["files"])
            self.assertTrue(all(report["snapshots"][snapshot]["verifiedAnchors"].values()))
        boundary=report["boundaries"]
        self.assertFalse(boundary["originalClientSceneInstanceLevelFieldProven"])
        self.assertFalse(boundary["networkLevelEqualsSceneScriptLevelProven"])
        self.assertFalse(boundary["originalOfficialServerChestLevelOwnershipProven"])
        self.assertTrue(boundary["forkLootLevelZeroCanBePassedWhenMetadataExists"])


if __name__=="__main__":
    unittest.main()
