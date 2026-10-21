"""Source-fingerprint and scope regression for original 7.1 scene row reader shortlist."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/audit-7.1-scene-reader-candidate-intersection.py"
spec = importlib.util.spec_from_file_location("scene_reader_intersection_71", SCRIPT)
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


class TestOriginalSceneReaderIntersection71(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report = json.loads(probe.OUTPUT.read_text(encoding="utf-8"))

    def test_source_bound_intersection_exactly_preserved(self):
        d = self.report
        self.assertEqual(d["originalClientExeSha256"], probe.PROFILE_71.exe_sha256)
        self.assertEqual(d["inputArtifacts"]["nativeKeyWriterFullReportSha256"],
                         probe.KEY_WRITERS_SHA256)
        self.assertEqual(d["inputArtifacts"]["metadataNeighborFullReportSha256"],
                         probe.NEIGHBOR_SHA256)
        tag = d["tables"]["SceneTag"]
        scene = d["tables"]["SceneExcel"]
        self.assertEqual((tag["keyWriterMethods"], scene["keyWriterMethods"]), (485, 168))
        self.assertEqual((tag["metadataNeighborReaderMethods"],
                          scene["metadataNeighborReaderMethods"]), (9, 10))
        self.assertEqual((tag["intersectionCount"], scene["intersectionCount"]), (2, 0))
        self.assertEqual((tag["singleNativeWrapperCallAndOnlyMatchingStore"],
                          scene["singleNativeWrapperCallAndOnlyMatchingStore"]), (69, 13))
        self.assertEqual(tag["verifiedDirectOffsetFourFalsificationsWithinKeyWriterSet"],
                         [696555])
        self.assertEqual(tag["unfalsifiedKeyWriterCandidateCount"], 484)
        self.assertEqual(scene["unfalsifiedKeyWriterCandidateCount"], 168)
        self.assertEqual([x["methodIndex"] for x in tag["intersectionCandidates"]],
                         [696555, 696558])
        self.assertEqual([x["falsifiedAsDirectOffsetFourReader"]
                          for x in tag["intersectionCandidates"]], [True, False])
        self.assertIn("VTABLE_UNRESOLVED", d["status"])
        self.assertTrue(any("remains unresolved" in x for x in d["limitations"]))

    def test_bounded_synthetic_selection_keeps_unproven_neighbors(self):
        rows = []
        for i in range(485):
            rows.append({
                "methodIndex": i+1,
                "keyWriteOffsetsAfterWrapper": [0x28],
                "nativeCallSites": [{}],
            })
        other = [{
            "methodIndex": i+1000,
            "keyWriteOffsetsAfterWrapper": [0x50],
            "nativeCallSites": [{}],
        } for i in range(168)]
        fake = {
            "exeSha256": probe.PROFILE_71.exe_sha256,
            "keyOffsetCandidates": {
                "SceneTag": {"memoryOffset": "0x28", "methods": rows},
                "SceneExcel": {"memoryOffset": "0x50", "methods": other},
            },
        }
        neighbors = {"tables": {
            "SceneTag": {"sameMethodAndInputSignatureCandidates": [{
                "methodIndex": 1, "typeName": "SyntheticTag",
                "typeIndex": 84295, "rva": "0xABC",
            }]},
            "SceneExcel": {"sameMethodAndInputSignatureCandidates": []},
        }}
        result = probe.intersection(fake, neighbors)
        self.assertEqual(result["tables"]["SceneTag"]["intersectionCount"], 1)
        self.assertFalse(result["tables"]["SceneTag"]["intersectionCandidates"][0]
                         ["falsifiedAsDirectOffsetFourReader"])
        self.assertEqual(result["tables"]["SceneExcel"]["intersectionCount"], 0)

    def test_source_artifact_hash_gate(self):
        with self.assertRaisesRegex(ValueError, "key-writer artifact SHA-256"):
            probe.run(b"random", b"random")
        self.assertEqual(probe.EXPECTED_WRITER_METHODS, {"SceneTag": 485, "SceneExcel": 168})


if __name__ == "__main__":
    unittest.main()
