"""Tests for original Global 7.1 factory class-slot method owners."""
from __future__ import annotations
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
SCRIPT=ROOT/"scripts/probe-7.1-point-factory-slot-owner-native-methods.py"
spec=importlib.util.spec_from_file_location("scene_point_slot_owner_71",SCRIPT)
p=importlib.util.module_from_spec(spec)
spec.loader.exec_module(p)


class OriginalFactorySlotOwnerNativeMethods(unittest.TestCase):
    def test_exact_original_source_slots_and_methods(self):
        j=json.loads((ROOT/p.SOURCE_REPORT).read_text(encoding="utf-8"))
        self.assertEqual(j["originalExeSha256"],p.PROFILE_71.exe_sha256)
        self.assertEqual(j["originalMethodMetadataGitBlob"],p.METHODS_BLOB)
        self.assertEqual(p.SLOTS,{1:0x57C37B0,14:0x57C1970})
        self.assertEqual(len(p.TARGET_OWNERS),3)
        for case,owner,index,rva,sites in p.TARGET_OWNERS:
            self.assertEqual({int(x["instructionRva"],16) for x in
              j["nativeClassSlotReferencesByFactoryCase"][str(case)]["exactOriginalCodeReferences"]
              if x["exactOriginalMetadataMethodOwners"][0]["originalTypeName"]==owner
              and x["exactOriginalMetadataMethodOwners"][0]["originalMethodName"]=="JOBDNGNICNC"},set(sites))
        self.assertEqual(sum(len(row[-1]) for row in p.TARGET_OWNERS),4)

    def test_metadata_source_identity_is_required(self):
        with tempfile.TemporaryDirectory() as temp:
            fake=Path(temp)/"methods.csv"
            fake.write_text("bad data",encoding="utf-8")
            with patch.object(p,"git_blob",return_value="wrong"):
                with self.assertRaisesRegex(ValueError,"methods CSV blob drift"):
                    p.validate_sources(fake,ROOT/p.SOURCE_REPORT)


if __name__=="__main__":
    unittest.main()
