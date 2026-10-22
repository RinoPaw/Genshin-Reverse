"""Exact original 7.1 native metadata usage and class slot source controls."""
from __future__ import annotations
import importlib.util
import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
SRC=ROOT/"scripts/probe-7.1-point-factory-metadata-usage-binding.py"
spec=importlib.util.spec_from_file_location("original_point_71_metausage",SRC)
m=importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class OriginalPointFactoryMetadataUsage(unittest.TestCase):
    def test_original_source_class_slot_identities(self):
        rows=m.source_cases(ROOT/m.FACTORY_REPORT,ROOT/m.SLOT_XREF_REPORT)
        self.assertEqual(len(rows),31)
        self.assertEqual(rows[1]["nativeRuntimeClassSlotRva"],"0x57C37B0")
        self.assertEqual(rows[14]["nativeRuntimeClassSlotRva"],"0x57C1970")
        self.assertEqual(m.CASE_INDICES,(1,14))
        self.assertEqual(m.CONTROL_SLOTS["MetadataRegistrationGlobal"],0x5AD52A8)

    def test_source_header_and_metadata_guards(self):
        bad=bytes(m.PROFILE_71.embedded_header_size)
        with self.assertRaisesRegex(ValueError,"original metadata header window"):
            m.decode_original_usage_tables(b"MHY\x00",b"invalid")
        j=m.decode_original_usage_tables(b"MHY\0",bad)
        self.assertFalse(j["originalMetadataUsageDestinationToClassSlotJoinProven"])
        self.assertEqual(len(j["sourceMetadataCandidateProbes"]),2)
        self.assertFalse(any(x["nativeUsageListsConsistent"] for x in
                             j["sourceMetadataCandidateProbes"]))

    def test_source_original_discriminator_no_semantic_promotion(self):
        self.assertEqual(m.PROFILE_71.exe_sha256,
           "08a3086d5f3fe695f01dab61efa42e442006b18e5e475b2520df356f6a073b7d")
        self.assertEqual(m.PROFILE_71.metadata_sha256,
           "05ae04d7a91b91cc880217a56b0b01f3e67f845b06e894216654ec5d160e0da0")



    def test_source_verified_native_usage_table_and_tail_boundary(self):
        report_file=(ROOT/"versions/7.1.0-global/analyses/progression/world/"
                     "7.1-original-point-factory-metadata-usage-table-boundary.json")
        j=json.loads(report_file.read_text(encoding="utf-8"))
        self.assertEqual(j["originalExecutableSha256"],m.PROFILE_71.exe_sha256)
        self.assertEqual(j["originalMetadataSha256"],m.PROFILE_71.metadata_sha256)
        self.assertEqual(j["originalSourceArtifactId"],12415411049)
        s=j["sourceOriginalUsageLayout"]
        self.assertEqual(s["candidateListTableFileOffset"],"0x4DA2AAC")
        self.assertEqual(s["candidatePairTableFileOffset"],"0x3DF52D8")
        self.assertEqual(s["originalCandidateListCount"],311730)
        self.assertEqual(s["originalCandidatePairCount"],788058)
        self.assertEqual(s["originalDecodedNativeKindCounts"],
                         {"0":10,"1":376243,"2":0,"3":84875,"4":1035,
                          "5":137467,"6":185864,"7":2564})
        self.assertTrue(s["originalKind1MaxEqualsOriginalRuntimeTypeCountMinusOne"])
        self.assertEqual(s["sourceKind1AndKind3OutOfBoundSourceIndices"],
                         {"1":0,"3":0})
        self.assertEqual(s["allOriginalKindZeroCandidateIndices"],
                         list(range(788048,788058)))
        self.assertFalse(s["lastTenRecordsAreProvenValidUsageEntries"])
        self.assertFalse(s["exactNativeUsageListCountProvenFromInitializer"])
        self.assertFalse(j["rejectedAlternativeHeaderBodyCandidate"]["consistent"])
        slots=j["staticFactoryClassSlotDataScan"]
        self.assertTrue(slots["all31FactorySlotsChecked"])
        self.assertEqual(slots["all31FactorySlotExactVaQwordHolders"],0)
        self.assertEqual(slots["all31FactorySlotRawRvaDwordCandidates"],0)
        self.assertEqual(slots["all31FactorySlotVaLow32DwordCandidates"],0)
        for value in slots["focusedFactoryCaseAndControlSlots"].values():
            self.assertEqual(value["exactImageVaQwordHolders"],0)
            self.assertEqual(value["alignedRawRvaDwordCandidates"],0)
        for k in ("metadataUsagePairDestinationToRuntimeClassSlotLinked",
                  "originalFactoryCase1ConcreteIL2CPPTypeProven",
                  "originalFactoryCase14ConcreteIL2CPPTypeProven",
                  "originalScenePointResourceLoaderMappedToParser",
                  "chestGadgetCoordinatesOrLevelDecoded"):
            self.assertFalse(j["claims"][k])

if __name__=="__main__":
    unittest.main()
