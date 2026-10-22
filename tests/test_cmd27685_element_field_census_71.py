"""Tests for strict original 7.1 scene-entity element metadata boundaries."""
import importlib.util
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase, main
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "native_71_element_census",
    ROOT / "scripts/probe-7.1-cmd27685-element-field-census.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class ElementSourceCensusTests(TestCase):
    def test_source_anchors_and_semantics_do_not_promote(self):
        self.assertEqual(module.TYPES[85506], ("KFOLLNPEMHH", 27, 17))
        self.assertEqual(module.TYPES[65670], ("KIIKIELOHOG", 4, 14))
        self.assertEqual(module.NATIVE_READER_RVA, 0xB43A2A0)
        self.assertEqual(module.KNOWN_TAG_CMP_RVA, 0xB43A328)
        self.assertEqual(module.KNOWN_TAG_CMP, ("cmp", "eax, 0x10"))
        self.assertEqual(module.KNOWN_FIELD_WRITE,
                         ("mov", "dword ptr [r12 + 0x98], eax"))

    def test_synthetic_original_member_census(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            fields = root / "fields.csv"
            methods = root / "methods.csv"
            fields.write_text(
                "type_definition_index,type_name,field_index,field_name,field_type,field_type_index\n"
                + "".join(
                    f"{index},{name},{100000+j},F{j},uint32,{j}\n"
                    for index, (name, nfields, _) in module.TYPES.items()
                    for j in range(nfields)
                ), encoding="utf-8")
            methods.write_text(
                "type_definition_index,type_name,method_index,method_name,rva,parameter_types\n"
                + "".join(
                    f"{index},{name},{705939 if index==85506 and j==0 else 6000+index+j},"
                    f"{'NLGBJEEJDLG' if index==85506 and j==0 else 'other'},"
                    f"{'0xB43A2A0' if index==85506 and j==0 else '0xB43D570'},[]\n"
                    for index, (name, _, count) in module.TYPES.items()
                    for j in range(count or 1)
                ), encoding="utf-8")
            with patch.object(module, "FIELDS_GIT_BLOB", "mocked"), patch.object(
                module, "METHODS_GIT_BLOB", "mocked"
            ), patch.object(module, "git_blob", return_value="mocked"):
                got = module.recover_members(methods, fields)
            self.assertEqual(len(got[85506]["fields"]), 27)
            self.assertEqual(len(got[85506]["methods"]), 17)
            self.assertEqual(len(got[65670]["fields"]), 4)
            self.assertEqual(len(got[51277]["fields"]), 1)

    def test_reject_member_drift(self):
        with TemporaryDirectory() as tmp:
            fields = Path(tmp) / "fields.csv"
            methods = Path(tmp) / "methods.csv"
            fields.write_text("type_definition_index,type_name,field_index,field_name,field_type,field_type_index\n"
                              "85506,KFOLLNPEMHH,0,a,int32,1\n", encoding="utf-8")
            methods.write_text("type_definition_index,type_name,method_index,method_name,rva\n",
                               encoding="utf-8")
            with patch.object(module, "FIELDS_GIT_BLOB", "mocked"), patch.object(
                module, "METHODS_GIT_BLOB", "mocked"
            ), patch.object(module, "git_blob", return_value="mocked"):
                with self.assertRaisesRegex(ValueError, "field count drift"):
                    module.recover_members(methods, fields)


    def test_source_authenticated_native_metadata_report(self):
        import json
        report_path = ROOT / "versions/7.1.0-global/analyses/progression/economy/7.1-original-cmd27685-element-metadata-reader-census.json"
        report = json.loads(report_path.read_text(encoding="utf-8"))
        self.assertEqual(report["originalExeSha256"], module.PROFILE_71.exe_sha256)
        self.assertEqual(report["canonicalMethodsGitBlob"], module.METHODS_GIT_BLOB)
        self.assertEqual(report["canonicalFieldsGitBlob"], module.FIELDS_GIT_BLOB)
        self.assertEqual(report["elementTypeDefinitionIndex"], 85506)
        self.assertEqual(len(report["metadata"]["elementFields"]), 27)
        self.assertEqual(len(report["metadata"]["elementMethods"]), 17)
        self.assertEqual(len(report["metadata"]["messageFields"]), 4)
        self.assertEqual(len(report["metadata"]["containerFields"]), 1)
        self.assertEqual(report["originalNativeReader"]["readerWindowSha256"],
                         "b9daf495a99150725dcadff1d6ba717e9a6edf1461b764ebd13b7f3905eb0c9e")
        self.assertEqual(report["originalNativeReader"]["readerWindowBytes"], module.NATIVE_READER_SIZE)
        self.assertEqual(report["originalNativeReader"]["verifiedNativeField2"]["fieldNumber"], 2)
        self.assertEqual(report["originalNativeReader"]["verifiedNativeField2"]["wireType"], 0)
        self.assertEqual(len(report["originalNativeReader"]["scalarComparisonCandidates"]), 30)
        self.assertEqual(len(report["originalNativeReader"]["distinctPotentialTagNumbers"]), 23)
        self.assertEqual(report["originalNativeReader"]["confirmedWireFieldNumbers"], [2])
        self.assertTrue(report["originalNativeReader"]["otherPotentialTagNumbersRemainUnverified"])
        self.assertFalse(report["originalPacketDirectionProven"])
        self.assertFalse(report["originalSceneChestPlacementSourceProven"])
        self.assertFalse(report["originalSceneLevelProven"])
        self.assertEqual(report["evidence"]["artifactId"], 12402756811)


if __name__ == "__main__":
    main()
