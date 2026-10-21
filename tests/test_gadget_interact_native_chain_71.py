"""Original 7.1 GadgetInteract native call-chain source and boundary regressions."""
from importlib import util
from pathlib import Path
import copy
import json
import unittest

ROOT=Path(__file__).resolve().parents[1]
p=ROOT/"scripts/audit-7.1-gadget-interact-native-chain.py"
spec=util.spec_from_file_location("interact_native_chain_71",p)
m=util.module_from_spec(spec)
spec.loader.exec_module(m)


class InteractChain(unittest.TestCase):
    def test_published_original_chain_is_strictly_candidate(self):
        row=json.loads((ROOT/"versions/7.1.0-global/analyses/progression/economy/7.1-gadget-interact-native-first-branch-chain.json").read_text(encoding="utf-8"))
        self.assertEqual(row["originalExeSha256"],m.PROFILE_71.exe_sha256)
        self.assertEqual(row["exactOriginalDerivedArtifactSha256"],m.EXPECTED_SHA)
        self.assertEqual(row["checkedNativeInstructionAnchors"],
            {k:len(v) for k,v in m.NATIVE_ANCHORS.items()})
        self.assertEqual(row["sourceFirstRecord"]["firstRowRawMaskByte"],"0x36")
        self.assertEqual(row["sourceFirstRecord"]["preWrapperKeyIfUninterrupted"],938583754)
        self.assertFalse(row["sourceFirstRecord"]["cursor9IsConfirmedRowEnd"])
        self.assertFalse(row["nativeConditionalEdges"]["rawMaskBit0NestedReader"]["takenForActualFirstRawMask0x36"])

    def test_original_anchored_disassembly_must_match(self):
        name="conditional"
        entries=[{"rva":p,"mnemonic":v[0],"op_str":v[1],"bytes":v[2]}
                 for p,v in m.NATIVE_ANCHORS[name].items()]
        obj={"exe_sha256":m.PROFILE_71.exe_sha256,
             "start_rva":m.ORIGINAL_METHOD_RVAS[name],"instructions":entries}
        self.assertEqual(m.verify_native_anchors(obj,name),len(entries))
        bad=copy.deepcopy(obj)
        bad["instructions"][0]["bytes"]="90"
        with self.assertRaisesRegex(ValueError,"instruction mismatch"):
            m.verify_native_anchors(bad,name)


if __name__=="__main__":unittest.main()
