"""Source-bound cross-copy chest Lv3 audit regressions; no live server loot."""
from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/audit-7.1-chest-lv3-cross-sources.py"
NATIVE = ROOT / "versions/7.1.0-global/analyses/progression/economy/7.1-chest-native-gadget-prefab-controls.json"
spec = importlib.util.spec_from_file_location("chest_lv3_cross_sources_71", SCRIPT)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class ChestLv3CrossSourceTests(unittest.TestCase):
    def setUp(self):
        self.native = json.loads(NATIVE.read_text(encoding="utf-8"))
        self.audio = []
        for r in self.native["controls"]["nativeNameFields"]:
            suffix = r["nameSuffixLevel"]
            entry = {"AIMCCDKDAKB": r["gadgetIdPreWrapperScalar"]}
            if suffix >= 3:
                entry["DMNAJDGMHDE"] = {3: "Mid", 4: "Hi", 5: "Top"}[suffix]
            self.audio.append(entry)
        self.audio.extend({"AIMCCDKDAKB": 900000 + i} for i in range(36))
        native_ids = [r["gadgetIdPreWrapperScalar"]
                      for r in self.native["controls"]["nativeNameFields"]]
        self.target_ids = native_ids + list(range(910000, 910068))
        self.trigger = {
            "id": 60003, "questId": 6000003, "investigationId": 10001,
            "triggerConfig": {
                "triggerType": "TRIGGER_OPEN_CHEST_WITH_GADGET_ID",
                "paramList": [";".join(map(str, self.target_ids)), "", ""],
            }
        }
        self.quests = [{"id": 900000 + i} for i in range(251)] + [self.trigger]

    def check(self, audio=None, quests=None):
        return module.audit(self.native, self.audio, audio or self.audio,
                            self.quests, quests or self.quests)

    def test_all_native_core_ids_are_in_audio_and_chest_open_trigger(self):
        report = self.check()
        self.assertEqual(report["crossSourceAudioRows"], 56)
        self.assertEqual(report["crossSourceChestOpenTriggerIds"], 88)
        self.assertEqual(report["coreClientDefinitionsCrossChecked"], 20)
        self.assertEqual(report["lv3ClientGadgetIdsInChestOpenTrigger"],
                         [70210031, 70210032, 70210033, 70210034])
        self.assertEqual(report["nativeCoreSuffixAudioClasses"][2]["classes"], {"Mid": 4})
        self.assertEqual(report["nativeCoreSuffixAudioClasses"][3]["classes"], {"Hi": 4})
        self.assertEqual(report["nativeCoreSuffixAudioClasses"][4]["classes"], {"Top": 4})

    def test_a_changed_audio_class_fails(self):
        bad = copy.deepcopy(self.audio)
        next(x for x in bad if x["AIMCCDKDAKB"] == 70210031)["DMNAJDGMHDE"] = "Hi"
        with self.assertRaisesRegex(ValueError, "audio gadget classification differs"):
            self.check(audio=bad)

    def test_missing_lv3_in_handbook_fails(self):
        bad = copy.deepcopy(self.quests)
        target = bad[-1]["triggerConfig"]["paramList"]
        target[0] = target[0].replace("70210032;", "920000;")
        with self.assertRaisesRegex(ValueError, "native Gadget missing"):
            self.check(quests=bad)

    def test_misleading_duplicates_and_non_integer_ids_fail(self):
        bad = copy.deepcopy(self.audio)
        bad[20]["AIMCCDKDAKB"] = 70210031
        with self.assertRaisesRegex(ValueError, "duplicate audio gadget ID"):
            module.audio_index(bad)
        bad = copy.deepcopy(self.quests)
        bad[-1]["triggerConfig"]["paramList"][0] += ";70210031"
        with self.assertRaisesRegex(ValueError, "duplicate ID"):
            module.chest_open_trigger(bad)

    def test_pinned_github_blob_fingerprint_rejects_mutation(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "source.json"
            raw = b'[{"test": 1}]'
            path.write_bytes(raw)
            digest = hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
            self.assertEqual(module.pinned_json(path, digest), [{"test": 1}])
            path.write_bytes(raw + b" ")
            with self.assertRaisesRegex(ValueError, "Git blob mismatch"):
                module.pinned_json(path, digest)


if __name__ == "__main__":
    unittest.main()
