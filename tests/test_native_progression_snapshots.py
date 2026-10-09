from __future__ import annotations

import json
import unittest
from pathlib import Path


DIR = Path(__file__).resolve().parents[1] / "versions" / "7.1.0-global" / "analyses" / "progression"


class NativeProgressionSnapshotsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.rank = json.loads((DIR / "7.1-adventure-world-level.json").read_text(encoding="utf-8"))
        cls.domain = json.loads((DIR / "7.1-daily-dungeon-schedule.json").read_text(encoding="utf-8"))

    def test_adventure_rank_and_world_level(self) -> None:
        rows = self.rank["adventureRanks"]
        worlds = self.rank["worldLevels"]
        self.assertEqual([r["adventureRank"] for r in rows], list(range(1, 61)))
        self.assertEqual(sum(r["expToNextRank"] for r in rows[:-1]), 1_880_200)
        self.assertIsNone(rows[-1]["expToNextRank"])
        for a, b in zip(rows, rows[1:]):
            self.assertEqual(a["cumulativeExp"] + a["expToNextRank"], b["cumulativeExp"])
        self.assertEqual([(w["worldLevel"], w["unlockAdventureRank"]) for w in worlds],
                         [(1,20),(2,25),(3,30),(4,35),(5,40),(6,45),(7,50),(8,55),(9,58)])
        for w in worlds:
            self.assertEqual(rows[w["unlockAdventureRank"]-1]["unlockWorldLevel"], w["worldLevel"])

    def test_daily_dungeon_weekdays(self) -> None:
        data = self.domain["weekdayDungeonIds"]
        self.assertEqual([x["id"] for x in data], list(range(17, 81)))
        for x in data:
            for key in ("monday","tuesday","wednesday","thursday","friday","saturday","sunday"):
                self.assertTrue(x[key])
                self.assertTrue(all(isinstance(n,int) and n>0 for n in x[key]))
            self.assertEqual(x["monday"],x["thursday"])
            self.assertEqual(x["tuesday"],x["friday"])
            self.assertEqual(x["wednesday"],x["saturday"])

    def test_previews_do_not_imply_drop_quantities(self) -> None:
        data=self.domain["domainEntryPreviews"]
        self.assertEqual(len(data),16)
        self.assertEqual(sum(x["type"]=="DUNGEN_ENTRY_TYPE_AVATAR_TALENT" for x in data),8)
        self.assertEqual(sum(x["type"]=="DUNGEN_ENTRY_TYPE_WEAPON_PROMOTE" for x in data),8)
        for x in data:
            a,b,c,all_ids=x["descriptionCycleRewardList"]
            self.assertEqual(a+b+c,all_ids)


if __name__ == "__main__":
    unittest.main()
