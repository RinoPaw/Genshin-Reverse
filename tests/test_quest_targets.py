from __future__ import annotations

import json
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
MONDSTADT_TARGET = ROOT / "versions" / "7.1.0-global" / "quest-mainline-mondstadt.json"
LIYUE_TARGET = ROOT / "versions" / "7.1.0-global" / "quest-mainline-liyue.json"
INAZUMA_TARGET = ROOT / "versions" / "7.1.0-global" / "quest-mainline-inazuma.json"
SUMERU_TARGET = ROOT / "versions" / "7.1.0-global" / "quest-mainline-sumeru.json"


class MondstadtQuestTargetTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.target = json.loads(MONDSTADT_TARGET.read_text(encoding="utf-8"))

    def test_target_is_exactly_39_unique_main_quests(self) -> None:
        ids = self.target["targetMainQuestIds"]
        self.assertEqual(39, len(ids))
        self.assertEqual(39, len(set(ids)))

    def test_groups_exactly_partition_target(self) -> None:
        grouped = [
            main_id
            for group in self.target["groups"]
            for main_id in group["mainQuestIds"]
        ]
        self.assertEqual(
            set(self.target["targetMainQuestIds"]),
            set(grouped),
        )
        self.assertEqual(len(grouped), len(set(grouped)))

    def test_official_prologue_chapter_boundaries(self) -> None:
        self.assertEqual([1001, 1002, 1003], self.target["officialChapterIds"])
        self.assertEqual(
            [
                (1001, 36301, 31101),
                (1002, 37004, 38406),
                (1003, 39705, 39604),
            ],
            [
                (
                    row["chapterId"],
                    row["beginSubQuestId"],
                    row["endSubQuestId"],
                )
                for row in self.target["chapterBoundaries"]
            ],
        )

    def test_known_non_linear_and_bridge_membership(self) -> None:
        self.assertIn([306, 307, 308], self.target["parallelSets"])
        self.assertIn([380, 381, 382], self.target["parallelSets"])
        self.assertIn(20101, self.target["targetMainQuestIds"])
        self.assertNotIn(361, self.target["targetMainQuestIds"])


class LiyueQuestTargetTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.target = json.loads(LIYUE_TARGET.read_text(encoding="utf-8"))

    def test_target_is_exactly_25_unique_main_quests(self) -> None:
        ids = self.target["targetMainQuestIds"]
        self.assertEqual(25, len(ids))
        self.assertEqual(25, len(set(ids)))

    def test_groups_exactly_partition_target(self) -> None:
        grouped = [
            main_id
            for group in self.target["groups"]
            for main_id in group["mainQuestIds"]
        ]
        self.assertEqual(set(self.target["targetMainQuestIds"]), set(grouped))
        self.assertEqual(len(grouped), len(set(grouped)))

    def test_official_chapter_i_boundaries(self) -> None:
        self.assertEqual([1101, 1102, 1103, 1104], self.target["officialChapterIds"])
        self.assertEqual(
            [
                (1101, 100002, 101801),
                (1102, 101003, 101609),
                (1103, 102001, 102510),
                (1104, 800002, 800311),
            ],
            [
                (
                    row["chapterId"],
                    row["beginSubQuestId"],
                    row["endSubQuestId"],
                )
                for row in self.target["chapterBoundaries"]
            ],
        )

    def test_known_non_linear_and_hidden_membership(self) -> None:
        self.assertIn([1008, 1009, 1003], self.target["parallelSets"])
        self.assertIn(1001, self.target["hiddenSupportMainQuestIds"])
        self.assertIn(1004, self.target["hiddenSupportMainQuestIds"])
        self.assertIn(1013, self.target["targetMainQuestIds"])


class InazumaQuestTargetTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.target = json.loads(INAZUMA_TARGET.read_text(encoding="utf-8"))

    def test_target_is_exactly_22_unique_main_quests(self) -> None:
        ids = self.target["targetMainQuestIds"]
        self.assertEqual(22, len(ids))
        self.assertEqual(22, len(set(ids)))

    def test_groups_exactly_partition_target(self) -> None:
        grouped = [
            main_id
            for group in self.target["groups"]
            for main_id in group["mainQuestIds"]
        ]
        self.assertEqual(set(self.target["targetMainQuestIds"]), set(grouped))
        self.assertEqual(len(grouped), len(set(grouped)))

    def test_official_chapter_ii_boundaries(self) -> None:
        self.assertEqual([1201, 1202, 1203, 1204], self.target["officialChapterIds"])
        self.assertEqual(
            [
                (1201, 200003, 200212),
                (1202, 201102, 200711),
                (1203, 200805, 200908),
                (1204, 201003, 202102),
            ],
            [
                (
                    row["chapterId"],
                    row["beginSubQuestId"],
                    row["endSubQuestId"],
                )
                for row in self.target["chapterBoundaries"]
            ],
        )

    def test_cross_number_chain_membership(self) -> None:
        ids = self.target["targetMainQuestIds"]
        self.assertIn(2011, ids)
        self.assertIn(2013, ids)
        self.assertIn(2003, ids)
        self.assertIn(2010, ids)
        self.assertIn(2021, ids)


class SumeruQuestTargetTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.target = json.loads(SUMERU_TARGET.read_text(encoding="utf-8"))

    def test_target_is_exactly_29_unique_main_quests(self) -> None:
        ids = self.target["targetMainQuestIds"]
        self.assertEqual(29, len(ids))
        self.assertEqual(29, len(set(ids)))

    def test_groups_exactly_partition_target(self) -> None:
        grouped = [
            main_id
            for group in self.target["groups"]
            for main_id in group["mainQuestIds"]
        ]
        self.assertEqual(set(self.target["targetMainQuestIds"]), set(grouped))
        self.assertEqual(len(grouped), len(set(grouped)))

    def test_official_chapter_iii_boundaries(self) -> None:
        self.assertEqual([1301, 1302, 1303, 1304, 1305, 1306], self.target["officialChapterIds"])
        self.assertEqual(
            [
                (1301, 300002, 300612),
                (1302, 300714, 301210),
                (1303, 301617, 301811),
                (1304, 301906, 302110),
                (1305, 302413, 302617),
            ],
            [
                (
                    row["chapterId"],
                    row["beginSubQuestId"],
                    row["endSubQuestId"],
                )
                for row in self.target["chapterBoundaries"]
            ],
        )

    def test_special_and_hidden_support_membership(self) -> None:
        ids = self.target["targetMainQuestIds"]
        self.assertIn(3013, ids)
        self.assertEqual([3013], self.target["specialChapterMainQuestIds"])
        for main_id in (3015, 3023, 3027):
            self.assertIn(main_id, ids)
            self.assertIn(main_id, self.target["hiddenSupportMainQuestIds"])


if __name__ == "__main__":
    unittest.main()
