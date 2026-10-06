from __future__ import annotations

import hashlib
from pathlib import Path
import unittest

from genshinre.questbin import decode_main_quest


FIXTURE = Path(__file__).with_name("fixtures") / "quest351.bin"


class NativeQuestBinTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.payload = FIXTURE.read_bytes()
        cls.decoded = decode_main_quest(cls.payload)

    def test_quest351_fixture_identity_and_full_consumption(self) -> None:
        self.assertEqual(920, len(self.payload))
        self.assertEqual(
            "285d825bedce0611494d114687bc7981789b0ef6d0a724f5abfecf423b6335de",
            hashlib.sha256(self.payload).hexdigest(),
        )
        self.assertEqual(920, self.decoded.consumed)
        self.assertTrue(self.decoded.fully_consumed)

    def test_quest351_native_row_framing(self) -> None:
        self.assertEqual(
            [
                (35100, 0x03F, 0x0A9),
                (35101, 0x0A9, 0x136),
                (35102, 0x136, 0x196),
                (35103, 0x196, 0x1F8),
                (35104, 0x1F8, 0x24F),
                (35105, 0x24F, 0x2B2),
                (35106, 0x2B2, 0x327),
                (35107, 0x327, 0x384),
            ],
            list(self.decoded.row_boundaries),
        )

    def test_quest351_native_finish_fail_semantics(self) -> None:
        rows = {row["subId"]: row for row in self.decoded.data["quests"]}

        self.assertEqual(
            [{"type": 4, "param": [35100, 0]}, {"type": 6, "param": [1053, 0]}],
            _core_content(rows[35100]["finishCond"]),
        )
        self.assertEqual(
            [{"type": 21, "param": [0, 0]}],
            _core_content(rows[35101]["failCond"]),
        )
        self.assertEqual([{"type": 14, "param": ["35100"]}], rows[35101]["failExec"])
        self.assertEqual(
            [{"type": 6, "param": [1100, 0]}],
            _core_content(rows[35101]["finishCond"]),
        )
        self.assertEqual(
            [{"type": 6, "param": [1017, 0]}],
            _core_content(rows[35102]["finishCond"]),
        )
        self.assertEqual(
            [{"type": 6, "param": [1016, 0]}],
            _core_content(rows[35103]["finishCond"]),
        )
        self.assertEqual(
            [{"type": 4, "param": [35104, 0]}],
            _core_content(rows[35104]["finishCond"]),
        )
        self.assertEqual(
            [{"type": 6, "param": [1016, 0]}],
            _core_content(rows[35105]["finishCond"]),
        )
        self.assertEqual(
            [{"type": 17, "param": ["3", "1720"]}],
            rows[35106]["finishExec"],
        )
        self.assertEqual(
            [{"type": 23, "param": [3, 6]}],
            _core_content(rows[35106]["finishCond"]),
        )
        self.assertEqual(
            [{"type": 19, "param": ["3", "133003429,1"]}],
            rows[35107]["finishExec"],
        )
        self.assertEqual(
            [{"type": 6, "param": [1101, 0]}],
            _core_content(rows[35107]["finishCond"]),
        )

    def test_quest351_outer_tail(self) -> None:
        data = self.decoded.data
        self.assertEqual(351, data["mainId"])
        self.assertEqual([14457059026087496718], data["unknown_bit_49"])
        self.assertEqual(1001, data["resId"])
        self.assertEqual(1008400655, data["unknown_bit_40"])


def _core_content(items: list[dict[str, object]]) -> list[dict[str, object]]:
    return [{"type": item["type"], "param": item["param"]} for item in items]


if __name__ == "__main__":
    unittest.main()
