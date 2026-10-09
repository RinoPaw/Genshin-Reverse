from __future__ import annotations

import unittest

from genshinre.questaction import parse_quest_action_config


QUEST_5034_ACTION_HEX = (
    "9ee373af3c2c553f09d5d58ee70a3c897360acbf69869e7b0a3d7019908f280"
    "d93000112431706539f48b37115a3580f20c02c9e1bb9627ab321f5b656644ba"
    "29a2da0adc29ae55db22c05ce6bb49f4eb67315b7580f20c42e9e1b728981967"
    "46e50d18e60409446"
)

QUEST_74703_ACTION_HEX = (
    "9ee373af3c9f074909d5d58ee70a3e897360acc7a9869e7b0a2b66a4d13d7099"
    "8ff7afdace8f2b0d93000110431706199fc9f346189efdc91c92f0969db9627ab"
    "321f5b656644ba29a2da0adc29ae55db22c05ce6bb49fa07e38180a65c81c45e"
    "8979d728981966e50d18e60406845ac47aa3d99a970869e7b0a2b66a4d13d703"
    "991f6afdace8d2b0d93000110431706199fc9f3461842eec91c0cc9969db9627a"
    "af21f5b656644ba29a2da0adc29ae55db22c05ce6bb49fa07e38183156c81cf7"
    "c0979d728981966040684599c7699c9e7b0a3d7019900bafdace"
)


class QuestActionTests(unittest.TestCase):
    def test_single_camera_move_payload(self) -> None:
        decoded = parse_quest_action_config(bytes.fromhex(QUEST_5034_ACTION_HEX))
        entry = decoded["KLKOKMBHCPI"]["503406"]
        self.assertEqual(1, len(entry["IMDGLPKIHCK"]))
        self.assertEqual(1, len(entry["IMDGLPKIHCK"][0]))

        action = entry["IMDGLPKIHCK"][0][0]
        self.assertEqual("GEEOEPCPODO", action["$type"])
        self.assertEqual("CAMERA_MOVE", action["type"])
        self.assertEqual("EaseInOutCubic", action["cameraBlendType"])
        self.assertEqual(6, action["lerpPattern"])
        self.assertFalse(action["HLGABAFOOMM"])
        self.assertTrue(action["needZAxisRotate"])
        self.assertTrue(action["DIGPJPDMJKF"])
        self.assertEqual("", action["AGNDLBACBLB"])
        self.assertEqual("", action["NEGBDDEAAAH"])
        self.assertEqual("", action["BEBDEGMLIPL"])
        self.assertEqual("", action["DAHBICEBHDB"])
        self.assertAlmostEqual(-1893.645, action["camPosOffset"]["x"], places=3)
        self.assertAlmostEqual(105.318, action["camPosOffset"]["y"], places=3)
        self.assertAlmostEqual(8630.627, action["camPosOffset"]["z"], places=3)
        self.assertAlmostEqual(-1893.707, action["camForwardTargetOffset"]["x"], places=3)
        self.assertAlmostEqual(35.0, action["camFov"], places=5)
        self.assertEqual(
            {
                "poleMinValue": -50.0,
                "elevMinValue": -50.0,
                "elevMaxValue": 50.0,
                "poleMaxValue": 50.0,
            },
            action["cutFrameTrans"],
        )

    def test_polymorphic_camera_and_time_protect_group(self) -> None:
        decoded = parse_quest_action_config(bytes.fromhex(QUEST_74703_ACTION_HEX))
        actions = decoded["KLKOKMBHCPI"]["7470301"]["IMDGLPKIHCK"][0]
        self.assertEqual(3, len(actions))

        first, second, third = actions
        self.assertEqual("CAMERA_MOVE", first["type"])
        self.assertEqual(148, first["actionId"])
        self.assertEqual(67108864, first["flag"])
        self.assertAlmostEqual(0.5, first["duration"], places=6)
        self.assertEqual("EaseInOutCubic", first["cameraBlendType"])
        self.assertTrue(first["NMEENCOHBNC"])

        self.assertEqual("CAMERA_MOVE", second["type"])
        self.assertEqual(149, second["actionId"])
        self.assertEqual("EaseOutQuad", second["cameraBlendType"])
        self.assertAlmostEqual(0.1, second["delayTime"], places=6)
        self.assertAlmostEqual(5.0, second["duration"], places=6)

        self.assertEqual("ConfigTimeProtectAction", third["$type"])
        self.assertEqual("TIME_PROTECT", third["type"])
        self.assertEqual(104, third["actionId"])
        self.assertAlmostEqual(1.0, third["duration"], places=6)


if __name__ == "__main__":
    unittest.main()
