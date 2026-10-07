from __future__ import annotations

import unittest

from genshinre.questrecovery71 import build_manifest


RAW_SOURCE = "DimbreathBot/AnimeGameData@792978e5"
COMMUNITY_71 = "capyb2222/LunaGC-Resources@395a5ee6"
COMMUNITY_70 = "chenlin996/LunaGC-Resources7.0@0991d8a9"


class QuestRecovery71Tests(unittest.TestCase):
    def test_native_retained_fields_keep_same_version_provenance(self) -> None:
        raw = {
            10001: {
                "finishCond": [
                    {
                        "type": "QUEST_CONTENT_TRIGGER_FIRE",
                        "param": [123, 0],
                        "JBELGECAIIL": "",
                    }
                ],
                "KHEBAEMAPPJ": [
                    {
                        "type": "QUEST_CONTENT_TEAM_DEAD",
                        "param": [0, 0],
                        "JBELGECAIIL": "",
                    }
                ],
                "FAPCNCGCEBJ": [
                    {
                        "type": "QUEST_EXEC_LOCK_POINT",
                        "param": ["3", "99"],
                    }
                ],
                "CNPOFCKIBDL": [
                    {
                        "type": "QUEST_EXEC_ROLLBACK_QUEST",
                        "param": ["10000"],
                    }
                ],
            }
        }
        community_70 = {
            10001: {
                "subId": 10001,
                "acceptCond": [
                    {
                        "type": "QUEST_COND_STATE_EQUAL",
                        "param": [10000, 3],
                    }
                ],
                "beginExec": [
                    {
                        "type": "QUEST_EXEC_SET_GAME_TIME",
                        "param": ["6", "0"],
                    }
                ],
            }
        }
        community_71 = {
            10001: {
                "subId": 10001,
                "acceptCond": [
                    {
                        "type": "QUEST_COND_STATE_EQUAL",
                        "param": [10000, 3, 0],
                    }
                ],
                "beginExec": [
                    {
                        "type": "QUEST_EXEC_SET_GAME_TIME",
                        "param": ["6", "0"],
                    }
                ],
            }
        }

        manifest, unresolved = build_manifest(
            raw,
            community_71,
            community_70,
            raw_71_source=RAW_SOURCE,
            community_71_source=COMMUNITY_71,
            community_70_source=COMMUNITY_70,
        )

        row = manifest["rows"]["10001"]
        fields = row["fields"]

        self.assertEqual(
            fields["finishCond"]["provenance"]["kind"],
            "same-version-client-projection",
        )
        self.assertEqual(
            fields["finishCond"]["provenance"]["raw_field"],
            "finishCond",
        )
        self.assertEqual(
            fields["failCond"]["provenance"]["raw_field"],
            "KHEBAEMAPPJ",
        )
        self.assertEqual(
            fields["finishExec"]["provenance"]["raw_field"],
            "FAPCNCGCEBJ",
        )
        self.assertEqual(
            fields["failExec"]["provenance"]["raw_field"],
            "CNPOFCKIBDL",
        )

        self.assertEqual(
            fields["acceptCond"]["provenance"]["kind"],
            "community-carry-forward",
        )
        self.assertFalse(fields["acceptCond"]["provenance"]["native_7_1"])
        self.assertEqual(
            fields["acceptCond"]["value"][0]["param"],
            [10000, 3, 0],
        )
        self.assertEqual(
            row["missing_field_status"]["acceptCond"]["status"],
            "compatibility-value",
        )
        self.assertEqual(
            row["missing_field_status"]["beginExec"]["status"],
            "compatibility-value",
        )
        self.assertEqual(unresolved["summary"]["rows"], 0)

    def test_new_71_row_does_not_synthesize_missing_fields(self) -> None:
        raw = {20001: {"finishCond": []}}
        community_71 = {
            20001: {
                "subId": 20001,
                "acceptCond": [
                    {
                        "type": "QUEST_COND_STATE_EQUAL",
                        "param": [20000, 3],
                    }
                ],
                "beginExec": [
                    {
                        "type": "QUEST_EXEC_NOTIFY_GROUP_LUA",
                        "param": ["3", "99"],
                    }
                ],
            }
        }

        manifest, unresolved = build_manifest(
            raw,
            community_71,
            {},
            raw_71_source=RAW_SOURCE,
            community_71_source=COMMUNITY_71,
            community_70_source=COMMUNITY_70,
        )

        row = manifest["rows"]["20001"]
        self.assertNotIn("acceptCond", row["fields"])
        self.assertNotIn("beginExec", row["fields"])
        self.assertEqual(
            row["missing_field_status"]["acceptCond"]["reason"],
            "no-predecessor-community-row",
        )
        self.assertEqual(
            row["missing_field_status"]["beginExec"]["reason"],
            "no-predecessor-community-row",
        )
        self.assertEqual(unresolved["summary"]["rows"], 1)
        self.assertFalse(manifest["policy"]["previous_row_synthesis"])

    def test_diverged_community_value_is_unresolved(self) -> None:
        raw = {30001: {}}
        community_70 = {
            30001: {
                "subId": 30001,
                "acceptCond": [
                    {
                        "type": "QUEST_COND_STATE_EQUAL",
                        "param": [30000, 3],
                    }
                ],
            }
        }
        community_71 = {
            30001: {
                "subId": 30001,
                "acceptCond": [
                    {
                        "type": "QUEST_COND_STATE_EQUAL",
                        "param": [29999, 3],
                    }
                ],
            }
        }

        manifest, unresolved = build_manifest(
            raw,
            community_71,
            community_70,
            raw_71_source=RAW_SOURCE,
            community_71_source=COMMUNITY_71,
            community_70_source=COMMUNITY_70,
        )

        status = manifest["rows"]["30001"]["missing_field_status"]["acceptCond"]
        self.assertEqual(status["status"], "unresolved")
        self.assertEqual(status["reason"], "community-carry-forward-diverged")
        self.assertNotIn("acceptCond", manifest["rows"]["30001"]["fields"])
        self.assertIn("acceptCond", unresolved["rows"]["30001"]["fields"])


    def test_comparison_ignores_exact_duplicate_source_slots(self) -> None:
        raw = {50001: {}}
        duplicated = [
            {
                "type": "QUEST_COND_STATE_EQUAL",
                "param": [49999, 3],
            },
            {
                "type": "QUEST_COND_STATE_EQUAL",
                "param": [49998, 3],
            },
            {
                "type": "QUEST_COND_STATE_EQUAL",
                "param": [49998, 3],
            },
        ]
        canonical = [
            {
                "type": "QUEST_COND_STATE_EQUAL",
                "param": [49999, 3],
            },
            {
                "type": "QUEST_COND_STATE_EQUAL",
                "param": [49998, 3],
            },
        ]

        manifest, unresolved = build_manifest(
            raw,
            {50001: {"subId": 50001, "acceptCond": canonical}},
            {50001: {"subId": 50001, "acceptCond": duplicated}},
            raw_71_source=RAW_SOURCE,
            community_71_source=COMMUNITY_71,
            community_70_source=COMMUNITY_70,
        )

        row = manifest["rows"]["50001"]
        self.assertEqual(
            row["missing_field_status"]["acceptCond"]["status"],
            "compatibility-value",
        )
        self.assertEqual(row["fields"]["acceptCond"]["value"], canonical)
        self.assertNotIn("50001", unresolved["rows"])

    def test_unknown_accept_placeholder_is_not_recovered(self) -> None:
        raw = {40001: {}}
        community_70 = {
            40001: {
                "subId": 40001,
                "acceptCond": [
                    {
                        "type": "QUEST_COND_UNKNOWN",
                        "param": [0, 0],
                    }
                ],
            }
        }
        community_71 = {
            40001: {
                "subId": 40001,
                "acceptCond": [
                    {
                        "type": "QUEST_COND_UNKNOWN",
                        "param": [0, 0],
                    }
                ],
            }
        }

        manifest, unresolved = build_manifest(
            raw,
            community_71,
            community_70,
            raw_71_source=RAW_SOURCE,
            community_71_source=COMMUNITY_71,
            community_70_source=COMMUNITY_70,
        )

        row = manifest["rows"]["40001"]
        self.assertNotIn("acceptCond", row["fields"])
        self.assertEqual(
            row["missing_field_status"]["acceptCond"]["status"],
            "unresolved",
        )
        self.assertEqual(
            row["missing_field_status"]["acceptCond"]["reason"],
            "community-placeholder-only",
        )
        self.assertIn("40001", unresolved["rows"])


if __name__ == "__main__":
    unittest.main()