from __future__ import annotations

import unittest

from genshinre.questaudit import audit_quest_rows


class QuestAuditTests(unittest.TestCase):
    def test_native_and_compatibility_are_classified_separately(self) -> None:
        raw = {
            35101: {
                "finishCond": [
                    {"type": "QUEST_CONTENT_STATE_EQUAL", "param": [35100, 3]}
                ],
                "FAPCNCGCEBJ": [
                    {"type": "QUEST_EXEC_ADD_QUEST_PROGRESS", "param": ["x"]}
                ],
            }
        }
        resource = {
            35101: {
                "subId": 35101,
                "finishCond": [
                    {"type": "QUEST_CONTENT_STATE_EQUAL", "param": [35100, 3, 0]}
                ],
                "finishExec": [
                    {"type": "QUEST_EXEC_ADD_QUEST_PROGRESS", "param": ["x"]}
                ],
                "acceptCond": [
                    {"type": "QUEST_COND_STATE_EQUAL", "param": [35100, 3]}
                ],
            }
        }
        manifest = {
            "rows": {
                "35101": {
                    "fields": {
                        "acceptCond": {
                            "value": [
                                {
                                    "type": "QUEST_COND_STATE_EQUAL",
                                    "param": [35100, 3],
                                }
                            ]
                        }
                    },
                    "missing_field_status": {
                        "acceptCond": {"status": "compatibility-value"},
                        "beginExec": {"status": "compatibility-empty"},
                    },
                }
            }
        }

        result = audit_quest_rows(raw, resource, recovery_manifest=manifest)
        row = result["rows"]["35101"]
        self.assertEqual(row["fields"]["finishCond"]["status"], "native-match")
        self.assertEqual(row["fields"]["finishExec"]["status"], "native-match")
        self.assertEqual(
            row["fields"]["acceptCond"]["status"],
            "compatibility-supported",
        )
        self.assertFalse(row["fields"]["acceptCond"]["native_7_1"])
        self.assertEqual(
            row["fields"]["beginExec"]["status"],
            "compatibility-empty-match",
        )
        self.assertEqual(result["summary"]["conflicts"], 0)

    def test_native_divergence_is_a_conflict(self) -> None:
        raw = {
            1: {
                "CNPOFCKIBDL": [
                    {"type": "QUEST_EXEC_FAIL_QUEST", "param": [2]}
                ]
            }
        }
        resource = {1: {"subId": 1}}
        result = audit_quest_rows(raw, resource)
        self.assertEqual(
            result["rows"]["1"]["fields"]["failExec"]["status"],
            "resource-missing-native",
        )
        self.assertEqual(result["summary"]["conflicts"], 1)

    def test_unresolved_compatibility_value_is_not_promoted(self) -> None:
        raw = {2: {}}
        resource = {
            2: {
                "subId": 2,
                "beginExec": [
                    {"type": "QUEST_EXEC_NOTIFY_GROUP_LUA", "param": [3, 4]}
                ],
            }
        }
        manifest = {
            "rows": {
                "2": {
                    "fields": {},
                    "missing_field_status": {
                        "acceptCond": {"status": "compatibility-empty"},
                        "beginExec": {
                            "status": "unresolved",
                            "reason": "community-consensus-diverged",
                        },
                    },
                }
            }
        }
        result = audit_quest_rows(raw, resource, recovery_manifest=manifest)
        item = result["rows"]["2"]["fields"]["beginExec"]
        self.assertEqual(item["status"], "compatibility-unresolved-present")
        self.assertFalse(item["native_7_1"])
        self.assertEqual(result["summary"]["conflicts"], 0)

    def test_only_problems_keeps_unresolved_rows(self) -> None:
        result = audit_quest_rows(
            {3: {}},
            {3: {"subId": 3}},
            recovery_manifest={
                "rows": {
                    "3": {
                        "fields": {},
                        "missing_field_status": {
                            "acceptCond": {"status": "unresolved"},
                            "beginExec": {"status": "compatibility-empty"},
                        },
                    }
                }
            },
            only_problems=True,
        )
        self.assertIn("3", result["rows"])


    def test_legacy_compatibility_controls_are_not_native(self) -> None:
        result = audit_quest_rows(
            {10: {}},
            {
                10: {
                    "subId": 10,
                    "finishCondComb": "LOGIC_OR",
                    "failCondComb": "LOGIC_OR",
                    "gainItems": [{"itemId": 1021, "count": 1}],
                }
            },
        )
        row = result["rows"]["10"]["fields"]
        self.assertEqual(
            row["finishCondComb"]["status"],
            "compatibility-control-present",
        )
        self.assertFalse(row["finishCondComb"]["native_7_1"])
        self.assertEqual(
            row["gainItems"]["status"],
            "legacy-compatibility-slot-present",
        )
        self.assertFalse(row["gainItems"]["native_7_1"])
        self.assertEqual(result["summary"]["conflicts"], 0)


if __name__ == "__main__":
    unittest.main()
