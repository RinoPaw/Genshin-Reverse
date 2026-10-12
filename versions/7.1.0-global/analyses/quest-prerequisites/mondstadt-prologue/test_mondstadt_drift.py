import unittest
from report_mondstadt_quest_drift import normalize, classify_accept


class QuestDriftTest(unittest.TestCase):
    def test_legacy_state_condition_padding(self):
        a = normalize([{"type": "QUEST_COND_STATE_EQUAL", "param": [35100, 3, 0]}])
        b = normalize([{"type": "QUEST_COND_STATE_EQUAL", "param": [35100, 3]}])
        self.assertEqual(a, b)
        self.assertIsNone(classify_accept(a, b, "LOGIC_NONE", "LOGIC_NONE"))

    def test_significant_third_param_is_kept(self):
        result = normalize([{"type": "QUEST_COND_STATE_EQUAL", "param": [123, 3, 8]}])
        self.assertEqual([123, 3, 8], result[0]["param"])

    def test_absent_history_is_not_called_bad_data(self):
        excel = normalize([{"type": "QUEST_COND_STATE_EQUAL", "param": [35104, 3]}])
        self.assertEqual("no_compatibility_evidence",
                         classify_accept([], excel, "LOGIC_NONE", "LOGIC_NONE"))

    def test_true_predecessor_difference(self):
        a = normalize([{"type": "QUEST_COND_STATE_EQUAL", "param": [35100, 3]}])
        b = normalize([{"type": "QUEST_COND_STATE_EQUAL", "param": [35107, 3]}])
        self.assertEqual("accept_disagreement",
                         classify_accept(a, b, "LOGIC_NONE", "LOGIC_NONE"))

    def test_unlinked_placeholder_and_combination(self):
        a = normalize([{"type": "QUEST_COND_STATE_EQUAL", "param": [35202, 3]}])
        b = normalize([{"type": "QUEST_COND_STATE_EQUAL", "param": [0, 3]}])
        self.assertEqual("excel_placeholder",
                         classify_accept(a, b, "LOGIC_NONE", "LOGIC_NONE"))
        self.assertEqual("combinator_disagreement",
                         classify_accept(a, a, "LOGIC_OR", "LOGIC_NONE"))


if __name__ == "__main__":
    unittest.main()
