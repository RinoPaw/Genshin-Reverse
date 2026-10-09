from __future__ import annotations

import hashlib
import json
from pathlib import Path
import unittest

import genshinre.questbin as questbin
from genshinre.cli import build_parser
from genshinre.questbin import QuestBinParseError, parse_main_quest
from genshinre.questcoverage import QuestPayloadSample, analyze_quest_samples


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests" / "fixtures" / "quest351.hex"


class QuestBinTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.payload = bytes.fromhex(FIXTURE.read_text(encoding="ascii"))
        cls.quest = parse_main_quest(cls.payload)

    def test_cli_parses_native_quest_decoder_contract(self) -> None:
        args = build_parser().parse_args(
            ["decode-quest-bin", "Quest/351", "--output", "351.json"]
        )

        self.assertEqual("decode-quest-bin", args.command)
        self.assertEqual("Quest/351", str(args.input))
        self.assertEqual("351.json", str(args.output))

        coverage_args = build_parser().parse_args(
            ["quest-coverage", "Quest", "--output", "coverage.json"]
        )
        self.assertEqual("quest-coverage", coverage_args.command)
        self.assertEqual("Quest", str(coverage_args.input))
        self.assertEqual("coverage.json", str(coverage_args.output))

    def test_native_mainquest_runtime_aliases(self) -> None:
        self.assertEqual((352,), self.quest.suggest_track_main_quest_list)
        self.assertEqual((100351,), self.quest.reward_id_list)
        rendered = self.quest.to_dict()
        self.assertEqual([352], rendered["suggestTrackMainQuestList"])
        self.assertEqual([100351], rendered["rewardIdList"])

        fixture = ROOT / "tests" / "fixtures" / "quest375.hex"
        quest375 = parse_main_quest(bytes.fromhex(fixture.read_text(encoding="ascii")))
        self.assertTrue(quest375.talks)
        self.assertTrue(all("id" in talk and "questId" in talk for talk in quest375.talks))
        self.assertTrue(all(talk["questId"] == 375 for talk in quest375.talks))
        self.assertEqual(list(quest375.talks), quest375.to_dict()["talks"])

    def test_native_progress_guide_segment(self) -> None:
        fixture = ROOT / "tests" / "fixtures" / "quest7005-progress-guide.hex"
        payload = bytes.fromhex(fixture.read_text(encoding="ascii"))
        self.assertEqual(328, len(payload))
        self.assertEqual(
            "c616c52335577105af5c269d4e8fc4e088aea01ad062224575c6b32300e609f0",
            hashlib.sha256(payload).hexdigest(),
        )

        reader = questbin._Reader(payload)
        guides = questbin._parse_afio_bit27_progress_guides(reader)
        self.assertEqual(len(payload), reader.pos)
        self.assertEqual(1, len(guides))
        self.assertEqual(700501, guides[0]["key"])

        guide = guides[0]["value"]
        self.assertEqual(700501, guide["guideID"])
        self.assertEqual("QUEST_ProgressGuide_700501_FoldBtn", guide["JDOHEPFGICB"])
        self.assertEqual("QUEST_ProgressGuide_700501_Title", guide["LKFNLHCLCNN"])
        self.assertEqual("QUEST_ProgressGuide_700501_SubTitle", guide["IPIANOIKKLC"])
        self.assertEqual("QUEST_ProgressGuide_700501_Complete", guide["BJFHABHMIHL"])

        item = guide["items"][0]
        self.assertEqual(3, item["tag"])
        self.assertEqual("LNHDPIPGOBL", item["type"])
        self.assertEqual(70050101, item["CDJOLFDMKGB"])
        self.assertEqual(
            "ART/UI/Atlas/QuestTabIcon/UI_QuestSubTrackMark_2",
            item["iconPath"],
        )
        self.assertEqual(
            "QUEST_ProgressGuide_700501_Items_70050101_Desc",
            item["GCDJDGAMBNG"],
        )
        show = item["showCond"][0][0]
        self.assertEqual(7005, show["mainQuestId"])
        self.assertEqual(3, show["typeId"])
        self.assertEqual([121663, 1], show["param"])
        finish = item["LACMLGKFILH"][0][0]
        self.assertEqual(7005, finish["mainQuestId"])
        self.assertEqual(1, finish["typeId"])
        self.assertEqual([700508, 3], finish["param"])

    def test_exact_71_content_and_exec_name_maps(self) -> None:
        self.assertEqual(93, len(questbin.QUEST_CONTENT_NAMES))
        self.assertEqual(100, len(questbin.QUEST_EXEC_NAMES))
        self.assertEqual(
            "QUEST_CONTENT_CALL_PLAYER_TRAIN_IN_RANGE",
            questbin.QuestContent(196).type_name,
        )
        self.assertEqual(
            "QUEST_CONTENT_QUEST_GLOBAL_VAR_EQUAL",
            questbin.QuestContent(160).type_name,
        )
        self.assertEqual(
            "QUEST_EXEC_CHANGE_PLAYER_TRAIN_FIGURE_SGV",
            questbin.QuestExec(138).type_name,
        )
        self.assertEqual(
            "QUEST_EXEC_SET_IS_GAME_TIME_LOCKED_V2",
            questbin.QuestExec(81).type_name,
        )

    def test_quest_351_fixture_identity_and_full_consumption(self) -> None:
        self.assertEqual(920, len(self.payload))
        self.assertEqual(
            "285d825bedce0611494d114687bc7981789b0ef6d0a724f5abfecf423b6335de",
            hashlib.sha256(self.payload).hexdigest(),
        )
        self.assertEqual(920, self.quest.consumed)
        self.assertEqual(920, self.quest.size)
        self.assertTrue(self.quest.fully_consumed)

    def test_quest_351_rows_match_native_boundaries(self) -> None:
        self.assertEqual(351, self.quest.main_id)
        self.assertEqual(1001, self.quest.res_id)
        self.assertEqual(list(range(35100, 35108)), [row.sub_id for row in self.quest.quests])
        self.assertEqual(
            [
                (0x03F, 0x0A9),
                (0x0A9, 0x136),
                (0x136, 0x196),
                (0x196, 0x1F8),
                (0x1F8, 0x24F),
                (0x24F, 0x2B2),
                (0x2B2, 0x327),
                (0x327, 0x384),
            ],
            [(row.start, row.end) for row in self.quest.quests],
        )
        self.assertEqual([2, 4, 8, 7, 1, 6, 5, 3], [row.order for row in self.quest.quests])

    def test_quest_351_confirmed_row_metadata_semantics(self) -> None:
        rows = {row.sub_id: row for row in self.quest.quests}
        self.assertEqual(573649119, rows[35100].desc_text_map_hash)
        self.assertTrue(rows[35100].is_rewind)
        self.assertEqual(1, rows[35100].show_guide)
        self.assertEqual(1, rows[35103].show_type)
        self.assertEqual(2, rows[35103].show_guide)
        self.assertTrue(rows[35102].finish_parent)
        self.assertIsInstance(rows[35100].guide, dict)
        self.assertEqual(
            {"param2": "", "param1": ""},
            rows[35101].guide_hint,
        )
        self.assertNotIn("BIHKOLLEDPE", rows[35101].unknown_fields)
        self.assertEqual(
            {"param2": "", "param1": ""},
            rows[35101].to_dict()["guideHint"],
        )
        rendered = rows[35102].to_dict()
        self.assertEqual(1403458759, rendered["descTextMapHash"])
        self.assertTrue(rendered["isRewind"])
        self.assertTrue(rendered["finishParent"])
        self.assertEqual(1, rendered["showGuideId"])

    def test_quest_351_confirmed_content_and_exec_semantics(self) -> None:
        rows = {row.sub_id: row for row in self.quest.quests}

        def contents(items):
            return [(item.type_name, list(item.params)) for item in items]

        def execs(items):
            return [(item.type_name, list(item.params)) for item in items]

        self.assertEqual(
            [
                ("QUEST_CONTENT_FINISH_PLOT", [35100, 0]),
                ("QUEST_CONTENT_TRIGGER_FIRE", [1053, 0]),
            ],
            contents(rows[35100].finish_cond),
        )
        self.assertEqual(
            [("QUEST_CONTENT_TEAM_DEAD", [0, 0])],
            contents(rows[35101].fail_cond),
        )
        self.assertEqual(
            [("QUEST_EXEC_ROLLBACK_QUEST", ["35100"])],
            execs(rows[35101].fail_exec),
        )
        self.assertEqual(
            [("QUEST_CONTENT_TRIGGER_FIRE", [1100, 0])],
            contents(rows[35101].finish_cond),
        )
        self.assertEqual(
            [("QUEST_CONTENT_TRIGGER_FIRE", [1017, 0])],
            contents(rows[35102].finish_cond),
        )
        self.assertEqual(
            [("QUEST_CONTENT_TRIGGER_FIRE", [1016, 0])],
            contents(rows[35103].finish_cond),
        )
        self.assertEqual(
            [("QUEST_CONTENT_FINISH_PLOT", [35104, 0])],
            contents(rows[35104].finish_cond),
        )
        self.assertEqual(
            [("QUEST_CONTENT_TRIGGER_FIRE", [1016, 0])],
            contents(rows[35105].finish_cond),
        )
        self.assertEqual(
            [("QUEST_EXEC_LOCK_POINT", ["3", "1720"])],
            execs(rows[35106].finish_exec),
        )
        self.assertEqual(
            [("QUEST_CONTENT_UNLOCK_TRANS_POINT", [3, 6])],
            contents(rows[35106].finish_cond),
        )
        self.assertEqual(
            [("QUEST_EXEC_REFRESH_GROUP_SUITE", ["3", "133003429,1"])],
            execs(rows[35107].finish_exec),
        )
        self.assertEqual(
            [("QUEST_CONTENT_TRIGGER_FIRE", [1101, 0])],
            contents(rows[35107].finish_cond),
        )

    def test_quest_351_confirmed_root_semantics(self) -> None:
        self.assertEqual("Actor/Quest/AQ351", self.quest.lua_path)
        self.assertEqual(1001, self.quest.series)
        self.assertIsNone(self.quest.chapter_id)
        self.assertEqual(597412161, self.quest.title_text_map_hash)
        self.assertEqual(1008400655, self.quest.desc_text_map_hash)
        rendered = self.quest.to_dict()
        self.assertEqual("Actor/Quest/AQ351", rendered["luaPath"])
        self.assertEqual(1001, rendered["series"])
        self.assertEqual(597412161, rendered["titleTextMapHash"])
        self.assertEqual(1008400655, rendered["descTextMapHash"])

    def test_mainquest_dialog_list_is_semantic(self) -> None:
        dialog = {
            "rawMask": "0x00000000",
            "id": 70059801,
            "talkContentTextMapHash": 193971018,
        }
        quest = questbin.MainQuest(
            main_id=7005,
            quests=(),
            dialog_list=(dialog,),
        )
        rendered = quest.to_dict()
        self.assertEqual([dialog], rendered["dialogList"])
        self.assertNotIn("PCIAMAFDDAA", rendered.get("unknown", {}))

    def test_quest_351_preload_lua_list_is_semantic(self) -> None:
        self.assertEqual((14457059026087496718,), self.quest.preload_lua_list)
        self.assertNotIn("JNHHOJAPDPP", self.quest.unknown_fields)
        rendered = self.quest.to_dict()
        self.assertEqual([14457059026087496718], rendered["preloadLuaList"])
        self.assertEqual(1008400655, self.quest.desc_text_map_hash)

    def test_product_json_does_not_synthesize_legacy_fields(self) -> None:
        rendered = self.quest.to_json()
        self.assertEqual(rendered, self.quest.to_json())
        for field_name in (
            "acceptCond",
            "beginExec",
            "acceptCondComb",
            "finishCondComb",
            "failCondComb",
        ):
            self.assertNotIn(field_name, rendered)
        self.assertNotIn('"start"', rendered)
        self.assertNotIn('"end"', rendered)
        parsed = json.loads(rendered)
        self.assertEqual(351, parsed["mainId"])
        self.assertEqual(8, len(parsed["quests"]))

    def test_representative_quest_fixtures_full_consume(self) -> None:
        cases = {
            375: {
                "size": 1310,
                "sha256": "d534575d068e26aa20c02a665a9ed9b1b497345f0d8ae754bfabdcf5d9dea928",
                "res_id": 1002,
                "row_ids": list(range(37501, 37508)),
                "orders": [1, 2, 3, 4, 5, 6, 7],
                "bounds": [
                    (0x1EB, 0x264),
                    (0x264, 0x2C9),
                    (0x2C9, 0x340),
                    (0x340, 0x3B6),
                    (0x3B6, 0x42F),
                    (0x42F, 0x492),
                    (0x492, 0x4F6),
                ],
                "dialogue_count": 4,
            },
            376: {
                "size": 1492,
                "sha256": "642bda42ebe38462fa3ce2525ecf20a8e3ad51dcdaca9d96c97325a49f96c130",
                "res_id": 1002,
                "row_ids": list(range(37601, 37609)),
                "orders": [1, 2, 3, 4, 5, 6, 7, 8],
                "bounds": [
                    (0x21D, 0x2A1),
                    (0x2A1, 0x350),
                    (0x350, 0x3A8),
                    (0x3A8, 0x408),
                    (0x408, 0x46F),
                    (0x46F, 0x4DB),
                    (0x4DB, 0x543),
                    (0x543, 0x5AC),
                ],
                "dialogue_count": 4,
            },
            388: {
                "size": 1374,
                "sha256": "ae0407c71114b0f202a5590eac5a493ddb3847f115228b5153f74e166f188eb9",
                "res_id": 1003,
                "row_ids": list(range(38801, 38807)),
                "orders": [2, 3, 5, 6, 4, 1],
                "bounds": [
                    (0x26E, 0x2DB),
                    (0x2DB, 0x379),
                    (0x379, 0x400),
                    (0x400, 0x46D),
                    (0x46D, 0x4C6),
                    (0x4C6, 0x536),
                ],
                "dialogue_count": 6,
            },
        }

        for main_id, expected in cases.items():
            with self.subTest(main_id=main_id):
                fixture = ROOT / "tests" / "fixtures" / f"quest{main_id}.hex"
                payload = bytes.fromhex(fixture.read_text(encoding="ascii"))
                quest = parse_main_quest(payload)

                self.assertEqual(expected["size"], len(payload))
                self.assertEqual(expected["sha256"], hashlib.sha256(payload).hexdigest())
                self.assertEqual(expected["size"], quest.consumed)
                self.assertEqual(expected["size"], quest.size)
                self.assertTrue(quest.fully_consumed)
                self.assertEqual(main_id, quest.main_id)
                self.assertEqual(expected["res_id"], quest.res_id)
                self.assertEqual(expected["res_id"], quest.chapter_id)
                self.assertEqual(expected["dialogue_count"], len(quest.talks))
                self.assertEqual(expected["row_ids"], [row.sub_id for row in quest.quests])
                self.assertEqual(expected["orders"], [row.order for row in quest.quests])
                self.assertEqual(
                    expected["bounds"],
                    [(row.start, row.end) for row in quest.quests],
                )

    def test_representative_quest_native_shapes(self) -> None:
        def load(main_id: int):
            fixture = ROOT / "tests" / "fixtures" / f"quest{main_id}.hex"
            return parse_main_quest(bytes.fromhex(fixture.read_text(encoding="ascii")))

        quest375 = load(375)
        dialogue375 = quest375.talks
        self.assertEqual(
            (7083671648706514976, 11108662340521195773),
            quest375.force_preload_lua_list,
        )
        self.assertNotIn("DKKIDDFEHMD", quest375.unknown_fields)
        self.assertEqual(
            [7083671648706514976, 11108662340521195773],
            quest375.to_dict()["forcePreloadLuaList"],
        )
        self.assertEqual([1161], dialogue375[0]["field0U32Array"])
        self.assertEqual(375, dialogue375[0]["field6U32"])
        self.assertEqual(37311, dialogue375[0]["field8U32"])
        self.assertEqual(
            ["37501", "2"],
            dialogue375[0]["field3Conditions"][0]["params"],
        )
        self.assertEqual(
            "QuestDialogue/AQ/Mengde2_375/Q37501",
            dialogue375[2]["field4String"],
        )

        rows375 = {row.sub_id: row for row in quest375.quests}
        self.assertEqual((1001,), rows375[37501].npc_ids)
        self.assertTrue(rows375[37503].is_mp_block)
        self.assertEqual(2, rows375[37503].ban_type)
        self.assertEqual(2, rows375[37501].finish_exec[0].type_id)
        self.assertEqual(("1008", "1"), rows375[37501].finish_exec[0].params)
        self.assertEqual(2, rows375[37501].finish_cond[0].type_id)
        self.assertEqual((37501, 0), rows375[37501].finish_cond[0].params)

        quest376 = load(376)
        rows376 = {row.sub_id: row for row in quest376.quests}
        self.assertNotIn("bit5", quest376.unknown_fields)
        self.assertEqual(1, rows376[37602].ban_type)
        self.assertEqual((1001, 1009), rows376[37605].npc_ids)

        quest388 = load(388)
        rows388 = {row.sub_id: row for row in quest388.quests}
        self.assertEqual(6, len(quest388.talks))
        self.assertEqual((1001, 1009, 1006), rows388[38801].npc_ids)
        self.assertEqual((1001, 1009, 1006), rows388[38801].exclusive_npc_list)
        self.assertEqual(
            [1001, 1009, 1006],
            rows388[38801].to_dict()["exclusiveNpcList"],
        )
        self.assertEqual(
            rows388[38801].to_dict()["npcId"],
            rows388[38801].to_dict()["exclusiveNpcList"],
        )
        self.assertEqual((1001, 1009, 1006), rows388[38806].shared_npc_list)
        self.assertNotIn("JFCJBBCEDGD", rows388[38806].unknown_fields)
        self.assertEqual(
            [1001, 1009, 1006],
            rows388[38806].to_dict()["sharedNpcList"],
        )
        self.assertEqual(7, rows388[38801].finish_exec[0].type_id)
        self.assertEqual(15, rows388[38803].finish_exec[0].type_id)
        self.assertEqual(7, rows388[38802].finish_cond[0].type_id)


    def test_quest_355_native_afio_bit56_and_oop_full_consumption(self) -> None:
        fixture = ROOT / "tests" / "fixtures" / "quest355.hex"
        payload = bytes.fromhex(fixture.read_text(encoding="ascii"))
        self.assertEqual(797, len(payload))
        self.assertEqual(
            "d95922df770abef9629302517d81b6c0ec423f094f88bb25fcff90a269fbda60",
            hashlib.sha256(payload).hexdigest(),
        )
        quest = parse_main_quest(payload)
        self.assertEqual(355, quest.main_id)
        self.assertEqual(797, quest.consumed)
        self.assertTrue(quest.fully_consumed)
        table = quest.free_style_dic
        self.assertIsInstance(table, tuple)
        self.assertTrue(table)
        self.assertTrue(all(set(entry) == {"key", "values"} for entry in table))
        self.assertEqual(list(table), quest.to_dict()["freeStyleDic"])

    def test_promoted_subquest_scalar_semantics(self) -> None:
        def decode_single(bit: int, encoded: bytes):
            mask = 1 << bit
            raw_mask = (mask - 0x2244ECE7) & 0xFFFFFFFFFFFFFFFF
            reader = questbin._Reader(raw_mask.to_bytes(8, "little") + encoded)
            row = questbin._parse_row(reader)
            self.assertEqual(len(reader.data), reader.pos)
            return row

        sub_id_set = 7
        raw = (sub_id_set - 0x191BB9F3) & 0xFFFFFFFF
        row = decode_single(5, raw.to_bytes(4, "little"))
        self.assertEqual(sub_id_set, row.sub_id_set)
        self.assertNotIn("IILNPFILEGJ", row.unknown_fields)

        fail_parent_show = 2
        raw = fail_parent_show ^ 0x792B3478
        row = decode_single(52, raw.to_bytes(4, "little"))
        self.assertEqual(fail_parent_show, row.fail_parent_show)
        self.assertNotIn("IAHIMJCLIJG", row.unknown_fields)

        guide_tips_hash = 0x12345678
        raw = guide_tips_hash ^ 0xDE74075F
        row = decode_single(7, raw.to_bytes(4, "little"))
        self.assertEqual(guide_tips_hash, row.guide_tips_text_map_hash)
        self.assertNotIn("KBDPGMJFJGO", row.unknown_fields)

        step_hash = 0x89ABCDEF
        raw = (step_hash - 0xA6768BF5) & 0xFFFFFFFF
        row = decode_single(53, raw.to_bytes(4, "little"))
        self.assertEqual(step_hash, row.step_desc_text_map_hash)
        self.assertNotIn("FKKAEBOAMCN", row.unknown_fields)

        force_priority = 4
        raw = ((force_priority ^ 0xBCB94817) - 0xB5F93568) & 0xFFFFFFFF
        row = decode_single(46, raw.to_bytes(4, "little"))
        self.assertEqual(force_priority, row.force_paimon_guide_priority)
        self.assertNotIn("EOFPICJEHLP", row.unknown_fields)
        self.assertEqual(
            force_priority,
            row.to_dict()["forcePaimonGuidePriority"],
        )

        unfinished_hint_show = 1
        raw = unfinished_hint_show ^ 0x011CF6ED
        row = decode_single(10, raw.to_bytes(4, "little"))
        self.assertEqual(unfinished_hint_show, row.unfinished_hint_show)
        self.assertNotIn("DMCMNPLMCKL", row.unknown_fields)
        self.assertEqual(
            unfinished_hint_show,
            row.to_dict()["unfinishedHintShowId"],
        )

        extra_show_type = 1
        raw = extra_show_type ^ 0x5E79B226
        row = decode_single(11, raw.to_bytes(4, "little"))
        self.assertEqual(extra_show_type, row.extra_show_type)
        self.assertNotIn("FABHGLLGFHN", row.unknown_fields)
        self.assertEqual(extra_show_type, row.to_dict()["extraShowTypeId"])

        row = decode_single(42, bytes([0xB1]))
        self.assertTrue(row.fail_parent)
        self.assertNotIn("HJOFKFKBFCF", row.unknown_fields)
        self.assertTrue(row.to_dict()["failParent"])

    def test_quest_310_native_afio_bit39_scalar(self) -> None:
        fixture = ROOT / "tests" / "fixtures" / "quest310.hex"
        quest = parse_main_quest(bytes.fromhex(fixture.read_text(encoding="ascii")))
        self.assertEqual(310, quest.main_id)
        self.assertEqual(588, quest.size)
        self.assertEqual(588, quest.consumed)
        self.assertEqual(7, quest.quest_type)
        self.assertEqual(8, len(quest.quests))

    def test_batch_coverage_report_for_gold_fixtures(self) -> None:
        samples = []
        for main_id in (310, 351, 375, 376, 388):
            fixture = ROOT / "tests" / "fixtures" / f"quest{main_id}.hex"
            samples.append(
                QuestPayloadSample(
                    name=fixture.name,
                    data=bytes.fromhex(fixture.read_text(encoding="ascii")),
                    main_id_hint=main_id,
                )
            )

        report = analyze_quest_samples(samples)
        self.assertEqual(5, report["total"])
        self.assertEqual(5, report["fullConsumed"])
        self.assertEqual(0, report["failed"])
        self.assertEqual([], report["failureFamilies"])
        self.assertEqual([], report["idMismatches"])
        self.assertEqual(5, report["observedAfioBits"]["45"])
        self.assertEqual(37, report["observedLaimBits"]["19"])
        self.assertEqual(3, report["structuralAfioFields"]["bit54"])

    def test_batch_coverage_groups_unknown_presence_bit(self) -> None:
        payload = bytearray(self.payload)
        raw_mask = int.from_bytes(payload[:8], "little")
        mask = (raw_mask + 0xB19CC79B) & 0xFFFFFFFFFFFFFFFF
        mask |= 1 << 1
        payload[:8] = ((mask - 0xB19CC79B) & 0xFFFFFFFFFFFFFFFF).to_bytes(8, "little")

        report = analyze_quest_samples(
            [QuestPayloadSample("quest351-mutated", bytes(payload), 351)]
        )
        self.assertEqual(0, report["fullConsumed"])
        self.assertEqual(1, report["failed"])
        self.assertEqual("AFIOOHMJHDM.bit1", report["failureFamilies"][0]["family"])
        self.assertEqual(1, report["failureFamilies"][0]["count"])

    def test_strict_decoder_rejects_trailing_bytes(self) -> None:
        with self.assertRaisesRegex(QuestBinParseError, "unexplained trailing bytes"):
            parse_main_quest(self.payload + b"\0")


if __name__ == "__main__":
    unittest.main()
