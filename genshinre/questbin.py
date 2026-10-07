from __future__ import annotations

from dataclasses import dataclass, field
import json
import struct
from typing import Any, Callable

from .questaction import QuestActionParseError, parse_quest_action_config

_U16 = 0xFFFF
_U32 = 0xFFFFFFFF
_U64 = 0xFFFFFFFFFFFFFFFF


class QuestBinParseError(ValueError):
    """Raised when a native Quest BinOutput payload violates the known 7.1 schema."""


@dataclass(frozen=True)
class QuestExec:
    type_id: int
    params: tuple[str, ...] = ()

    @property
    def type_name(self) -> str | None:
        return QUEST_EXEC_NAMES.get(self.type_id)

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {"typeId": self.type_id}
        if self.type_name is not None:
            out["type"] = self.type_name
        if self.params:
            out["param"] = list(self.params)
        return out


@dataclass(frozen=True)
class QuestContent:
    type_id: int
    params: tuple[int, ...] = ()
    string_param: str | None = None
    value: int | None = None

    @property
    def type_name(self) -> str | None:
        return QUEST_CONTENT_NAMES.get(self.type_id)

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {"typeId": self.type_id}
        if self.type_name is not None:
            out["type"] = self.type_name
        if self.params:
            out["param"] = list(self.params)
        if self.string_param is not None:
            out["paramStr"] = self.string_param
        if self.value is not None:
            out["value"] = self.value
        return out


@dataclass(frozen=True)
class QuestRow:
    main_id: int | None
    sub_id: int | None
    order: int | None
    desc_text_map_hash: int | None = None
    is_mp_block: bool | None = None
    is_rewind: bool | None = None
    finish_parent: bool | None = None
    show_type: int | None = None
    show_guide: int | None = None
    ban_type: int | None = None
    sub_id_set: int | None = None
    step_desc_text_map_hash: int | None = None
    fail_parent_show: int | None = None
    guide_tips_text_map_hash: int | None = None
    guide: dict[str, Any] | None = None
    npc_ids: tuple[int, ...] = ()
    exclusive_place_list: tuple[int, ...] = ()
    fail_exec: tuple[QuestExec, ...] = ()
    fail_cond: tuple[QuestContent, ...] = ()
    finish_cond: tuple[QuestContent, ...] = ()
    finish_exec: tuple[QuestExec, ...] = ()
    unknown_fields: dict[str, Any] = field(default_factory=dict)
    presence_bits: tuple[int, ...] = ()
    start: int = 0
    end: int = 0

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {}
        if self.main_id is not None:
            out["mainId"] = self.main_id
        if self.sub_id is not None:
            out["subId"] = self.sub_id
        if self.order is not None:
            out["order"] = self.order
        if self.desc_text_map_hash is not None:
            out["descTextMapHash"] = self.desc_text_map_hash
        if self.is_mp_block is not None:
            out["isMpBlock"] = self.is_mp_block
        if self.is_rewind is not None:
            out["isRewind"] = self.is_rewind
        if self.finish_parent is not None:
            out["finishParent"] = self.finish_parent
        if self.show_type is not None:
            out["showTypeId"] = self.show_type
        if self.show_guide is not None:
            out["showGuideId"] = self.show_guide
        if self.ban_type is not None:
            out["banTypeId"] = self.ban_type
        if self.sub_id_set is not None:
            out["subIdSet"] = self.sub_id_set
        if self.step_desc_text_map_hash is not None:
            out["stepDescTextMapHash"] = self.step_desc_text_map_hash
        if self.fail_parent_show is not None:
            out["failParentShow"] = self.fail_parent_show
        if self.guide_tips_text_map_hash is not None:
            out["guideTipsTextMapHash"] = self.guide_tips_text_map_hash
        if self.guide is not None:
            out["guide"] = self.guide
        if self.npc_ids:
            out["npcId"] = list(self.npc_ids)
        if self.exclusive_place_list:
            out["exclusivePlaceList"] = list(self.exclusive_place_list)
        if self.fail_exec:
            out["failExec"] = [x.to_dict() for x in self.fail_exec]
        if self.fail_cond:
            out["failCond"] = [x.to_dict() for x in self.fail_cond]
        if self.finish_cond:
            out["finishCond"] = [x.to_dict() for x in self.finish_cond]
        if self.finish_exec:
            out["finishExec"] = [x.to_dict() for x in self.finish_exec]
        if self.unknown_fields:
            out["unknown"] = self.unknown_fields
        return out


@dataclass(frozen=True)
class MainQuest:
    """Native 7.1 MainQuest with runtime-useful aliases backed by recovered AFIO fields."""

    main_id: int | None
    quests: tuple[QuestRow, ...]
    res_id: int | None = None
    lua_path: str | dict[str, Any] | None = None
    series: int | None = None
    chapter_id: int | None = None
    activity_id: int | None = None
    recommend_level: int | None = None
    task_id: int | None = None
    title_text_map_hash: int | None = None
    desc_text_map_hash: int | None = None
    free_style_dic: tuple[dict[str, Any], ...] = ()
    show_type: int | None = None
    quest_type: int | None = None
    active_mode: int | None = None
    main_quest_tag: int | None = None
    show_red_point: bool | None = None
    repeatable: bool | None = None
    suggest_track_out_of_order: bool | None = None
    special_show_quest_id: int | None = None
    special_show_cond_id_list: tuple[int, ...] = ()
    special_show_reward_id: tuple[int, ...] = ()
    suggest_track_main_quest_list: tuple[int, ...] = ()
    reward_id_list: tuple[int, ...] = ()
    talks: tuple[dict[str, Any], ...] = ()
    action_config: dict[str, Any] | None = None
    unknown_fields: dict[str, Any] = field(default_factory=dict)
    presence_bits: tuple[int, ...] = ()
    consumed: int = 0
    size: int = 0

    @property
    def fully_consumed(self) -> bool:
        return self.consumed == self.size

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {}
        if self.main_id is not None:
            out["mainId"] = self.main_id
        if self.res_id is not None:
            out["resId"] = self.res_id
        if self.lua_path is not None:
            out["luaPath"] = self.lua_path
        if self.series is not None:
            out["series"] = self.series
        if self.chapter_id is not None:
            out["chapterId"] = self.chapter_id
        if self.activity_id is not None:
            out["activityId"] = self.activity_id
        if self.recommend_level is not None:
            out["recommendLevel"] = self.recommend_level
        if self.task_id is not None:
            out["taskID"] = self.task_id
        if self.title_text_map_hash is not None:
            out["titleTextMapHash"] = self.title_text_map_hash
        if self.desc_text_map_hash is not None:
            out["descTextMapHash"] = self.desc_text_map_hash
        if self.free_style_dic:
            out["freeStyleDic"] = list(self.free_style_dic)
        if self.show_type is not None:
            out["showTypeId"] = self.show_type
        if self.quest_type is not None:
            out["typeId"] = self.quest_type
        if self.active_mode is not None:
            out["activeModeId"] = self.active_mode
        if self.main_quest_tag is not None:
            out["mainQuestTagId"] = self.main_quest_tag
        if self.show_red_point is not None:
            out["showRedPoint"] = self.show_red_point
        if self.repeatable is not None:
            out["repeatable"] = self.repeatable
        if self.suggest_track_out_of_order is not None:
            out["suggestTrackOutOfOrder"] = self.suggest_track_out_of_order
        if self.special_show_quest_id is not None:
            out["specialShowQuestId"] = self.special_show_quest_id
        if self.special_show_cond_id_list:
            out["specialShowCondIdList"] = list(self.special_show_cond_id_list)
        if self.special_show_reward_id:
            out["specialShowRewardId"] = list(self.special_show_reward_id)
        if self.suggest_track_main_quest_list:
            out["suggestTrackMainQuestList"] = list(self.suggest_track_main_quest_list)
        if self.reward_id_list:
            out["rewardIdList"] = list(self.reward_id_list)
        if self.talks:
            out["talks"] = list(self.talks)
        if self.action_config is not None:
            out["IACKBAAICMK"] = self.action_config
        out["quests"] = [x.to_dict() for x in self.quests]
        if self.unknown_fields:
            out["unknown"] = self.unknown_fields
        return out

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=2, sort_keys=True) + "\n"


# Names below are exact 7.1 mappings: native type IDs aligned against the pinned\n# Dimbreath 7.1 Quest JSON by mainId/subId/array position (71,051 entries, zero conflicts).
QUEST_CONTENT_NAMES = {
    2: "QUEST_CONTENT_COMPLETE_TALK",
    3: "QUEST_CONTENT_MONSTER_DIE",
    4: "QUEST_CONTENT_FINISH_PLOT",
    5: "QUEST_CONTENT_OBTAIN_ITEM",
    6: "QUEST_CONTENT_TRIGGER_FIRE",
    7: "QUEST_CONTENT_CLEAR_GROUP_MONSTER",
    8: "QUEST_CONTENT_NOT_FINISH_PLOT",
    9: "QUEST_CONTENT_ENTER_DUNGEON",
    10: "QUEST_CONTENT_ENTER_MY_WORLD",
    11: "QUEST_CONTENT_FINISH_DUNGEON",
    12: "QUEST_CONTENT_DESTROY_GADGET",
    13: "QUEST_CONTENT_OBTAIN_MATERIAL_WITH_SUBTYPE",
    17: "QUEST_CONTENT_ENTER_ROOM",
    18: "QUEST_CONTENT_GAME_TIME_TICK",
    19: "QUEST_CONTENT_FAIL_DUNGEON",
    20: "QUEST_CONTENT_LUA_NOTIFY",
    21: "QUEST_CONTENT_TEAM_DEAD",
    22: "QUEST_CONTENT_COMPLETE_ANY_TALK",
    23: "QUEST_CONTENT_UNLOCK_TRANS_POINT",
    24: "QUEST_CONTENT_ADD_QUEST_PROGRESS",
    25: "QUEST_CONTENT_INTERACT_GADGET",
    27: "QUEST_CONTENT_FINISH_ITEM_GIVING",
    107: "QUEST_CONTENT_SKILL",
    109: "QUEST_CONTENT_CITY_LEVEL_UP",
    111: "QUEST_CONTENT_ITEM_LESS_THAN",
    112: "QUEST_CONTENT_PLAYER_LEVEL_UP",
    119: "QUEST_CONTENT_QUEST_VAR_EQUAL",
    120: "QUEST_CONTENT_QUEST_VAR_GREATER",
    121: "QUEST_CONTENT_QUEST_VAR_LESS",
    122: "QUEST_CONTENT_OBTAIN_VARIOUS_ITEM",
    124: "QUEST_CONTENT_BARGAIN_SUCC",
    125: "QUEST_CONTENT_BARGAIN_FAIL",
    126: "QUEST_CONTENT_ITEM_LESS_THAN_BARGAIN",
    127: "QUEST_CONTENT_ACTIVITY_TRIGGER_FAILED",
    128: "QUEST_CONTENT_MAIN_COOP_ENTER_SAVE_POINT",
    129: "QUEST_CONTENT_ANY_MANUAL_TRANSPORT",
    130: "QUEST_CONTENT_USE_ITEM",
    131: "QUEST_CONTENT_MAIN_COOP_ENTER_ANY_SAVE_POINT",
    132: "QUEST_CONTENT_ENTER_MY_HOME_WORLD",
    133: "QUEST_CONTENT_ENTER_MY_WORLD_SCENE",
    134: "QUEST_CONTENT_TIME_VAR_GT_EQ",
    135: "QUEST_CONTENT_TIME_VAR_PASS_DAY",
    136: "QUEST_CONTENT_QUEST_STATE_EQUAL",
    137: "QUEST_CONTENT_QUEST_STATE_NOT_EQUAL",
    138: "QUEST_CONTENT_UNLOCKED_RECIPE",
    139: "QUEST_CONTENT_NOT_UNLOCKED_RECIPE",
    140: "QUEST_CONTENT_FISHING_SUCC",
    141: "QUEST_CONTENT_ENTER_ROGUE_DUNGEON",
    142: "QUEST_CONTENT_USE_WIDGET",
    145: "QUEST_CONTENT_CAPTURE_USE_MATERIAL_LIST",
    147: "QUEST_CONTENT_ENTER_VEHICLE",
    148: "QUEST_CONTENT_SCENE_LEVEL_TAG_EQ",
    149: "QUEST_CONTENT_LEAVE_SCENE",
    150: "QUEST_CONTENT_LEAVE_SCENE_RANGE",
    151: "QUEST_CONTENT_IRODORI_FINISH_FLOWER_COMBINATION",
    152: "QUEST_CONTENT_IRODORI_POETRY_REACH_MIN_PROGRESS",
    153: "QUEST_CONTENT_IRODORI_POETRY_FINISH_FILL_POETRY",
    154: "QUEST_CONTENT_ACTIVITY_TRIGGER_UPDATE",
    155: "QUEST_CONTENT_GADGET_STATE_CHANGE",
    156: "QUEST_CONTENT_LEAVE_SCENE_RANGE_AND_ROOM",
    157: "QUEST_CONTENT_GCG_LEVEL_WIN",
    158: "QUEST_CONTENT_AVATAR_RENAME_COMPLETE",
    159: "QUEST_CONTENT_GCG_GUIDE_PROGRESS",
    160: "QUEST_CONTENT_QUEST_GLOBAL_VAR_EQUAL",
    161: "QUEST_CONTENT_QUEST_GLOBAL_VAR_GREATER",
    162: "QUEST_CONTENT_QUEST_GLOBAL_VAR_LESS",
    163: "QUEST_CONTENT_ACHIEVEMENT_ISACHIEVED",
    164: "QUEST_CONTENT_EVENTS_ITEM_STATUS",
    165: "QUEST_CONTENT_ACHIEVEMENT_STATE_EQUAL",
    166: "QUEST_CONTENT_EXHIBITION_ACCUMULATE_GT_EQ",
    167: "QUEST_CONTENT_UNLOCK_ANY_TRANS_POINT",
    168: "QUEST_CONTENT_ITEM_NUM_EQUAL",
    169: "QUEST_CONTENT_ITEM_NUM_GREATER",
    170: "QUEST_CONTENT_ITEM_NUM_LESS",
    171: "QUEST_CONTENT_QUEST_VAR_NOT_EQUAL",
    172: "QUEST_CONTENT_QUEST_GLOBAL_VAR_NOT_EQUAL",
    173: "QUEST_CONTENT_SHOP_SELL_OUT",
    174: "QUEST_CONTENT_QUEST_CHECK_EQUAL",
    177: "QUEST_CONTENT_PRESENT_AT_SPECIFIC_SCENE",
    179: "QUEST_CONTENT_MISC_RENAME_COMPLETE",
    180: "QUEST_CONTENT_ENTER_FEATURE_TAG_VEHICLE",
    181: "QUEST_CONTENT_LEAVE_FEATURE_TAG_VEHICLE",
    182: "QUEST_CONTENT_LEAVE_VEHICLE",
    183: "QUEST_CONTENT_ABYSS_WAR_LEVEL_STATE_EQUAL",
    185: "QUEST_CONTENT_ABYSS_WAR_LIMIT_REIGON_STATE_EQUAL",
    186: "QUEST_CONTENT_PARENT_QUEST_STATE_EQUAL",
    188: "QUEST_CONTENT_FINISH_ANY_FOOD_COOK",
    189: "QUEST_CONTENT_TIME_VAR_PASS_REFRESH_POLICY",
    190: "QUEST_CONTENT_SCENERY_STATE_EQUAL",
    192: "QUEST_CONTENT_ACTIVITY_END",
    193: "QUEST_CONTENT_AVATAR_CAPTURE_ANIMAL",
    195: "QUEST_CONTENT_SPECIFIC_WIDGET_ATTACHED",
    196: "QUEST_CONTENT_CALL_PLAYER_TRAIN_IN_RANGE",
}

QUEST_EXEC_NAMES = {
    1: "QUEST_EXEC_DEL_PACK_ITEM",
    2: "QUEST_EXEC_UNLOCK_POINT",
    3: "QUEST_EXEC_UNLOCK_AREA",
    6: "QUEST_EXEC_CHANGE_AVATAR_ELEMET",
    7: "QUEST_EXEC_REFRESH_GROUP_MONSTER",
    8: "QUEST_EXEC_SET_IS_FLYABLE",
    9: "QUEST_EXEC_SET_IS_WEATHER_LOCKED",
    10: "QUEST_EXEC_SET_IS_GAME_TIME_LOCKED",
    12: "QUEST_EXEC_GRANT_TRIAL_AVATAR",
    14: "QUEST_EXEC_ROLLBACK_QUEST",
    15: "QUEST_EXEC_NOTIFY_GROUP_LUA",
    16: "QUEST_EXEC_SET_OPEN_STATE",
    17: "QUEST_EXEC_LOCK_POINT",
    18: "QUEST_EXEC_DEL_PACK_ITEM_BATCH",
    19: "QUEST_EXEC_REFRESH_GROUP_SUITE",
    20: "QUEST_EXEC_REMOVE_TRIAL_AVATAR",
    21: "QUEST_EXEC_SET_GAME_TIME",
    22: "QUEST_EXEC_SET_WEATHER_GADGET",
    23: "QUEST_EXEC_ADD_QUEST_PROGRESS",
    24: "QUEST_EXEC_NOTIFY_DAILY_TASK",
    27: "QUEST_EXEC_REFRESH_GROUP_SUITE_RANDOM",
    28: "QUEST_EXEC_ACTIVE_ITEM_GIVING",
    29: "QUEST_EXEC_DEL_ALL_SPECIFIC_PACK_ITEM",
    30: "QUEST_EXEC_ROLLBACK_PARENT_QUEST",
    31: "QUEST_EXEC_LOCK_AVATAR_TEAM",
    32: "QUEST_EXEC_UNLOCK_AVATAR_TEAM",
    33: "QUEST_EXEC_UPDATE_PARENT_QUEST_REWARD_INDEX",
    34: "QUEST_EXEC_SET_DAILY_TASK_VAR",
    35: "QUEST_EXEC_INC_DAILY_TASK_VAR",
    37: "QUEST_EXEC_ACTIVE_ACTIVITY_COND_STATE",
    38: "QUEST_EXEC_INACTIVE_ACTIVITY_COND_STATE",
    39: "QUEST_EXEC_ADD_CUR_AVATAR_ENERGY",
    42: "QUEST_EXEC_STOP_BARGAIN",
    43: "QUEST_EXEC_SET_QUEST_GLOBAL_VAR",
    44: "QUEST_EXEC_INC_QUEST_GLOBAL_VAR",
    46: "QUEST_EXEC_REGISTER_DYNAMIC_GROUP",
    47: "QUEST_EXEC_UNREGISTER_DYNAMIC_GROUP",
    48: "QUEST_EXEC_SET_QUEST_VAR",
    49: "QUEST_EXEC_INC_QUEST_VAR",
    50: "QUEST_EXEC_DEC_QUEST_VAR",
    51: "QUEST_EXEC_RANDOM_QUEST_VAR",
    54: "QUEST_EXEC_REGISTER_DYNAMIC_GROUP_ONLY",
    55: "QUEST_EXEC_CHANGE_SKILL_DEPOT",
    56: "QUEST_EXEC_ADD_SCENE_TAG",
    57: "QUEST_EXEC_DEL_SCENE_TAG",
    58: "QUEST_EXEC_INIT_TIME_VAR",
    59: "QUEST_EXEC_CLEAR_TIME_VAR",
    60: "QUEST_EXEC_MODIFY_CLIMATE_AREA",
    61: "QUEST_EXEC_GRANT_TRIAL_AVATAR_AND_LOCK_TEAM",
    62: "QUEST_EXEC_CHANGE_MAP_AREA_STATE",
    63: "QUEST_EXEC_DEACTIVE_ITEM_GIVING",
    64: "QUEST_EXEC_CHANGE_SCENE_LEVEL_TAG",
    65: "QUEST_EXEC_UNLOCK_PLAYER_WORLD_SCENE",
    68: "QUEST_EXEC_MODIFY_WEATHER_AREA",
    69: "QUEST_EXEC_MODIFY_ARANARA_COLLECTION_STATE",
    71: "QUEST_EXEC_REFRESH_WORLD_QUEST_FLOW_GROUP_SUITE",
    72: "QUEST_EXEC_HIDE_SCENE_POINT",
    73: "QUEST_EXEC_UNHIDE_SCENE_POINT",
    75: "QUEST_EXEC_RANDOM_CLOSED_QUEST_VAR",
    76: "QUEST_EXEC_OPTIONAL_REVIVAL_TEAM",
    77: "QUEST_EXEC_LOCK_AVATAR_TEAM_V2",
    78: "QUEST_EXEC_UNLOCK_AVATAR_TEAM_V2",
    79: "QUEST_EXEC_GRANT_TRIAL_AVATAR_BATCH_AND_LOCK_TEAM_V2",
    80: "QUEST_EXEC_GRANT_TRIAL_AVATAR_AND_LOCK_TEAM_V2",
    81: "QUEST_EXEC_SET_IS_GAME_TIME_LOCKED_V2",
    82: "QUEST_EXEC_CLEAR_VEHICLE",
    83: "QUEST_EXEC_SHOW_MAP_LAYER_GROUP",
    84: "QUEST_EXEC_SET_MAP_LAYER_UNLOCK_STATE",
    86: "QUEST_EXEC_SET_IS_DIVEABLE",
    87: "QUEST_EXEC_UNLOCK_EVENTS_ITEM",
    92: "QUEST_EXEC_LOCK_MIRROR_AVATAR_TEAM",
    93: "QUEST_EXEC_UNLOCK_MIRROR_AVATAR_TEAM",
    94: "QUEST_EXEC_ADD_ALCHEMY_SIM_CROP",
    97: "QUEST_EXEC_SET_LIMIT_REGION_STATE",
    100: "QUEST_EXEC_DEL_SCENE_TEMP_RES",
    101: "QUEST_EXEC_ENTER_VEHICLE",
    102: "QUEST_EXEC_EXIT_VEHICLE",
    103: "QUEST_EXEC_CLEAR_FEATURE_TAG_VEHICLE",
    104: "QUEST_EXEC_UNIQUE_RANDOM_QUEST_VAR",
    105: "QUEST_EXEC_SET_ABYSS_WAR_LEVEL_STATE",
    106: "QUEST_EXEC_SET_ABYSS_WAR_LIMIT_REGION_STATE",
    109: "QUEST_EXEC_FINISH_ABYSS_WAR_ACCOUNT_PERFORMANCE",
    112: "QUEST_EXEC_BATCH_SET_QUEST_VAR",
    113: "QUEST_EXEC_ACTIVATE_PERSISTENT_DUNGEON_SCENE",
    114: "QUEST_EXEC_CLEAR_PERSISTENT_DUNGEON_SCENE",
    115: "QUEST_EXEC_CREATE_VEHICLE",
    116: "QUEST_EXEC_ADD_ABYSS_WAR_ACCOUNT_DATA",
    118: "QUEST_EXEC_SET_OPEN_STATE_V2",
    119: "QUEST_EXEC_ACTIVE_DAMSELETTE_FREE_MOON_PHASE",
    121: "QUEST_EXEC_ACTIVATE_SCENERY",
    122: "QUEST_EXEC_CHANGE_AVATAR_COSTUME",
    123: "QUEST_EXEC_BATCH_SET_OPEN_STATE",
    130: "QUEST_EXEC_UNLOCK_SCENE_MP",
    131: "QUEST_EXEC_MODIFY_DUNGEON_EXIT_POINT",
    132: "QUEST_EXEC_ENTER_AQUARIUM_DIVING_DUNGEON",
    133: "QUEST_EXEC_SET_SCENE_VAR",
    134: "QUEST_EXEC_SET_TPS_GLASSES_CHAT_PROGRESS",
    135: "QUEST_EXEC_UNLOCK_TPS_AVATAR",
    137: "QUEST_EXEC_UNLOCK_DUNGEON_MIRROR_AVATAR_TEAM",
    138: "QUEST_EXEC_CHANGE_PLAYER_TRAIN_FIGURE_SGV",
}


class _Reader:
    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0

    def take(self, count: int) -> bytes:
        end = self.pos + count
        if count < 0 or end > len(self.data):
            raise QuestBinParseError(
                f"truncated Quest BinOutput at 0x{self.pos:X}: need {count} bytes, "
                f"have {len(self.data) - self.pos}"
            )
        out = self.data[self.pos:end]
        self.pos = end
        return out

    def u8(self) -> int:
        return self.take(1)[0]

    def u16(self) -> int:
        return struct.unpack("<H", self.take(2))[0]

    def u32(self) -> int:
        return struct.unpack("<I", self.take(4))[0]

    def u64(self) -> int:
        return struct.unpack("<Q", self.take(8))[0]


def _bits(value: int, width: int) -> tuple[int, ...]:
    return tuple(bit for bit in range(width) if value & (1 << bit))


def _add16(value: int, constant: int) -> int:
    return (value + constant) & _U16


def _add32(value: int, constant: int) -> int:
    return (value + constant) & _U32


def _decode_chunks(data: bytes, key: int, op: str) -> bytes:
    out = bytearray()
    for offset in range(0, len(data), 8):
        chunk = data[offset : offset + 8]
        value = int.from_bytes(chunk, "little")
        if op == "xor":
            value ^= key
        elif op == "add":
            value = (value + key) & _U64
        else:
            raise AssertionError(op)
        out += value.to_bytes(8, "little")[: len(chunk)]
    return bytes(out)


def _native_string(
    reader: _Reader,
    length_decoder: Callable[[int], int],
    *,
    key: int | None = None,
    op: str | None = None,
) -> str | dict[str, Any]:
    length = length_decoder(reader.u16())
    encoded = reader.take(length)
    decoded = encoded if key is None else _decode_chunks(encoded, key, op or "xor")
    try:
        return decoded.decode("utf-8")
    except UnicodeDecodeError:
        # Preserve undecoded official bytes rather than guessing their meaning.
        return {"rawHex": encoded.hex(), "length": length}


def _read_string_array(
    reader: _Reader,
    count_decoder: Callable[[int], int],
    length_decoder: Callable[[int], int],
    *,
    key: int,
    op: str,
) -> list[str | dict[str, Any]]:
    count = count_decoder(reader.u32())
    if count > 100_000:
        raise QuestBinParseError(f"implausible native string-array count {count}")
    return [
        _native_string(reader, length_decoder, key=key, op=op)
        for _ in range(count)
    ]


def _parse_exec(reader: _Reader) -> QuestExec:
    start = reader.pos
    mask = (reader.u8() + 0x44) & 0xFF
    unsupported = mask & ~((1 << 5) | (1 << 2))
    if unsupported:
        raise QuestBinParseError(
            f"unsupported QuestExec presence bits {_bits(unsupported, 8)} at 0x{start:X}"
        )

    params: tuple[str, ...] = ()
    if mask & (1 << 5):
        raw_values = _read_string_array(
            reader,
            lambda raw: (_add32(raw, 0x8DAF6E6F) ^ 0x745258F8) & _U32,
            lambda raw: raw ^ 0xDEA7,
            key=0x0B61F31AFE80DEA7,
            op="add",
        )
        if not all(isinstance(value, str) for value in raw_values):
            raise QuestBinParseError(f"QuestExec contains undecodable string at 0x{start:X}")
        params = tuple(raw_values)  # type: ignore[arg-type]

    type_id: int | None = None
    if mask & (1 << 2):
        type_id = _add32(reader.u32(), 0x203BCD7F)
    if type_id is None:
        raise QuestBinParseError(f"QuestExec has no QuestExecType at 0x{start:X}")
    return QuestExec(type_id=type_id, params=params)


def _parse_exec_array(reader: _Reader) -> tuple[QuestExec, ...]:
    start = reader.pos
    count = _add32(reader.u32(), 0xB0F7C9F4)
    if count > 100_000:
        raise QuestBinParseError(f"implausible QuestExec[] count {count} at 0x{start:X}")
    return tuple(_parse_exec(reader) for _ in range(count))


def _parse_content(reader: _Reader) -> QuestContent:
    start = reader.pos
    mask = (reader.u8() + 0x8F) & 0xFF
    supported = (1 << 1) | (1 << 0) | (1 << 7) | (1 << 4)
    unsupported = mask & ~supported
    if unsupported:
        raise QuestBinParseError(
            f"unsupported QuestContent presence bits {_bits(unsupported, 8)} at 0x{start:X}"
        )

    string_param: str | None = None
    if mask & (1 << 1):
        value = _native_string(
            reader,
            lambda raw: _add16(raw, 0x8555),
            key=0xA4D839D96CBB8555,
            op="xor",
        )
        if not isinstance(value, str):
            raise QuestBinParseError(f"QuestContent string is not UTF-8 at 0x{start:X}")
        string_param = value

    type_id: int | None = None
    if mask & (1 << 0):
        type_id = _add32(reader.u32() ^ 0xE9FA3068, 0x31C7C23E)

    params: tuple[int, ...] = ()
    if mask & (1 << 7):
        count = _add32(reader.u32(), 0xC867B940)
        if count > 100_000:
            raise QuestBinParseError(f"implausible QuestContent param count {count}")
        params = tuple(_add32(reader.u32(), 0x78B6DDFA) for _ in range(count))

    value: int | None = None
    if mask & (1 << 4):
        value = reader.u32() ^ 0x06723F87

    if type_id is None:
        raise QuestBinParseError(f"QuestContent has no QuestContentType at 0x{start:X}")
    return QuestContent(type_id=type_id, params=params, string_param=string_param, value=value)


def _parse_content_array(reader: _Reader) -> tuple[QuestContent, ...]:
    start = reader.pos
    count = (_add32(reader.u32(), 0x9278C6C1) ^ 0x415C14AA) & _U32
    if count > 100_000:
        raise QuestBinParseError(f"implausible QuestContent[] count {count} at 0x{start:X}")
    return tuple(_parse_content(reader) for _ in range(count))


_OOP_TESTED_BITS = {
    1, 2, 3, 4, 5, 6, 7, 8, 13, 15, 20, 21, 24, 25, 26, 28, 30,
}


def _parse_oop(reader: _Reader) -> dict[str, Any]:
    """Decode OOPFBIEAILL using the exact 7.1 native reader order.

    The transformed mask may contain bits the client never tests. Those bits do not
    consume wire bytes and therefore are not treated as unknown fields.
    """
    start = reader.pos
    raw_mask = reader.u32()
    mask = (raw_mask - 0x5816EEF2) & _U32
    active = set(_bits(mask, 32))

    out: dict[str, Any] = {}
    if 21 in active:
        out["bit21"] = reader.u32() ^ 0xB1CEAA21
    if 30 in active:
        out["bit30"] = _native_string(
            reader,
            lambda raw: _add16(raw, -0x06DC) ^ 0x3684,
            key=0x53293684354DF924,
            op="xor",
        )
    if 4 in active:
        out["bit4"] = _read_string_array(
            reader,
            lambda raw: (_add32(raw, 0x0444371E) ^ 0x011A3440) & _U32,
            lambda raw: raw ^ 0xD538,
            key=0xE575DFB19A2DD538,
            op="add",
        )
    if 7 in active:
        out["bit7"] = reader.u32() ^ 0xF2E446C9
    if 6 in active:
        out["bit6"] = reader.u32() ^ 0x01836AF8
    if 25 in active:
        out["bit25"] = (_add32(reader.u32(), 0xBB4C1A74) ^ 0xC4348988) & _U32
    if 26 in active:
        out["bit26"] = reader.u32() ^ 0xDB7D7792
    if 2 in active:
        out["bit2"] = _add32(reader.u32(), 0x45C609CE)
    if 1 in active:
        out["bit1"] = reader.u32() ^ 0xD0F3A0A3
    if 24 in active:
        out["bit24"] = reader.u32() ^ 0xCF1202E3
    if 13 in active:
        out["bit13"] = _native_string(
            reader,
            lambda raw: _add16(raw, 0x72FE),
            key=0x6F1ACF7F7A3872FE,
            op="xor",
        )
    if 28 in active:
        out["bit28"] = _add32(reader.u32(), 0xC3BE4A3E)
    if 3 in active:
        out["bit3"] = reader.u32() ^ 0xBB23DA81
    if 20 in active:
        out["bit20"] = _add32(reader.u32(), 0xDD1C8CBE)

    # Native OOP checks raw-mask bit0 separately from the transformed mask.
    if raw_mask & 1:
        out["rawBit0"] = _add32(reader.u32(), 0x2821917D)

    if 15 in active:
        out["bit15"] = reader.u32() ^ 0xEDE96EF8
    if 8 in active:
        out["bit8"] = reader.u32() ^ 0xB5A11D8E
    if 5 in active:
        out["bit5"] = reader.u32() ^ 0xD87113B8

    # Keep a diagnostic trace of transformed bits that the native reader ignores.
    ignored = sorted(active - _OOP_TESTED_BITS)
    if ignored:
        out["ignoredMaskBits"] = ignored
    return out


def _parse_kph(reader: _Reader) -> dict[str, Any]:
    mask = reader.u8()
    out: dict[str, Any] = {"mask": mask}

    # This native reader has mixed mask polarity. bit2 means read the first string;
    # bit6/bit7 mean use defaults, so their fields are read when the bits are clear.
    if mask & (1 << 2):
        out["bit2"] = _native_string(
            reader,
            lambda raw: raw ^ 0x78AE,
            key=0xE01441134DDA78AE,
            op="add",
        )
    if not mask & (1 << 6):
        out["bit6"] = reader.u32() ^ 0x3F857DF8
    if not mask & (1 << 7):
        out["bit7"] = _native_string(
            reader,
            lambda raw: raw ^ 0xEFA9,
            key=0x2C320EC05CBCEFA9,
            op="add",
        )

    ignored = [bit for bit in _bits(mask, 8) if bit not in (2, 6, 7)]
    if ignored:
        out["ignoredMaskBits"] = ignored
    return out



_FBKM_TESTED_BITS = {
    4, 6, 7, 8, 11, 12, 14, 15, 16, 17, 18, 21, 22, 23, 25, 26,
    27, 28, 29, 31, 32, 33, 35, 36, 37, 39, 40, 41, 42, 43, 44,
    45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 57, 59, 60, 61, 63,
}
_FBKM_SUPPORTED_BITS = _FBKM_TESTED_BITS


def _parse_dialogue_condition(reader: _Reader) -> dict[str, Any]:
    """Decode the native FBKM condition element reader at 0x0AB280B0."""

    start = reader.pos
    raw_mask = reader.u8()
    mask = (raw_mask + 0xA2) & 0xFF
    active = set(_bits(mask, 8))

    out: dict[str, Any] = {"rawMask": raw_mask}

    if 6 in active:
        count = _add32(reader.u32() ^ 0x80D7C50F, 0x64DD1E86)
        if count > 100_000:
            raise QuestBinParseError(
                f"implausible FBKMIOOJCKG condition param count {count} at 0x{start:X}"
            )
        out["params"] = [
            _native_string(
                reader,
                lambda raw: _add16(raw, 0xC1D7),
                key=0x6BF9DA79B3C8C1D7,
                op="xor",
            )
            for _ in range(count)
        ]

    if 2 in active:
        out["field2U32"] = _add32(reader.u32() ^ 0x4154E56A, 0xF28B58B8)

    return out


def _read_fbkm_u32_array(
    reader: _Reader,
    *,
    count_decoder: Callable[[int], int],
    value_decoder: Callable[[int], int],
    label: str,
) -> list[int]:
    count = count_decoder(reader.u32()) & _U32
    if count > 100_000:
        raise QuestBinParseError(f"implausible FBKMIOOJCKG {label} count {count}")
    return [value_decoder(reader.u32()) & _U32 for _ in range(count)]


def _parse_fbkm_bit48_element(reader: _Reader) -> dict[str, Any]:
    """Decode the native FBKM bit48 element reader at 0x0ACDEAF0."""

    raw_mask = reader.u8()
    active = set(_bits(raw_mask, 8))
    out: dict[str, Any] = {"rawMask": raw_mask}

    if 4 in active:
        out["bit4"] = reader.u32() ^ 0xAE4299CD
    if 7 in active:
        out["bit7Strings"] = _read_string_array(
            reader,
            lambda raw: _add32(raw, 0xC92274DF),
            lambda raw: raw ^ 0x341C,
            key=0xA1DC317923F5341C,
            op="add",
        )

    ignored = sorted(active - {4, 7})
    if ignored:
        out["ignoredMaskBits"] = ignored
    return out


def _parse_fbkm_bit48_array(reader: _Reader) -> list[dict[str, Any]]:
    """Decode the native FBKM bit48 array wrapper at 0x0ACDE990."""

    count = _add32(reader.u32(), 0x07C17281)
    if count > 100_000:
        raise QuestBinParseError(f"implausible FBKMIOOJCKG bit48 count {count}")
    return [_parse_fbkm_bit48_element(reader) for _ in range(count)]


def _parse_dialogue_record(reader: _Reader) -> dict[str, Any]:
    """Decode one native FBKMIOOJCKG record using the 7.1 reader order.

    The reader transforms the 64-bit raw mask with +0xDECF26B4. Only fields
    independently proven from the native reader are exposed. Reserved mask bits
    that the reader never tests do not consume bytes.
    """
    start = reader.pos
    raw_mask = reader.u64()
    mask = (raw_mask + 0xDECF26B4) & _U64
    active = set(_bits(mask, 64))

    unsupported = (active & _FBKM_TESTED_BITS) - _FBKM_SUPPORTED_BITS
    if unsupported:
        raise QuestBinParseError(
            f"unsupported FBKMIOOJCKG presence bits {sorted(unsupported)} at 0x{start:X}"
        )

    out: dict[str, Any] = {"rawMask": f"0x{raw_mask:016X}"}

    # Exact native field order from FBKMIOOJCKG.GMENPOPMKAA @ 0x10E9EB50.
    if 57 in active:
        out["bit57"] = _read_fbkm_u32_array(
            reader,
            count_decoder=lambda raw: raw ^ 0x18B7E2BC,
            value_decoder=lambda raw: raw ^ 0xEE6C5ED9,
            label="bit57",
        )
    if 14 in active:
        out["field0U32Array"] = _read_fbkm_u32_array(
            reader,
            count_decoder=lambda raw: _add32(raw, 0xF7FCA63F),
            value_decoder=lambda raw: raw ^ 0x4FFD8FA0,
            label="bit14",
        )
    if 6 in active:
        out["bit6"] = reader.u8() != 0xE5
    if 41 in active:
        out["bit41"] = _read_fbkm_u32_array(
            reader,
            count_decoder=lambda raw: _add32(raw, 0xD6DDCF83),
            value_decoder=lambda raw: _add32(raw, 0x549D2AB7),
            label="bit41",
        )
    if 63 in active:
        out["bit63"] = reader.u8() != 0x57
    if 27 in active:
        out["bit27"] = reader.u8() != 0xC5
    if 36 in active:
        out["field1U64"] = reader.u64() ^ 0x36A19096
    if 43 in active:
        out["bit43"] = reader.u8() != 0xA8
    if 35 in active:
        out["bit35"] = reader.u32() ^ 0x7D2CB2EF
    if 49 in active:
        out["field2U32"] = _add32(reader.u32(), 0xAA33055D)
    if 54 in active:
        count = _add32(reader.u32(), 0x16413C4C)
        if count > 100_000:
            raise QuestBinParseError(
                f"implausible FBKMIOOJCKG condition count {count} at 0x{start:X}"
            )
        out["field3Conditions"] = [_parse_dialogue_condition(reader) for _ in range(count)]
    if 60 in active:
        out["bit60"] = reader.u32() ^ 0x223E04E1
    if 4 in active:
        out["field4String"] = _native_string(
            reader,
            lambda raw: raw ^ 0x04BA,
            key=0xDBDADBFD711604BA,
            op="add",
        )
    if 40 in active:
        out["bit40"] = reader.u8() != 0x9E
    if 47 in active:
        out["field5String"] = _native_string(
            reader,
            lambda raw: raw ^ 0x5169,
            key=0xBE5D4D72A5255169,
            op="add",
        )
    if 15 in active:
        out["bit15"] = reader.u8() != 0x5D
    if 51 in active:
        out["bit51"] = _read_fbkm_u32_array(
            reader,
            count_decoder=lambda raw: _add32(raw, 0xBA61F062),
            value_decoder=lambda raw: _add32(raw, 0x73B6A9BA),
            label="bit51",
        )
    if 42 in active:
        out["bit42"] = _read_fbkm_u32_array(
            reader,
            count_decoder=lambda raw: raw ^ 0xF1DECF2A,
            value_decoder=lambda raw: _add32(raw, 0x1D64053C),
            label="bit42",
        )
    if 31 in active:
        out["bit31"] = reader.u8() != 0x69
    if 55 in active:
        out["bit55"] = reader.u8() != 0xFE
    if 37 in active:
        out["bit37"] = _read_fbkm_u32_array(
            reader,
            count_decoder=lambda raw: raw ^ 0x38650336,
            value_decoder=lambda raw: _add32(raw ^ 0xFB128693, 0x98D1CB7D),
            label="bit37",
        )
    if 45 in active:
        out["bit45"] = reader.u8() != 0xFF
    if 18 in active:
        out["bit18"] = reader.u32() ^ 0xD7A9CE43
    if 52 in active:
        out["bit52"] = _read_fbkm_u32_array(
            reader,
            count_decoder=lambda raw: _add32(raw, 0xE7243AC6),
            value_decoder=lambda raw: raw ^ 0xB7D71B0B,
            label="bit52",
        )
    if 7 in active:
        out["bit7"] = reader.u32() ^ 0x0ECE3703
    if 29 in active:
        out["bit29"] = reader.u32() ^ 0x3A7BDD8C
    if 53 in active:
        out["bit53"] = _read_fbkm_u32_array(
            reader,
            count_decoder=lambda raw: _add32(raw, 0x829D7F20),
            value_decoder=lambda raw: (_add32(raw, 0x54599859) ^ 0xA5C729AF),
            label="bit53",
        )
    if 33 in active:
        out["bit33"] = _read_fbkm_u32_array(
            reader,
            count_decoder=lambda raw: raw ^ 0xC1A1A855,
            value_decoder=lambda raw: raw ^ 0xC6B4BC7A,
            label="bit33",
        )
    if 8 in active:
        out["bit8"] = reader.u8() != 0x0F
    if 21 in active:
        out["bit21"] = reader.u32() ^ 0xF4C6CA5A
    if 61 in active:
        out["bit61"] = reader.u8() != 0x10
    if 12 in active:
        out["bit12"] = reader.u8() != 0x0A
    if 48 in active:
        out["bit48"] = _parse_fbkm_bit48_array(reader)
    if 22 in active:
        value = reader.u32() ^ 0x8EC725F6
        out["field6U32"] = value
        out["questId"] = value
    if 44 in active:
        out["bit44"] = reader.u8() != 0x64
    if 46 in active:
        out["field7U32"] = _add32(reader.u32(), 0xC61D2505)
    if 59 in active:
        out["bit59"] = reader.u32() ^ 0xF137EB4C
    if 17 in active:
        out["bit17"] = reader.u32() ^ 0x381B8F7E
    if 23 in active:
        out["bit23"] = _read_fbkm_u32_array(
            reader,
            count_decoder=lambda raw: raw ^ 0x0DFF51CB,
            value_decoder=lambda raw: raw ^ 0xCA7CD165,
            label="bit23",
        )
    if 50 in active:
        value = reader.u32() ^ 0xE858B9A1
        out["field8U32"] = value
        out["id"] = value

    # The native reader checks raw-mask bit 1 separately from the transformed mask.
    if raw_mask & (1 << 1):
        out["rawBit1Strings"] = _read_string_array(
            reader,
            lambda raw: _add32(raw, 0x3A2271F6),
            lambda raw: raw ^ 0x2273,
            key=0x8BB6FAA197782273,
            op="add",
        )

    if 16 in active:
        out["bit16"] = _add32(reader.u32() ^ 0x11FA436C, 0x0ABA7E75)
    if 39 in active:
        out["bit39"] = reader.u8() != 0x79
    if 28 in active:
        out["bit28"] = _add32(reader.u32(), 0x8EDB656F)
    if 26 in active:
        out["field9U32"] = _add32(reader.u32(), 0x1EA26BBB)
    if 32 in active:
        out["bit32"] = reader.u8() != 0x0C
    if 11 in active:
        out["bit11"] = reader.u8() != 0xF0
    if 25 in active:
        out["bit25"] = _read_fbkm_u32_array(
            reader,
            count_decoder=lambda raw: (_add32(raw, 0xAFCD1D20) ^ 0x828554EE),
            value_decoder=lambda raw: _add32(raw, 0x19BC9086),
            label="bit25",
        )

    return out


def _parse_dialogue_array(reader: _Reader) -> list[dict[str, Any]]:
    start = reader.pos
    raw_count = reader.u32()
    count = (_add32(raw_count, 0x6EBD3446) ^ 0xF54F810A) & _U32
    if count > 100_000:
        raise QuestBinParseError(
            f"implausible FBKMIOOJCKG[] count {count} at 0x{start:X}"
        )
    return [_parse_dialogue_record(reader) for _ in range(count)]


def _parse_row_bit6_u32_array(reader: _Reader) -> list[int]:
    count = reader.u32() ^ 0xA8148251
    if count > 100_000:
        raise QuestBinParseError(f"implausible LAIMPNDEFCL bit6 count {count}")
    return [reader.u32() ^ 0xA54AB96F for _ in range(count)]


def _parse_row_bit31_u32_array(reader: _Reader) -> list[int]:
    count = (_add32(reader.u32(), 0x878CF5D0) ^ 0x4051665B) & _U32
    if count > 100_000:
        raise QuestBinParseError(f"implausible LAIMPNDEFCL bit31 count {count}")
    return [
        (_add32(reader.u32(), 0xF27104B8) ^ 0x0BBC22AB) & _U32
        for _ in range(count)
    ]


def _parse_row_bit61_u32_array(reader: _Reader) -> list[int]:
    count = _add32(reader.u32() ^ 0xDFED35B0, 0x531C2D72)
    if count > 100_000:
        raise QuestBinParseError(f"implausible LAIMPNDEFCL bit61 count {count}")
    return [
        (_add32(reader.u32(), 0x0FBADB4A) ^ 0x71A8931C) & _U32
        for _ in range(count)
    ]

_ROW_SUPPORTED_BITS = {
    0, 3, 5, 6, 7, 10, 11, 12, 17, 19, 21, 22, 23, 25, 26, 31, 33, 34,
    35, 36, 38, 39, 41, 42, 46, 48, 51, 52, 53, 55, 56, 61, 62,
}


def _parse_row(reader: _Reader) -> QuestRow:
    start = reader.pos
    raw_mask = reader.u64()
    mask = (raw_mask + 0x2244ECE7) & _U64
    active = set(_bits(mask, 64))
    unsupported = active - _ROW_SUPPORTED_BITS
    if unsupported:
        raise QuestBinParseError(
            f"unsupported LAIMPNDEFCL bits {sorted(unsupported)} at 0x{start:X}"
        )

    fail_exec: tuple[QuestExec, ...] = ()
    fail_cond: tuple[QuestContent, ...] = ()
    finish_cond: tuple[QuestContent, ...] = ()
    finish_exec: tuple[QuestExec, ...] = ()
    main_id = sub_id = order = None
    desc_text_map_hash = None
    is_mp_block = is_rewind = finish_parent = None
    show_type = show_guide = ban_type = None
    sub_id_set = step_desc_text_map_hash = fail_parent_show = guide_tips_text_map_hash = None
    guide: dict[str, Any] | None = None
    npc_ids: tuple[int, ...] = ()
    exclusive_place_list: tuple[int, ...] = ()
    unknown: dict[str, Any] = {}

    # Exact 7.1 LAIMPNDEFCL reader order, not field-offset or sample-offset order.
    if 56 in active:
        finish_exec = _parse_exec_array(reader)
    if 36 in active:
        unknown["IHOOIFBLPJK"] = _add32(reader.u32(), 0xD3B00C66)
    if 5 in active:
        sub_id_set = _add32(reader.u32(), 0x191BB9F3)
    if 41 in active:
        is_mp_block = reader.u8() != 0x18
    if 22 in active:
        show_type = reader.u32() ^ 0x7C9371BD
    if 17 in active:
        show_guide = reader.u32() ^ 0x491C364E
    if 46 in active:
        unknown["EOFPICJEHLP"] = _add32(reader.u32(), 0xB5F93568) ^ 0xBCB94817
    if 34 in active:
        guide = _parse_oop(reader)
    if 38 in active:
        unknown["FJDKHGMJOPL"] = reader.u32() ^ 0x8FE7A26B
    if 19 in active:
        sub_id = reader.u32() ^ 0xAB3097F8
    if 21 in active:
        unknown["LBEFPHGELAN"] = reader.u8() != 0x63
    if 3 in active:
        desc_text_map_hash = reader.u32() ^ 0xB4EBB7D3
    if 10 in active:
        unknown["DMCMNPLMCKL"] = reader.u32() ^ 0x011CF6ED
    if 51 in active:
        fail_cond = _parse_content_array(reader)
    if 52 in active:
        fail_parent_show = reader.u32() ^ 0x792B3478
    if 7 in active:
        guide_tips_text_map_hash = reader.u32() ^ 0xDE74075F
    if 39 in active:
        unknown["EINOPNJGDNM"] = _native_string(
            reader,
            lambda raw: _add16(raw, 0x6275),
            key=0xCAB6E5555D466275,
            op="xor",
        )
    if 33 in active:
        unknown["DABNIJGHAPJ"] = _add32(reader.u32(), 0x4B39F4CC) ^ 0xC08A4FDA
    if 25 in active:
        unknown["HJFALMFICOM"] = _native_string(
            reader,
            lambda raw: _add16(raw, 0x997F),
            key=0xF99BB614A15B997F,
            op="xor",
        )
    if 0 in active:
        order = _add32(reader.u32(), 0x1B56F89A)
    if 6 in active:
        unknown["JFCJBBCEDGD"] = _parse_row_bit6_u32_array(reader)
    if 55 in active:
        fail_exec = _parse_exec_array(reader)
    if 35 in active:
        finish_cond = _parse_content_array(reader)
    if 53 in active:
        step_desc_text_map_hash = _add32(reader.u32(), 0xA6768BF5)
    if 62 in active:
        finish_parent = reader.u8() != 0xE6
    if 48 in active:
        is_rewind = reader.u8() != 0x0D
    if 11 in active:
        unknown["FABHGLLGFHN"] = reader.u32() ^ 0x5E79B226
    if 12 in active:
        main_id = _add32(reader.u32(), 0x076F8836)
    if 61 in active:
        npc_ids = tuple(_parse_row_bit61_u32_array(reader))
    if 26 in active:
        unknown["BIHKOLLEDPE"] = _parse_kph(reader)
    if 42 in active:
        unknown["HJOFKFKBFCF"] = reader.u8() != 0xB0
    if 23 in active:
        ban_type = _add32(reader.u32(), 0x546D0AF3)
    if 31 in active:
        exclusive_place_list = tuple(_parse_row_bit31_u32_array(reader))

    return QuestRow(
        main_id=main_id,
        sub_id=sub_id,
        order=order,
        desc_text_map_hash=desc_text_map_hash,
        is_mp_block=is_mp_block,
        is_rewind=is_rewind,
        finish_parent=finish_parent,
        show_type=show_type,
        show_guide=show_guide,
        ban_type=ban_type,
        sub_id_set=sub_id_set,
        step_desc_text_map_hash=step_desc_text_map_hash,
        fail_parent_show=fail_parent_show,
        guide_tips_text_map_hash=guide_tips_text_map_hash,
        guide=guide,
        npc_ids=npc_ids,
        exclusive_place_list=exclusive_place_list,
        fail_exec=fail_exec,
        fail_cond=fail_cond,
        finish_cond=finish_cond,
        finish_exec=finish_exec,
        unknown_fields=unknown,
        presence_bits=tuple(sorted(active)),
        start=start,
        end=reader.pos,
    )


def _parse_row_array(reader: _Reader) -> tuple[QuestRow, ...]:
    start = reader.pos
    count = reader.u32() ^ 0xA74F0ACB
    if count > 100_000:
        raise QuestBinParseError(f"implausible LAIMPNDEFCL[] count {count} at 0x{start:X}")
    return tuple(_parse_row(reader) for _ in range(count))



_AFIO_BIT28_DIALOG_BITS = {
    2, 4, 5, 8, 9, 11, 12, 13, 15, 16, 18, 20, 23, 24, 25, 26, 28, 29, 30,
}


def _parse_afio_bit28_role(reader: _Reader) -> dict[str, Any]:
    """Decode the nested 7.1 dialog-role reader at RVA 0x0B647D90."""

    start = reader.pos
    raw_mask = reader.u8()
    mask = (raw_mask + 0x91) & 0xFF
    active = set(_bits(mask, 8))
    unsupported = active - {0, 5}
    if unsupported:
        raise QuestBinParseError(
            f"unsupported AFIO bit28 role bits {sorted(unsupported)} at 0x{start:X}"
        )

    out: dict[str, Any] = {"rawMask": raw_mask}
    if 5 in active:
        out["bit5"] = _native_string(
            reader,
            lambda raw: _add16(raw, 0xED0F),
            key=0x8C9FAFD3A11FED0F,
            op="xor",
        )
    if 0 in active:
        out["bit0"] = _add32(reader.u32(), 0x51D01F5A)
    return out


def _parse_afio_bit28_dialog(reader: _Reader) -> dict[str, Any]:
    """Decode one native AFIO bit28 dialog element at RVA 0x0F6F5F30."""

    start = reader.pos
    raw_mask = reader.u32()
    mask = _add32(raw_mask, 0x2BB57208)
    active = set(_bits(mask, 32))
    unsupported = active - _AFIO_BIT28_DIALOG_BITS
    if unsupported:
        raise QuestBinParseError(
            f"unsupported AFIO bit28 dialog bits {sorted(unsupported)} at 0x{start:X}"
        )

    out: dict[str, Any] = {"rawMask": f"0x{raw_mask:08X}"}

    # Exact native read order from the pinned 7.1 client.
    if 25 in active:
        out["bit25"] = _native_string(
            reader,
            lambda raw: raw ^ 0x01DE,
            key=0x807EDE33FF1E01DE,
            op="add",
        )
    if 12 in active:
        out["bit12"] = _native_string(
            reader,
            lambda raw: raw ^ 0x10C3,
            key=0x6D3B2A62782310C3,
            op="add",
        )
    if 16 in active:
        out["bit16"] = _native_string(
            reader,
            lambda raw: raw ^ 0x9677,
            key=0x7461F15B01599677,
            op="add",
        )
    if 18 in active:
        out["bit18"] = reader.u32() ^ 0xE8A42851
    if 20 in active:
        out["bit20"] = _native_string(
            reader,
            lambda raw: _add16(raw, 0xE0FD),
            key=0x4C78FAA2F6E6E0FD,
            op="xor",
        )

    # The native element reader checks raw-mask bit0 independently.
    if raw_mask & 1:
        out["rawBit0"] = _add32(reader.u32(), 0x0C4E164E)

    if 5 in active:
        out["bit5"] = _native_string(
            reader,
            lambda raw: _add16(raw, 0xC73E),
            key=0x44A229A9A0FDC73E,
            op="xor",
        )
    if 28 in active:
        out["bit28"] = _add32(reader.u32(), 0x19CAAE51) ^ 0x61CD831E
    if 9 in active:
        out["bit9"] = _parse_afio_bit28_role(reader)
    if 24 in active:
        out["bit24"] = _native_string(
            reader,
            lambda raw: _add16(raw, 0xEDDE),
            key=0xD1F383E06866EDDE,
            op="xor",
        )
    if 26 in active:
        out["bit26"] = _add32(reader.u32(), 0xD54A8F0C)
    if 15 in active:
        out["bit15"] = _add32(reader.u32() ^ 0xB49BD1F9, 0x5088A0F2)
    if 11 in active:
        out["bit11"] = reader.u32() ^ 0xB22C9400

    # Raw-mask bit2 is another independent native field gate.
    if raw_mask & (1 << 2):
        out["rawBit2"] = _add32(reader.u32() ^ 0xE7B0A418, 0xC5801D00)

    if 8 in active:
        count = reader.u32() ^ 0xEF65762F
        if count > 100_000:
            raise QuestBinParseError(
                f"implausible AFIO bit28 dialog bit8 count {count} at 0x{start:X}"
            )
        out["bit8"] = [reader.u32() ^ 0xA6C66ADD for _ in range(count)]
    if 29 in active:
        out["bit29"] = _add32(reader.u32(), 0xDBD53451)
    if 30 in active:
        out["bit30"] = _native_string(
            reader,
            lambda raw: raw ^ 0x6BC6,
            key=0xC41D63AD1BA86BC6,
            op="add",
        )
    if 13 in active:
        out["bit13"] = reader.u32() ^ 0x70B9C2C0
    if 23 in active:
        out["bit23"] = _native_string(
            reader,
            lambda raw: raw ^ 0x5CB1,
            key=0xA951CB8A687F5CB1,
            op="add",
        )
    if 4 in active:
        count = _add32(reader.u32(), 0xC346C2DD) ^ 0x695CFE12
        if count > 100_000:
            raise QuestBinParseError(
                f"implausible AFIO bit28 dialog bit4 count {count} at 0x{start:X}"
            )
        out["bit4"] = [_add32(reader.u32(), 0x6D0EB6EE) for _ in range(count)]

    return out


def _parse_afio_bit28_dialog_array(reader: _Reader) -> list[dict[str, Any]]:
    """Decode AFIO bit28's native dialog array wrapper at RVA 0x0F6F5DD0."""

    start = reader.pos
    count = reader.u32() ^ 0xE9578097
    if count > 100_000:
        raise QuestBinParseError(f"implausible AFIO bit28 dialog count {count} at 0x{start:X}")
    return [_parse_afio_bit28_dialog(reader) for _ in range(count)]


def _parse_progress_quest_condition(reader: _Reader) -> dict[str, Any]:
    """Decode one 7.1 Quest ProgressGuide condition (LLDOFLKNHLP)."""

    start = reader.pos
    raw_mask = reader.u8()
    mask = ((raw_mask ^ 0xBF) + 0xB1) & 0xFF
    out: dict[str, Any] = {"rawMask": raw_mask}

    if mask & 0x10:
        out["mainQuestId"] = reader.u32() ^ 0x9AC01F5B
    if mask & 0x40:
        out["typeId"] = _add32(reader.u32(), 0x614393C8)
    if mask & 0x04:
        count = reader.u32() ^ 0xF1A72BFF
        if count > 100_000:
            raise QuestBinParseError(
                f"implausible ProgressGuide condition param count {count} at 0x{start:X}"
            )
        out["param"] = [reader.u32() ^ 0x9A8E9EA3 for _ in range(count)]
    return out


def _parse_progress_condition_group(reader: _Reader) -> list[dict[str, Any]]:
    start = reader.pos
    count = reader.u32() ^ 0x72542D61
    if count > 100_000:
        raise QuestBinParseError(
            f"implausible ProgressGuide condition-group count {count} at 0x{start:X}"
        )
    out: list[dict[str, Any]] = []
    for _ in range(count):
        tag = reader.u8() ^ 0x18
        if tag not in (0, 1):
            raise QuestBinParseError(
                f"unsupported ProgressGuide condition tag {tag} at 0x{reader.pos - 1:X}"
            )
        item = _parse_progress_quest_condition(reader)
        item["tag"] = tag
        out.append(item)
    return out


def _parse_progress_condition_groups(reader: _Reader) -> list[list[dict[str, Any]]]:
    start = reader.pos
    count = reader.u32() ^ 0x2586746A
    if count > 100_000:
        raise QuestBinParseError(
            f"implausible ProgressGuide outer condition count {count} at 0x{start:X}"
        )
    return [_parse_progress_condition_group(reader) for _ in range(count)]


def _parse_progress_item_common(reader: _Reader) -> dict[str, Any]:
    """Decode the NCPLGNFFLDM base shared by 7.1 ProgressGuide items."""

    raw_mask = reader.u16()
    mask_a = raw_mask + 0x697F
    mask_b = mask_a ^ 0xA559
    out: dict[str, Any] = {"rawMask": raw_mask}

    if mask_a & 0x4000:
        out["ANHIDFLMIDL"] = reader.u8() != 0x96
    if mask_b & 0x10:
        out["AMOKIPEIIKM"] = reader.u8() != 0xD4

    # Native reader uses the enum default when bit15 is set; the wire value exists
    # only on the inverse branch.
    if not (mask_a & 0x8000):
        out["CDJOLFDMKGB"] = reader.u32() ^ 0xF9B10CF7

    if mask_a & 0x02:
        out["BKHGPAJHKAE"] = reader.u8() != 0x74
    if mask_b & 0x01:
        out["CHDOOKAJLDJId"] = reader.u32() ^ 0x6ED46E4C
    if mask_a & 0x0800:
        out["iconPath"] = _native_string(
            reader,
            lambda raw: raw ^ 0x6D6D,
            key=0x5B789C8E0C966D6D,
            op="add",
        )
    if mask_a & 0x0080:
        out["showCond"] = _parse_progress_condition_groups(reader)
    if mask_b & 0x0400:
        out["LACMLGKFILH"] = _parse_progress_condition_groups(reader)
    if mask_b & 0x2000:
        out["IIMAJMACDMB"] = reader.u32() ^ 0x8F4AC5B8
    return out


def _parse_progress_item_lnhd(reader: _Reader) -> dict[str, Any]:
    out = _parse_progress_item_common(reader)
    out["type"] = "LNHDPIPGOBL"
    raw_mask = reader.u8()
    mask = (raw_mask + 0x0D) & 0xFF
    out["subRawMask"] = raw_mask
    if mask & 0x10:
        out["GCDJDGAMBNG"] = _native_string(
            reader,
            lambda raw: raw ^ 0xC482,
            key=0xADEC7D8026D1C482,
            op="add",
        )
    return out


def _parse_progress_item_mfpo(reader: _Reader) -> dict[str, Any]:
    out = _parse_progress_item_common(reader)
    out["type"] = "MFPOBCHKOLD"
    raw_mask = reader.u8()
    out["subRawMask"] = raw_mask

    if raw_mask & 0x10:
        out["itemID"] = reader.u32() ^ 0x0AFA11FA
    if not (raw_mask & 0x80):
        out["OPDKLELMPIA"] = reader.u8() != 0x1E

    mask = raw_mask ^ 0xC7
    if mask & 0x02:
        out["BEDEKPMMIIK"] = _add32(reader.u32(), 0x17C1C9A8)
    if mask & 0x04:
        out["GCDJDGAMBNG"] = _native_string(
            reader,
            lambda raw: _add16(raw ^ 0xB8A8, 0xF1D1),
            key=0xAA25F1D1B1ADB8A8,
            op="add",
        )
    return out


def _parse_progress_items(reader: _Reader) -> list[dict[str, Any]]:
    start = reader.pos
    count = _add32(reader.u32(), 0xE9672AD5)
    if count > 100_000:
        raise QuestBinParseError(f"implausible ProgressGuide item count {count} at 0x{start:X}")

    out: list[dict[str, Any]] = []
    for _ in range(count):
        tag = reader.u8() ^ 0x77
        if tag == 3:
            item = _parse_progress_item_lnhd(reader)
        elif tag == 2:
            item = _parse_progress_item_mfpo(reader)
        else:
            raise QuestBinParseError(
                f"unsupported 7.1 ProgressGuide item tag {tag} at 0x{reader.pos - 1:X}"
            )
        item["tag"] = tag
        out.append(item)
    return out


def _parse_progress_guide(reader: _Reader) -> dict[str, Any]:
    """Decode one PAMGBICKEOA ProgressGuide value."""

    raw_mask = reader.u8()
    mask = raw_mask ^ 0xEC
    out: dict[str, Any] = {"rawMask": raw_mask}

    if mask & 0x40:
        out["JDOHEPFGICB"] = _native_string(
            reader,
            lambda raw: raw ^ 0xC481,
            key=0xACBBE958366BC481,
            op="add",
        )
    if mask & 0x20:
        out["LACMLGKFILH"] = _parse_progress_condition_groups(reader)
    if mask & 0x08:
        out["LKFNLHCLCNN"] = _native_string(
            reader,
            lambda raw: _add16(raw, 0x3954),
            key=0x33084B6DC92A3954,
            op="xor",
        )
    if mask & 0x80:
        out["guideID"] = _add32(reader.u32(), 0x1227A8FE)
    if mask & 0x10:
        out["items"] = _parse_progress_items(reader)
    if mask & 0x01:
        out["IPIANOIKKLC"] = _native_string(
            reader,
            lambda raw: _add16(raw, 0xF13C),
            key=0xE689BB71611CF13C,
            op="xor",
        )
    if mask & 0x02:
        out["BJFHABHMIHL"] = _native_string(
            reader,
            lambda raw: _add16(raw, 0x1815),
            key=0xAD7201BCFEA21815,
            op="xor",
        )
    return out


def _parse_afio_bit27_progress_guides(reader: _Reader) -> list[dict[str, Any]]:
    """Decode AFIO bit27's guideID -> PAMGBICKEOA table."""

    start = reader.pos
    count = _add32(reader.u32(), 0x0FD8A5C6)
    if count > 100_000:
        raise QuestBinParseError(f"implausible AFIO bit27 count {count} at 0x{start:X}")

    out: list[dict[str, Any]] = []
    for _ in range(count):
        key = _add32(reader.u32() ^ 0x4CC5150F, 0xF08BC7D8)
        out.append({"key": key, "value": _parse_progress_guide(reader)})
    return out


def _parse_afio_bit53_element(reader: _Reader) -> dict[str, Any]:
    """Decode one AFIO bit53 element from the exact 7.1 reader at RVA 0x0BE19C30."""

    raw_mask = reader.u8()
    out: dict[str, Any] = {"rawMask": raw_mask}
    if raw_mask & (1 << 5):
        # The native helper normalizes this enum after the wire transform. Preserve the
        # transformed numeric value until the enum identity is independently named.
        out["bit5"] = _add32(reader.u32(), 0xBF88F35A)
    if raw_mask & 1:
        out["bit0"] = _add32(reader.u32(), 0x023A2E70)
    return out


def _parse_afio_bit53_array(reader: _Reader) -> list[dict[str, Any]]:
    """Decode AFIO bit53's native object array wrapper at RVA 0x0BE19DD0."""

    count = (_add32(reader.u32(), 0xEA3AAA5F) ^ 0xB715D28E) & _U32
    if count > 100_000:
        raise QuestBinParseError(f"implausible AFIO bit53 count {count}")
    return [_parse_afio_bit53_element(reader) for _ in range(count)]


def _parse_afio_bit26_u32_array(reader: _Reader) -> list[int]:
    """Decode AFIO bit26's native uint32 array from the exact root reader."""

    count = _add32(reader.u32(), 0xE4B9416C)
    if count > 100_000:
        raise QuestBinParseError(f"implausible AFIO bit26 count {count}")
    return [_add32(reader.u32(), 0xA1E55B52) for _ in range(count)]


def _parse_afio_bit56_map(reader: _Reader) -> list[dict[str, Any]]:
    """Decode the AFIO bit56 native key -> uint32[] table.

    The client materializes this wire shape as a managed dictionary. Keep a list of
    entries here so the decoded object preserves exact serialized entry order instead
    of imposing dictionary semantics on the product JSON.
    """
    start = reader.pos
    count = reader.u32() ^ 0x30C89ED2
    if count > 100_000:
        raise QuestBinParseError(f"implausible AFIO bit56 entry count {count} at 0x{start:X}")

    out: list[dict[str, Any]] = []
    for _ in range(count):
        key = _add32(reader.u32(), 0x76218C9E)
        value_count = _add32(reader.u32(), 0x903C85A7)
        if value_count > 100_000:
            raise QuestBinParseError(
                f"implausible AFIO bit56 value count {value_count} at 0x{reader.pos - 4:X}"
            )
        values = [
            (_add32(reader.u32(), 0xC35B495C) ^ 0x08CA1CAA) & _U32
            for _ in range(value_count)
        ]
        out.append({"key": key, "values": values})
    return out


def parse_main_quest(data: bytes, *, require_full: bool = True) -> MainQuest:
    """Decode a Genshin 7.1 Full MainQuest `Data/_BinOutput/Quest/*` payload.

    The productionized schema follows the recovered AFIO/FBKM/OOP native reader shapes,
    including the AFIO bit56 table, generalized FBKM record family, and OOP scalar
    families, plus the current gold fixtures. Unknown presence bits fail closed; no data is
    synthesized from QuestExcel or downstream resources.
    """
    reader = _Reader(data)
    raw_mask = reader.u64()
    mask = (raw_mask + 0xB19CC79B) & _U64
    active = set(_bits(mask, 64))
    supported = {
        3, 4, 5, 7, 8, 12, 13, 14, 15, 18, 19, 20, 21, 22,
        23, 26, 27, 28, 30, 31, 34, 35, 36, 37, 38, 39, 40, 41, 43, 44, 45,
        47, 48, 49, 50, 53, 54, 56, 58, 59, 61, 62, 63,
    }
    unsupported = active - supported
    if unsupported:
        raise QuestBinParseError(f"unsupported AFIOOHMJHDM bits {sorted(unsupported)}")

    main_id: int | None = None
    res_id: int | None = None
    quests: tuple[QuestRow, ...] = ()
    suggest_track_main_quest_list: tuple[int, ...] = ()
    reward_id_list: tuple[int, ...] = ()
    talks: tuple[dict[str, Any], ...] = ()
    action_config: dict[str, Any] | None = None
    lua_path: str | dict[str, Any] | None = None
    series = chapter_id = activity_id = recommend_level = task_id = None
    title_text_map_hash = desc_text_map_hash = None
    free_style_dic: tuple[dict[str, Any], ...] = ()
    show_type = quest_type = active_mode = main_quest_tag = None
    show_red_point = repeatable = suggest_track_out_of_order = None
    special_show_quest_id = None
    special_show_cond_id_list: tuple[int, ...] = ()
    special_show_reward_id: tuple[int, ...] = ()
    unknown: dict[str, Any] = {}

    # Exact AFIOOHMJHDM.GMENPOPMKAA reader order from the pinned 7.1 client.
    if 35 in active:
        main_id = reader.u32() ^ 0x1A9C24BC
    if 63 in active:
        unknown["LCBNMMFPDFH"] = reader.u8() != 0xFD
    if 59 in active:
        count = reader.u32() ^ 0x42B0ADDA
        if count > 100_000:
            raise QuestBinParseError(f"implausible AFIO bit59 count {count}")
        values = [reader.u32() ^ 0x8CA1F71F for _ in range(count)]
        reward_id_list = tuple(values)
    if 54 in active:
        values = _parse_dialogue_array(reader)
        talks = tuple(values)
    if 20 in active:
        show_red_point = reader.u8() != 0xB1
    if 21 in active:
        show_type = reader.u32() ^ 0xF2C0E96A
    if 15 in active:
        unknown["LLHHDHNBAGG"] = _add32(reader.u32(), 0x67CBB540) ^ 0xADF9DE7E
    if 56 in active:
        free_style_dic = tuple(_parse_afio_bit56_map(reader))
    if 48 in active:
        repeatable = reader.u8() != 0x9E
    if 44 in active:
        unknown["KJOHNNANDBK"] = _native_string(reader, lambda raw: raw ^ 0x56EA)
    if 50 in active:
        lua_path = _native_string(
            reader,
            lambda raw: _add16(raw, 0xC5A5),
            key=0x4B7CD17133A1C5A5,
            op="xor",
        )
    if 5 in active:
        count = _add32(reader.u32() ^ 0xD3327418, 0xA5B87FB0)
        if count > 100_000:
            raise QuestBinParseError(f"implausible AFIO bit5 count {count}")
        unknown["DKKIDDFEHMD"] = [
            ((reader.u64() ^ 0x342FB47E) + 0xA073A78B) & _U64
            for _ in range(count)
        ]
    if 58 in active:
        recommend_level = reader.u32() ^ 0xCBDC3C8D
    if 27 in active:
        unknown["IBIILFJEHBC"] = _parse_afio_bit27_progress_guides(reader)
    if 47 in active:
        unknown["AFEAMKOGMBF"] = _add32(reader.u32(), 0xCCBBD336)
    if 30 in active:
        unknown["HGFFNBIGPJK"] = reader.u8() != 0xD5
    if 53 in active:
        unknown["DJADGDCICCB"] = _parse_afio_bit53_array(reader)
    if 38 in active:
        unknown["IMGDIONBDMGId"] = reader.u32() ^ 0x7B7C8749
    if 3 in active:
        unknown["FEBBDBPEFCE"] = _add32(reader.u32() ^ 0x499938C6, 0x689183FC)
    if 13 in active:
        special_show_quest_id = reader.u32() ^ 0x8B28ACA8
    if 18 in active:
        unknown["KJBJDKALING"] = _native_string(reader, lambda raw: _add16(raw, 0xB085))
    if 12 in active:
        count = _add32(reader.u32(), 0x68594DDC)
        if count > 100_000:
            raise QuestBinParseError(f"implausible AFIO bit12 count {count}")
        special_show_cond_id_list = tuple(
            reader.u32() ^ 0x2D1891C8 for _ in range(count)
        )
    if 31 in active:
        count = _add32(reader.u32() ^ 0xB93361B5, 0x4FD39A66)
        if count > 100_000:
            raise QuestBinParseError(f"implausible AFIO bit31 count {count}")
        values = [_add32(reader.u32(), 0x591049E7) for _ in range(count)]
        suggest_track_main_quest_list = tuple(values)
    if 62 in active:
        count = _add32(reader.u32(), 0x28CB52A6)
        if count > 100_000:
            raise QuestBinParseError(f"implausible AFIO bit62 count {count}")
        special_show_reward_id = tuple(
            reader.u32() ^ 0x755615B1 for _ in range(count)
        )
    if 7 in active:
        unknown["AHBDGODKBDF"] = reader.u32() ^ 0xA7B47DF7
    if 41 in active:
        title_text_map_hash = _add32(reader.u32(), 0x985FAF13)
    if 61 in active:
        series = reader.u32() ^ 0x957E4B93
    if 45 in active:
        quests = _parse_row_array(reader)
    if 14 in active:
        unknown["MNPJPMCNIIP"] = reader.u8() != 0xF1
    if 8 in active:
        task_id = _add32(reader.u32(), 0x7BA20A25)
    if 49 in active:
        count = _add32(reader.u32(), 0x8BF0777A)
        if count > 100_000:
            raise QuestBinParseError(f"implausible AFIO bit49 count {count}")
        unknown["JNHHOJAPDPP"] = [
            ((reader.u64() ^ 0xA6AA5B5A) + 0x729DC4AB) & _U64
            for _ in range(count)
        ]
    if 22 in active:
        active_mode = reader.u32() ^ 0x4E78EC1D
    if 43 in active:
        chapter_id = reader.u32() ^ 0x24646272
    if 34 in active:
        main_quest_tag = _add32(reader.u32(), 0x40CD93BE)
    if 39 in active:
        quest_type = _add32(reader.u32(), 0xB995B37F)
    if 37 in active:
        res_id = reader.u32() ^ 0x32170514
    if 26 in active:
        unknown["HGDMKDGAJOM"] = _parse_afio_bit26_u32_array(reader)
    if 28 in active:
        unknown["PCIAMAFDDAA"] = _parse_afio_bit28_dialog_array(reader)
    if 36 in active:
        activity_id = _add32(reader.u32(), 0x72C6043D) ^ 0x8C794B70
    if 4 in active:
        unknown["INFDFLBGLPD"] = reader.u8() != 0xBE
    if 19 in active:
        suggest_track_out_of_order = reader.u8() != 0x90
    if 23 in active:
        # IACKBAAICMK is the penultimate root field in the exact 7.1 reader;
        # only fixed-width bit40 can follow it. Its nested polymorphic action
        # stream is decoded by the same-version Quest action-config decoder.
        trailing = 4 if 40 in active else 0
        remaining = len(reader.data) - reader.pos
        if remaining < trailing + 1:
            raise QuestBinParseError("truncated AFIO bit23 payload")
        raw = reader.take(remaining - trailing)
        try:
            action_config = parse_quest_action_config(raw)
        except QuestActionParseError as exc:
            raise QuestBinParseError(
                f"invalid AFIO bit23 action-config at 0x{reader.pos - len(raw):X}: {exc}"
            ) from exc
    if 40 in active:
        desc_text_map_hash = reader.u32() ^ 0x6B058DBD

    result = MainQuest(
        main_id=main_id,
        quests=quests,
        res_id=res_id,
        lua_path=lua_path,
        series=series,
        chapter_id=chapter_id,
        activity_id=activity_id,
        recommend_level=recommend_level,
        task_id=task_id,
        title_text_map_hash=title_text_map_hash,
        desc_text_map_hash=desc_text_map_hash,
        free_style_dic=free_style_dic,
        show_type=show_type,
        quest_type=quest_type,
        active_mode=active_mode,
        main_quest_tag=main_quest_tag,
        show_red_point=show_red_point,
        repeatable=repeatable,
        suggest_track_out_of_order=suggest_track_out_of_order,
        special_show_quest_id=special_show_quest_id,
        special_show_cond_id_list=special_show_cond_id_list,
        special_show_reward_id=special_show_reward_id,
        suggest_track_main_quest_list=suggest_track_main_quest_list,
        reward_id_list=reward_id_list,
        talks=talks,
        action_config=action_config,
        unknown_fields=unknown,
        presence_bits=tuple(sorted(active)),
        consumed=reader.pos,
        size=len(data),
    )
    if require_full and not result.fully_consumed:
        raise QuestBinParseError(
            f"Quest BinOutput has {result.size - result.consumed} unexplained trailing bytes "
            f"at 0x{result.consumed:X}"
        )
    return result
