#!/usr/bin/env python3
"""Static 7.1 Mondstadt prologue audit; no assertion of playable client behavior.

Provenance:
- Native full Quest: RinoPaw/Genshin-Reverse, quest-extraction analysis.
- Historical compatibility beginExec: TomyJan/GCResource 3700 and 4000.
- Native 7.1 scene Lua: this repository, Scripts/Scene.
- Scope: prelude, Prologue Acts I/II/III; see Genshin-Reverse mainline manifest.
"""
import json
import re
from pathlib import Path

SCOPE = {
    "prelude": (351, 359, 361),
    "act1": (363, 352, 353, 355, 354, 360, 356, 357, 358, 306, 307, 308, 309, 311),
    "act2": (370, 371, 372, 373, 374, 375, 376, 377, 20101, 379, 380, 381, 382, 383, 384),
    "act3": (397, 388, 389, 390, 393, 394, 398, 396),
}
# Handler coverage reviewed in the paired AstaPS integration branch.
# The set covers every accept, finish and fail opcode encountered in these 40
# MainQuests. Missing content event *sources* still need runtime testing.
IMPLEMENTED_ACCEPT_TYPES = {
    "QUEST_COND_STATE_EQUAL", "QUEST_COND_STATE_NOT_EQUAL",
}
IMPLEMENTED_CONTENT_TYPES = {
    "QUEST_CONTENT_FINISH_PLOT", "QUEST_CONTENT_TRIGGER_FIRE",
    "QUEST_CONTENT_UNLOCK_TRANS_POINT", "QUEST_CONTENT_ADD_QUEST_PROGRESS",
    "QUEST_CONTENT_COMPLETE_TALK", "QUEST_CONTENT_SKILL",
    "QUEST_CONTENT_LUA_NOTIFY", "QUEST_CONTENT_OBTAIN_ITEM",
    "QUEST_CONTENT_ENTER_DUNGEON", "QUEST_CONTENT_ENTER_MY_WORLD",
    "QUEST_CONTENT_GAME_TIME_TICK", "QUEST_CONTENT_ENTER_ROOM",
    "QUEST_CONTENT_DESTROY_GADGET", "QUEST_CONTENT_FAIL_DUNGEON",
    "QUEST_CONTENT_FINISH_DUNGEON", "QUEST_CONTENT_TEAM_DEAD",
    "QUEST_CONTENT_NOT_FINISH_PLOT", "QUEST_CONTENT_CLEAR_GROUP_MONSTER",
    "QUEST_CONTENT_INTERACT_GADGET",
}
IMPLEMENTED_EXEC_TYPES = {
    "QUEST_EXEC_REFRESH_GROUP_SUITE", "QUEST_EXEC_NOTIFY_GROUP_LUA",
    "QUEST_EXEC_ADD_CUR_AVATAR_ENERGY", "QUEST_EXEC_GRANT_TRIAL_AVATAR",
    "QUEST_EXEC_DEL_PACK_ITEM", "QUEST_EXEC_DEL_PACK_ITEM_BATCH",
    "QUEST_EXEC_ADD_QUEST_PROGRESS", "QUEST_EXEC_UNLOCK_POINT",
    "QUEST_EXEC_LOCK_POINT", "QUEST_EXEC_UNLOCK_AREA",
    "QUEST_EXEC_ROLLBACK_QUEST", "QUEST_EXEC_REMOVE_TRIAL_AVATAR",
    "QUEST_EXEC_SET_IS_GAME_TIME_LOCKED", "QUEST_EXEC_SET_IS_WEATHER_LOCKED",
    "QUEST_EXEC_SET_IS_FLYABLE", "QUEST_EXEC_CHANGE_AVATAR_ELEMET",
    "QUEST_EXEC_SET_OPEN_STATE", "QUEST_EXEC_SET_QUEST_GLOBAL_VAR",
    "QUEST_EXEC_REFRESH_GROUP_MONSTER",
    "QUEST_EXEC_SET_WEATHER_GADGET",
}
# The paired play/rino runtime has a registered SET_WEATHER_GADGET handler
# (commit cd65df2), with a mapped 7.1 weather gadget ID in its outgoing
# SceneAreaWeatherNotify. The visible scene effect still needs client testing.
KNOWN_UNIMPLEMENTED_EXEC_TYPES = set()

# Only narrowly confirmed historical actions are asserted. Empty modern beginExec
# is NOT automatically treated as broken: some actions moved to other assets.
ACTIONS = {
    35106: ("finishExec", "QUEST_EXEC_LOCK_POINT", ["3", "1720"]),
    35301: ("beginExec", "QUEST_EXEC_REFRESH_GROUP_SUITE", ["3", "133003002,1"]),
    35302: ("beginExec", "QUEST_EXEC_REFRESH_GROUP_SUITE", ["3", "133003002,2"]),
    35303: ("beginExec", "QUEST_EXEC_NOTIFY_GROUP_LUA", ["3", "133003448"]),
    35304: ("beginExec", "QUEST_EXEC_NOTIFY_GROUP_LUA", ["3", "133003449"]),
    35404: ("beginExec", "QUEST_EXEC_NOTIFY_GROUP_LUA", ["3", "133003439"]),
    36001: ("beginExec", "QUEST_EXEC_REFRESH_GROUP_SUITE", ["3", "133003435,1"]),
    36003: ("beginExec", "QUEST_EXEC_REFRESH_GROUP_SUITE", ["3", "133003136,1"]),
    35901: ("beginExec", "QUEST_EXEC_SET_WEATHER_GADGET", ["3", "1"]),
    30904: ("beginExec", "QUEST_EXEC_ADD_QUEST_PROGRESS", ["359011", "1"]),
    37303: ("beginExec", "QUEST_EXEC_REFRESH_GROUP_SUITE", ["3", "133001305,2"]),
    2010102: ("beginExec", "QUEST_EXEC_GRANT_TRIAL_AVATAR", ["11"]),
    38202: ("beginExec", "QUEST_EXEC_REFRESH_GROUP_SUITE", ["3", "133001249,2"]),
    39703: ("beginExec", "QUEST_EXEC_REFRESH_GROUP_SUITE", ["3", "133002233,2"]),
    38905: ("beginExec", "QUEST_EXEC_NOTIFY_GROUP_LUA", ["3", "133007227"]),
    39003: ("beginExec", "QUEST_EXEC_NOTIFY_GROUP_LUA", ["3", "133007227"]),
    39401: ("beginExec", "QUEST_EXEC_UNLOCK_POINT", ["3", "38"]),
    39801: ("beginExec", "QUEST_EXEC_REFRESH_GROUP_SUITE", ["3", "133003910,2"]),
    39808: ("beginExec", "QUEST_EXEC_REFRESH_GROUP_SUITE", ["3", "133004917,1"]),
    39812: ("beginExec", "QUEST_EXEC_NOTIFY_GROUP_LUA", ["3", "133003910"]),
    39604: ("beginExec", "QUEST_EXEC_REFRESH_GROUP_SUITE", ["3", "133001910,2"]),
}
# Explicit acceptance edges recovered from historical compatibility and corroborated by
# current 7.1 chapter/tutorial flow. Do not infer missing acceptCond from file order.
REQUIRED_ACCEPT_EDGES = {
    35101: (35100,), 35200: (35102,), 35301: (35205,),
    35302: (35301,), 35309: (35302,), 35303: (35309,),
    35310: (35303,), 35304: (35310,), 35311: (35304,),
    35501: (35311,), 35502: (35501, 36101), 35503: (35502,),
    35504: (35503,), 35505: (35504,), 35401: (35505,),
    35403: (35404,), 36001: (35403,), 36003: (36001,),
    36301: (35202,), 37001: (31101,), 39701: (38406,),
}

FAIL_COMBINATORS = {
    35203: "LOGIC_OR", 37602: "LOGIC_OR",
    39703: "LOGIC_OR", 38802: "LOGIC_OR", 39404: "LOGIC_OR",
}
COMBINATORS = {
    35100: "LOGIC_OR", 35201: "LOGIC_OR", 35203: "LOGIC_AND",
    31101: "LOGIC_OR", 35901: "LOGIC_OR",
    38201: "LOGIC_OR", 39807: "LOGIC_OR",
    30710: "LOGIC_OR", 30810: "LOGIC_OR", 30814: "LOGIC_OR",
    30901: "LOGIC_AND",
}
CHAPTER_BEGIN = {1001: 36301, 1002: 37004, 1003: 39705}
CHAPTER_END = {1001: 31101, 1002: 38406, 1003: 39604}


def load(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def require(test, message):
    if not test:
        raise AssertionError(message)


def expected_action(row, field, action_type, params):
    return {"type": action_type, "param": params} in [
        {"type": x.get("type"), "param": x.get("param")}
        for x in row.get(field, [])
    ]


def has_condition(row, typ, first, second=None):
    return any(
        c.get("type") == typ
        and c.get("param", [None])[0] == first
        and (second is None or len(c.get("param", [])) > 1 and c["param"][1] == second)
        for c in row.get("acceptCond", [])
    )


def lua(group):
    path = Path("Scripts/Scene/3/scene3_group%d.lua" % group)
    require(path.is_file(), "Missing group Lua: %s" % path)
    text = path.read_text(encoding="utf-8")
    require("group_id = %d" % group in text, "Wrong group identity %d" % group)
    return text


def check_scene(scripts):
    a = lua(133003002)
    require(re.search(r"monsters\s*=\s*\{\s*439\s*\}", a), "35302 slime suite absent")
    require('ScriptLib.AddQuestProgress(context, "1330030022")' in a, "35302 kill notification missing")
    # Later tutorial waves are quest-start-triggered: the task must emit the
    # Lua event, which in turn creates the actual world monsters.
    for sub, gid, monster_configs, progress in [
        (35303, 133003448, (440, 441), "1330030023"),
        (35304, 133003449, (442, 443, 444, 445), "1330030024"),
    ]:
        group_lua = lua(gid)
        require('source = "%d"' % sub in group_lua,
                "Quest %d has no Lua QUEST_START trigger" % sub)
        for config in monster_configs:
            require(re.search(
                r"ScriptLib\.CreateMonster\(context,\s*\{\s*config_id\s*=\s*%d\b" % config,
                group_lua,
            ), "Quest %d cannot create tutorial slime config %d" % (sub, config))
        require('ScriptLib.AddQuestProgress(context, "%s")' % progress in group_lua,
                "Quest %d wave has no completion Lua progress" % sub)

    a = lua(133003439)
    for token in ('source = "35404"', 'config_id = 3834',
                  'ScriptLib.CreateGadget(context, { config_id = 3834 })',
                  'ScriptLib.AddQuestProgress(context, "133003079")'):
        require(token in a, "35404 moving target lacks " + token)
    for gid, configs, progress in [
        (133003435, (1442,), "133003435"),
        (133003136, (623, 1443, 1444), "133003136"),
    ]:
        a = lua(gid)
        first = re.search(r"suites\s*=\s*\{\s*\{(.*?)\}\s*,", a, re.S)
        require(first is not None, "No initial suite in group %d" % gid)
        for config in configs:
            require(re.search(r"\b%d\b" % config, first.group(1)),
                    "Group %d suite 1 missing monster %d" % (gid, config))
        require('ScriptLib.AddQuestProgress(context, "%s")' % progress in a,
                "Group %d missing quest progress trigger" % gid)
    scripts.add("353 first/second/third slime waves, 354 target, 360 hilichurl groups")


def count_lua_suites(source):
    """Count top-level suites without mistaking nested monsters/triggers for suites."""
    match = re.search(r"\bsuites\s*=\s*\{", source)
    require(match is not None, "Lua group has no suites table")
    level = 0
    count = 0
    quoted = None
    index = match.end() - 1
    while index < len(source):
        c = source[index]
        if quoted is not None:
            if c == "\\":
                index += 2
                continue
            if c == quoted:
                quoted = None
        elif source[index:index + 2] == "--":
            end = source.find("\n", index)
            index = len(source) if end == -1 else end
            continue
        elif c in ("'", '"'):
            quoted = c
        elif c == "{":
            if level == 1:
                count += 1
            level += 1
        elif c == "}":
            level -= 1
            if level == 0:
                return count
        index += 1
    raise AssertionError("Unclosed Lua suites table")


def check_act1_group_references(mains):
    """Check every quest-driven group and requested suite, not only handpicked fixes."""
    verified = 0
    cached = {}
    for main in SCOPE["prelude"] + SCOPE["act1"]:
        for row in mains[main]["subQuests"]:
            for field in ("beginExec", "finishExec", "failExec"):
                for action in row.get(field, []):
                    kind = action.get("type")
                    if kind not in ("QUEST_EXEC_REFRESH_GROUP_SUITE",
                                    "QUEST_EXEC_NOTIFY_GROUP_LUA"):
                        continue
                    params = action.get("param") or []
                    require(len(params) >= 2, "Quest %d %s lacks scene/group args" %
                            (row["subId"], kind))
                    scene = int(params[0])
                    entries = (params[1].split(";") if kind == "QUEST_EXEC_REFRESH_GROUP_SUITE"
                               else [params[1]])
                    for entry in entries:
                        pieces = entry.split(",")
                        require(pieces[0].strip().isdigit(),
                                "Quest %d malformed group %s" % (row["subId"], entry))
                        group = int(pieces[0])
                        path = Path("Scripts/Scene/%d/scene%d_group%d.lua" %
                                    (scene, scene, group))
                        require(path.is_file(), "Quest %d references absent group %s" %
                                (row["subId"], path))
                        if path not in cached:
                            lua_text = path.read_text(encoding="utf-8")
                            require(re.search(r"\bgroup_id\s*=\s*%d\b" % group, lua_text),
                                    "Wrong identity in Lua group %d" % group)
                            cached[path] = (lua_text, count_lua_suites(lua_text))
                        lua_text, suite_count = cached[path]
                        if kind == "QUEST_EXEC_REFRESH_GROUP_SUITE":
                            require(len(pieces) == 2 and pieces[1].strip().isdigit(),
                                    "Quest %d missing group suite in %s" % (row["subId"], entry))
                            suite = int(pieces[1])
                            require(0 <= suite <= suite_count,
                                    "Quest %d requests group %d suite %d but Lua has %d" %
                                    (row["subId"], group, suite, suite_count))
                        else:
                            event = ("EVENT_QUEST_FINISH" if field == "finishExec"
                                     else "EVENT_QUEST_START")
                            require(event in lua_text,
                                    "Quest %d Lua group %d cannot receive %s" %
                                    (row["subId"], group, event))
                        verified += 1
    return verified, len(cached)


def check_act23_resources():
    routes = load("BinOutput/LevelDesign/Routes/scene20023_routes.json")
    require(routes.get("sceneId") == 20023, "Act II elevator route scene mismatch")
    require(any(x.get("localId") == 3 for x in routes.get("routes", [])),
            "Act II hideout elevator route 3 absent")
    keep = Path("Scripts/Scene/20017/scene20017_block20017.lua").read_text(encoding="utf-8")
    require("220017001" in keep and "dontUnload = true" in keep,
            "Act III Stormterror scene group lifetime not retained")
    for scene in (20017, 20018, 20020):
        s = Path("Scripts/Scene/%d/scene%d_group2200%d001.lua" % (scene, scene, scene % 100)).read_text(encoding="utf-8")
        require("special_name_id = 2010102" in s,
                "Stormterror scene %d missing corrected displayed name" % scene)
    for gid in (133007228, 133007229, 133007230):
        text = lua(gid)
        require("Point_Value" in text and "Temp_Point_Value" in text,
                "Tower seal %d lacks collection/delivery state" % gid)
    final = lua(133007230)
    require("seal_battle_done" in final, "Third seal missing battle-complete guard")


def check_reviewed_later_acts(subs):
    require(expected_action(subs[2010101], "beginExec",
                            "QUEST_EXEC_DEL_PACK_ITEM", ["100175", "1"]),
            "2010101 must consume the hideout key")
    require(expected_action(subs[2010101], "beginExec",
                            "QUEST_EXEC_REFRESH_GROUP_SUITE", ["3", "133002334,2"]),
            "2010101 must activate hideout gadget group")
    require(expected_action(subs[2010151], "finishExec",
                            "QUEST_EXEC_REMOVE_TRIAL_AVATAR", ["11"]),
            "2010102 trial avatar must be revoked on dungeon exit")
    require(expected_action(subs[38402], "failExec",
                            "QUEST_EXEC_ROLLBACK_QUEST", ["38401"]),
            "38402 failure must enable retry")
    reward_ids = {37203: 100164, 38303: 100163, 38406: 100165}
    reward_ids.update({sub: 100175 for sub in (
        2010145, 2010146, 2010147, 2010148, 2010149, 2010150, 2010151)})
    for sub, item in reward_ids.items():
        require(subs[sub].get("gainItems") == [{"itemId": item, "count": 1}],
                "Missing quest reward %d in %d" % (item, sub))
    for gid, tokens in {
        133001305: ("monsters = { 1307 }",),
        133002334: ("gadgets = { 334001 }",),
        133001249: ("gadgets = { 2883 }",),
        133002233: ("monsters = { 870, 871, 872 }",),
        133007227: ('source = "38905"', 'source = "39003"',
                      'AddQuestProgress(context, "39003_success")'),
        133003910: ('source = "39812"', 'AddQuestProgress(context, "133003910")'),
        133004917: ("suites = {",),
        133001910: ("gadgets = { 910001 }",),
    }.items():
        lua_content = lua(gid)
        for token in tokens:
            require(token in lua_content,
                    "Group %d lacks evidence token: %s" % (gid, token))


def main():
    mains, subs, count = {}, {}, 0
    action_uses = {}
    accept_uses = {}
    content_uses = {}
    for chapter, ids in SCOPE.items():
        for main_id in ids:
            path = Path("BinOutput/Quest/%d.json" % main_id)
            require(path.is_file(), "Missing %s MainQuest %d" % (chapter, main_id))
            obj = load(path)
            require(obj.get("id") == main_id, "MainQuest identity mismatch: %d" % main_id)
            rows = obj.get("subQuests")
            require(isinstance(rows, list) and rows, "Empty quest %d" % main_id)
            mains[main_id] = obj
            for row in rows:
                sub = row["subId"]
                require(sub not in subs, "Duplicate subquest %d" % sub)
                require(row.get("mainId") == main_id, "Bad parent for %d" % sub)
                subs[sub] = row
                count += 1
                for field in ("acceptCond", "finishCond", "failCond",
                              "finishExec", "failExec", "beginExec"):
                    for entry in row.get(field, []):
                        kind = entry.get("type")
                        require(isinstance(kind, str),
                                "Unnamed %s for %d" % (field, sub))
                        if field == "acceptCond":
                            accept_uses.setdefault(kind, []).append(sub)
                        elif field in ("finishCond", "failCond"):
                            content_uses.setdefault(kind, []).append((sub, field))
                        else:
                            action_uses.setdefault(kind, []).append((sub, field))
            print("%s: %d main quests" % (chapter, len(ids)))
    unsupported_accept = sorted(set(accept_uses) - IMPLEMENTED_ACCEPT_TYPES)
    unsupported_content = sorted(set(content_uses) - IMPLEMENTED_CONTENT_TYPES)
    require(not unsupported_accept, "Quest accepts without Java handlers: %s" %
            {kind: accept_uses[kind][:8] for kind in unsupported_accept})
    require(not unsupported_content, "Quest content/fail conditions without Java handlers: %s" %
            {kind: content_uses[kind][:8] for kind in unsupported_content})
    print("PASS condition census: %d accept types, %d finish/fail types" %
          (len(accept_uses), len(content_uses)))
    unexpected = sorted(set(action_uses) - IMPLEMENTED_EXEC_TYPES -
                        KNOWN_UNIMPLEMENTED_EXEC_TYPES)
    require(not unexpected, "Quest actions without reviewed Java handlers: %s" %
            {kind: action_uses[kind][:8] for kind in unexpected})
    for kind in sorted(set(action_uses) & KNOWN_UNIMPLEMENTED_EXEC_TYPES):
        print("KNOWN UNSUPPORTED quest action: %s uses=%d sample=%s" %
              (kind, len(action_uses[kind]), action_uses[kind][:8]))
    print("PASS handler type census: %d action types, %d supported, %d known missing" %
          (len(action_uses), len(set(action_uses) & IMPLEMENTED_EXEC_TYPES),
           len(set(action_uses) & KNOWN_UNIMPLEMENTED_EXEC_TYPES)))
    for sub, (field, kind, params) in ACTIONS.items():
        require(sub in subs and expected_action(subs[sub], field, kind, params),
                "Lost reviewed compatibility %d %s %s" % (sub, field, kind))
    # The paired rino branch handles these weather-area activation actions.
    # Pin both activation and cleanup; avoid interpreting the second
    # parameter as a climate ID.
    for field, params in [
        ("beginExec", ["3", "1"]),
        ("finishExec", ["3", "0"]),
        ("finishExec", ["1", "0"]),
    ]:
        require(expected_action(subs[35901], field,
                                "QUEST_EXEC_SET_WEATHER_GADGET", params),
                "35901 weather-gadget activation/reset action missing: %s %s" %
                (field, params))
    # 39403's finish in dungeon 1008 must deactivate weather in scene 3
    # and notify its cross-group seal cleanup Lua.
    require([(a.get("type"), a.get("param")) for a in subs[39403]["finishExec"]] == [
        ("QUEST_EXEC_REMOVE_TRIAL_AVATAR", ["5"]),
        ("QUEST_EXEC_SET_WEATHER_GADGET", ["2", "0"]),
        ("QUEST_EXEC_NOTIFY_GROUP_LUA", ["3", "133007183"]),
    ], "39403 verified finishExec order changed")
    seal_lua = Path("Scripts/Scene/3/scene3_group133007183.lua").read_text(encoding="utf-8")
    require("39403 ~= evt.param1" in seal_lua
            and "1 ~= evt.param2" in seal_lua,
            "39403 Lua notification group lacks expected finish trigger")
    for gid in (133007004, 133007076, 133007078, 133007079, 133007001):
        require(re.search(r"group_id\s*=\s*%d\b" % gid, seal_lua),
                "39403 cleanup lost target group %d" % gid)
    quest359 = Path("Scripts/Quest/Share/Q359ShareConfig.lua").read_text(encoding="utf-8")
    quest359_actor = re.search(
        r'quest_data\["35901"\]\s*=\s*\{(.*?)quest_data\["35902"\]',
        quest359, re.S)
    require(quest359_actor is not None,
            "35901 quest actor configuration absent")
    require(re.search(r"\bid\s*=\s*70700004\b", quest359_actor.group(1))
            and 'alias = "MengdeWindDragon"' in quest359_actor.group(1)
            and re.search(r"\bscene_id\s*=\s*3\b", quest359_actor.group(1)),
            "35901 Stormterror weather VFX quest gadget lost from Q359 config")
    # The first weather-gadget argument indexes WeatherExcel.areaID, not a
    # scene ID or climate enum. Area 2150, used by Q40016, belongs to scene 4:
    # the numeric weather area and the scene can be different.
    weather_rows = load(Path("ExcelBinOutput/WeatherExcelConfigData.json"))
    weather_areas = {row["areaID"]: row for row in weather_rows}
    for area_id, scene_id, gadget_id, profile_suffix in [
        (1, 3, 70020001, "ESP_Md_General"),
        (2, 3, 70020002, "ESP_Md_WindDragon"),
        (3, 3, 70020003, "ESP_Md_City_Storm"),
    ]:
        area = weather_areas.get(area_id)
        require(area is not None
                and area.get("weatherAreaId") == area_id
                and area.get("sceneID") == scene_id
                and area.get("gadgetID") == gadget_id
                and area.get("profileName", "").endswith(profile_suffix),
                "WeatherExcel lost native weather-area/gadget metadata for %d" % area_id)
    distant_area = weather_areas.get(2150)
    require(distant_area is not None
            and distant_area.get("weatherAreaId") == 2150
            and distant_area.get("sceneID") == 4,
            "Weather gadget opcode first argument must be interpreted as weather area, not scene")
    print("PASS 35901 weather-area action contract: area 3 storm gadget 70020003; area 1 general gadget 70020001; paired server handler present; client effect unverified")
    for sub, predecessors in REQUIRED_ACCEPT_EDGES.items():
        require(sub in subs, "Missing reviewed acceptance node %d" % sub)
        for prev in predecessors:
            require(prev in subs, "Missing reviewed predecessor %d for %d" % (prev, sub))
            require(has_condition(subs[sub], "QUEST_COND_STATE_EQUAL", prev, 3),
                    "Lost quest handoff %d -> %d" % (prev, sub))
    # The forest handoff needs BOTH the task completion and the WQ scene event.
    require(subs[35502].get("acceptCondComb") == "LOGIC_AND",
            "35502 must wait for forest plot and scene event")
    # The hilltop-to-chapter controller is an independent branch; do not open it at birth.
    require(has_condition(subs[36301], "QUEST_COND_STATE_EQUAL", 35202, 3),
            "36301 chapter banner must wait for 35202")

    for sub, logic in COMBINATORS.items():
        require(subs[sub].get("finishCondComb") == logic, "%d must combine finish with %s" % (sub, logic))
    for sub, logic in FAIL_COMBINATORS.items():
        require(subs[sub].get("failCondComb") == logic, "%d must combine failure with %s" % (sub, logic))
        fail_types = [c.get("type") for c in subs[sub].get("failCond", [])]
        if sub == 39404:
            require(fail_types == ["QUEST_CONTENT_FAIL_DUNGEON",
                                   "QUEST_CONTENT_ENTER_MY_WORLD"],
                    "39404 must fail on dungeon failure or scene 3 return")
        else:
            require("QUEST_CONTENT_TEAM_DEAD" in fail_types
                    and "QUEST_CONTENT_NOT_FINISH_PLOT" in fail_types,
                    "%d lost one of its two combat failure paths" % sub)
    require(any(c.get("type") == "QUEST_CONTENT_UNLOCK_TRANS_POINT"
                and c.get("param") == [3, 6]
                for c in subs[35106].get("finishCond", [])),
            "35106 must finish from unlocking waypoint 3/6")
    require(not any(x.get("type") == "QUEST_EXEC_GRANT_TRIAL_AVATAR"
                    for x in subs[35301].get("finishExec", [])),
            "35301 incorrectly grants Amber before Anemo tutorial")
    dungeon_ids = [tuple(c.get("param", [])) for c in subs[30901].get("finishCond", [])
                   if c.get("type") == "QUEST_CONTENT_FINISH_DUNGEON"]
    require(dungeon_ids == [(1001, 0), (1, 0), (1003, 0)],
            "30901 must require all three distinct dungeon completions")
    require(subs[35402].get("gainItems") == [{"itemId": 1021, "count": 1}],
            "35402 must give Amber's encounter reward")
    require(expected_action(subs[35304], "beginExec",
                            "QUEST_EXEC_ADD_CUR_AVATAR_ENERGY", []),
            "35304 needs elemental burst energy during third slime wave")
    for sub, progress in ((35309, "1330030022"),
                          (35310, "1330030023"),
                          (35311, "1330030024")):
        require(any(c.get("type") == "QUEST_CONTENT_LUA_NOTIFY"
                    and c.get("param_str") == progress
                    for c in subs[sub].get("finishCond", [])),
                "Quest %d is disconnected from slime wave %s" % (sub, progress))
    require(has_condition(subs[36301], "QUEST_COND_STATE_EQUAL", 35202, 3),
            "Chapter 1001 must open only after 35202")
    for chapter, sub in CHAPTER_BEGIN.items():
        require(sub in subs, "Missing chapter %d opener %d" % (chapter, sub))
    for chapter, sub in CHAPTER_END.items():
        require(sub in subs, "Missing chapter %d closer %d" % (chapter, sub))
    for chapter, ids in SCOPE.items():
        if chapter in ("act1", "act2", "act3"):
            require(all(mains[q].get("series") in (1001, 1002, 1003) for q in ids),
                    "Unexpected chapter series in %s" % chapter)
    # Detect current Excel priority conflicts on repaired beginExec/actions.
    excel_path = Path("ExcelBinOutput/QuestExcelConfigData.json")
    if excel_path.exists():
        rows = {r.get("subId"): r for r in load(excel_path) if isinstance(r, dict)}
        for sub, (field, kind, params) in ACTIONS.items():
            if sub not in rows:
                continue
            actions = [e for e in rows[sub].get(field, []) if e.get("type")]
            if actions:
                require(expected_action(rows[sub], field, kind, params),
                        "QuestExcel nonempty %d %s masks BinOutput action" % (sub, field))
        require(not any(x.get("type") == "QUEST_EXEC_GRANT_TRIAL_AVATAR"
                        for x in rows.get(35301, {}).get("finishExec", [])),
                "QuestExcel prematurely grants trial Amber")
    act1_edges, act1_groups = check_act1_group_references(mains)
    scripts = set()
    check_scene(scripts)
    check_act23_resources()
    check_reviewed_later_acts(subs)
    print("PASS static Mondstadt prologue: %d main quests, %d subquests, "
          "%d reviewed actions; %s" %
          (len(mains), count, len(ACTIONS), ", ".join(sorted(scripts))))
    print("PASS Act I group link audit: %d group actions, %d distinct Lua files" %
          (act1_edges, act1_groups))
    print("NOTE: does not prove chapter gameplay, scene lifecycle, or old save recovery")


if __name__ == "__main__":
    main()
