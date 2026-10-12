# Genshin 7.1 Mondstadt Prologue integration contract

Scope: birth/prelude plus Prologue Acts I, II and III through 39604; derived
from RinoPaw/Genshin-Reverse versioned Mondstadt mainline manifest. Quest 361 is
the WQ-typed transition for the 353 -> 355 forest segment, included only as a
support check. Hidden chapter controllers 363, 370 and 397 must not be
linearized with visible objectives.

## Ownership (do not substitute one source for another)

- **Client-native**: current 7.1 QuestExcel and full Quest fields recovered
  by Genshin-Reverse. Full Quest owns finishCond/failCond/finishExec/failExec;
  ordinary acceptCond/beginExec do not belong to the 7.1 full Quest payload.
- **Compatibility**: reviewed historical 3.7 and 4.0 Quest beginExec,
  corroborated by current 7.1 Lua group suites and their progress events.
  These are explicitly NOT recovered 7.1 native beginExec.
- **Asta materialization**: current QuestExcel flattened accept conditions
  may include previous-physical-row chains. These are not evidence of native
  7.1 prerequisites and must not override verified chapter logic.
- **Server runtime**: PR #71 and companion PR #87 / previously merged #84.
  Suite dispatch needs script initialization and group persistence, quest
  event delivery, real NPC/talk handling, object callbacks and scene effects.

## Reviewed compatibility restorations

| Subquest | Recovered semantic action | Evidence |
| --- | --- | --- |
| 35301 / 35302 | scene 3 group 133003002 suite 1 / 2 | original pre-c98b896710 resource; 7.1 Lua |
| 35402 | reward item 1021 | historical GCResource 3700/4000 |
| 35404 | notify scene 3 group 133003439 | GCResource; current Lua 35404 trigger |
| 36001 | scene 3 group 133003435 suite 1 | GCResource 3700+4000; current 7.1 Lua suite 1 monster 1442 / quest progress |
| 36003 | scene 3 group 133003136 suite 1 | GCResource 3700+4000; current 7.1 Lua suite 1 monsters 623,1443,1444 / quest progress |
| 35901 | SET_WEATHER_GADGET (3,1) on begin | GCResource 3700+4000, matching historical 359 progression |
| 30904 | ADD_QUEST_PROGRESS 359011 by 1 on begin | GCResource 3700+4000, supports 359 branch |
| 31101 / 35901 | finishCondComb LOGIC_OR | both historical versions; #13 also repairs |
| 35301 | no early GRANT_TRIAL_AVATAR | proven accidental addition c98b896710 |

All materialized actions remain source-scoped; no hardcoded quest-ID runtime
bypass. This table is a *minimum proved subset*, not proof that the remaining
Mondstadt quest graphs are correct or complete.

## Static checks and open integration risks

Run `python tools/audit_mondstadt_prologue.py` and
`python tools/verify_prologue_35301.py` with 7.1 Resource data. The audit
checks the whole scoped MainQuest population and exact actions above, plus
scene Lua linkage and spreadsheet override conflicts where present. Unknown
`acceptCond` and `beginExec` are not fabricated. This cannot exercise:

1. Real-time server event to quest completion / action execution.
2. Quest-owned monster lifetime across scene loading and group replacement.
3. Prologue Acts II/III mechanics (chest drops, elevators, seal battles,
   Dungeon scene re-entry, Stormterror combat); these need specific PR #13/#87
   review and matching runtime support before a full-client-test claim.
4. Existing saved accounts stuck in older task state.

Do not request a client test before the full CI gates are green. Existing
generic prerequisite audit failures outside this scope must be reported
separately; they are not evidence this new scoped check passed.

## Imported evidence-supported companion work

Select native-resource-side changes from upstream resource PR #13 are folded
in without copying QuestExcel wholesale: Act II 20101 route 3; Act III
Stormterror group keepalive and name IDs; Light Guiding Ceremony seal
ability/Lua state handling. Companion server runtime is drawn from PR #87
and PR #71 with chapter bootstrap-at-birth explicitly excluded.

**Not yet imported:** PR #13's broad flattened QuestExcel changes (several
hundred entries), because the native 7.1 Quest ownership boundary requires
per-condition provenance and avoids silently replacing the entire table.
Remaining acceptance graph and cross-scene visual gameplay must be checked
after code and CI validation. Do not claim three-act completion based only
on static resources.

## Drift reporting semantics

Historical STATE_EQUAL/STATE_NOT_EQUAL arrays often carry a third zero padding
value; the scoped report normalizes that layout. Missing BinOutput compatibility
is counted separately, not treated as a proven Excel defect. Predecessor,
combinator and Quest-0 placeholder conflicts remain visible but are evidence
candidates, never automatically overwritten or promoted to 7.1 native data.

## Act I elemental tutorial sequence

The static gate now verifies the first fire slime (35302/439) and the later
quest-triggered slime waves: 35303 -> group 133003448 -> monsters 440,441;
35304 -> group 133003449 -> monsters 442..445. Both Lua groups must send
progress 1330030023/4, chained through 35310/35311. The 35304 burst-energy
action is required. These links are native 7.1 Lua evidence corroborating
the retained compatibility beginExec; they do not prove in-game visibility.

## Further reviewed Act II / Act III compatibility

Historical GCResource 3.7 and 4.0 agree on the restored actions. The
current 7.1 Lua files confirm the referenced group suites, monster configs
and quest-start notification sources:

- 37303, 38202, 39703: start the scene groups required by objectives.
- 2010101: consume hideout key and enable gadget; 2010102: trial 11,
  matched by its existing removal at 2010151; seven key-reward branches.
- 37203, 38303, 38406: story items 100164, 100163, 100165.
- 38402: rollback on fail; 38905 / 39003: Lua group 133007227.
- 39401: unlock point 3/38 for dungeon approach.
- 39801, 39808, 39812, 39604: closing-act gadget suites and Lua link.

We intentionally did not import historical 37903 gainItems(1021):
permanent Amber is already restored in 35402 and a second grant requires
7.1-specific evidence. None of the compatibility restorations claims to
be a native 7.1 beginExec/acceptCond field.

## Static quest acceptance handoff contract

The prelude/Act I audit pins the verified 351 -> 352 -> 353 -> 355/361 ->
354 -> 360 transitions, including the two tutorial slime wave handoffs and
both 360 combat group starts. The 35502 plot/scene join requires LOGIC_AND.
The Act II and III entry edges 31101 -> 37001 and 38406 -> 39701 are
also checked. Unknown chapter-controller acceptance is not reconstructed
from numeric ordering or guessed from a missing acceptCond record.

## Whole first-act group-action linkage

All refreshed groups and Lua notifications in the prelude and Act I (not
just the originally known slime and hilichurl repairs) are audited against
actual scene Lua files. Refresh suite indices must be in the Lua suites table,
including the scene 1004 dungeon group. Quest-start or quest-finish
notifications must target a script with the corresponding event type. This
remains structural validation; it does not execute ScriptLib or check loaded
world entities.

## Prelude lock point handler

35106 finishes when scene 3 waypoint 6 unlocks; its native/historical
finishExec then locks scene 3 point 1720. AstaPS now has an explicit
`QUEST_EXEC_LOCK_POINT` handler, separate from unlocking 3/6. The static
resource gate verifies both parts of this waypoint transition.

## Runtime QuestExec handler census

The scoped static audit enumerates every begin/finish/fail execution action in
all 40 MainQuests. All twenty handler types are now present in the paired
`fix/mondstadt-runtime-rino-71` AstaPS branch. The last action,
`QUEST_EXEC_SET_WEATHER_GADGET`, was implemented in server commit
`cd65df2` and maps 7.1 weather-area IDs to WeatherExcel gadget IDs in
`SceneAreaWeatherNotify`. Server CI passes, but visible storm transitions
remain unverified on a real 7.1 client. Any newly seen unreviewed opcode
fails CI instead of becoming an invisible gameplay defect.

## 30901 all-three-dungeon logic and alternative objectives

GCResource 3700 and 4000 independently preserve `finishCondComb=LOGIC_AND`
for 30901 with FINISH_DUNGEON IDs 1001, 1, 1003; without it,
QuestData's missing combinator defaults to LOGIC_NONE (OR-like) and the
first dungeon falsely completes the multi-dungeon task. 30710, 30810
and 30814 use LOGIC_OR for alternative talk/object objectives. Both
resource combinators and the matching server-side full Quest loader
are included in this integration; static CI checks the exact IDs.

## Scoped accept/content handler census

The same 40-MainQuest gate now enumerates every acceptCond, finishCond and
failCond, including repeatable death and dungeon failure conditions. All
observed types have registered Java content/condition handlers in the paired
AstaPS integration branch: two accept-condition types and nineteen
finish/fail content types. The previously absent QUEST_CONTENT_TEAM_DEAD
handler and full-team death event are included there. This census checks
handler presence; it does not prove a Lua/client event actually fires.
New condition types are CI-blocking until reviewed.

## Battle failure combinations

GCResource 3700 and 4000 preserve LOGIC_OR for 37602, 39703 and 38802,
just as the existing 35203 alternative-death/plot fail condition does.
These four battle quests can fail on either story-cancel or a full-party
wipe. The static gate now pins both failure conditions and the OR
combinator, with a matching scoped server-side failCondComb fallback.

## Leaving Stormterror dungeon during 39404

Both historical GCResource 3700 and 4000 specify LOGIC_OR for quest
39404 failCond: fail dungeon 2001 OR enter scene 3. The materialized
7.1 file lacked failCondComb and would ignore the world-return branch.
Restore the historical OR, preserving the independent failure paths;
static CI now checks the exact condition order and IDs.

## 35901 weather-gadget evidence boundary

The 7.1 quest activates weather area 3 at begin, and disables areas 3
and 1 at finish. The Q359 Lua configuration also declares a separate
quest-owned `MengdeWindDragon` VFX actor (gadget 70700004). The paired
server now maps weather-area activation to the corresponding 7.1 weather
gadget in SceneAreaWeatherNotify. The independent VFX actor remains
separate; CI asserts all actions and assets, but cannot verify rendering.

## Verified SET_WEATHER_GADGET parameter meaning

Historical GCResource 4.0 confirms the opcode's first parameter can be
`2150` and the second parameter is an activation flag (`0` or `1`).
The 7.1 `WeatherExcelConfigData.json` maps weather area 2150 to **scene 4**,
so that parameter cannot simply be treated as a scene ID.

For the opening Stormterror scene:
- Weather area **3** uses `ESP_Md_City_Storm`, gadget **70020003** and scene **3**.
- Weather area **1** uses `ESP_Md_General`, gadget **70020001** and scene **3**.
- Weather area **2** uses `ESP_Md_WindDragon`, gadget **70020002** and scene **3**.
- The independent Q359 quest VFX actor `MengdeWindDragon` is gadget **70700004**.

Thus 35901's `[3,1]`, `[3,0]`, `[1,0]` operate on weather-area gadget
activation. Their visible environmental effects cannot be reproduced by
mistaking 3 for a scene ID, 1 for a climate type, or spawning 70700004
as the WeatherExcel gadget. The 7.1 resource CI now pins these joins. The paired server
`fix/mondstadt-runtime-rino-71` has an implemented opcode handler and
passes CI. Whether the 7.1 client displays the intended storm and cleanup
needs end-to-end validation.

## Third-act 39403 scene-3 cleanup contract

The verified `39403` finish actions execute in order:
`REMOVE_TRIAL_AVATAR(5)`, `SET_WEATHER_GADGET(2,0)`, and
`NOTIFY_GROUP_LUA(3,133007183)`. Its native scene-3 Lua group accepts
`EVENT_QUEST_FINISH` for subquest 39403 with success=1 and targets the
five seal gadget groups 133007004, 133007076, 133007078, 133007079,
and 133007001. Static CI now pins these dependencies. The paired server's
Lua group handler must wait for scene 3 after the dungeon exit and respect
the explicit `group_id` given to the kill script function.
