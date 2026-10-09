# Quest extraction and prerequisite ownership

Status: **CONFIRMED extraction/ownership boundary**. Compatibility restoration remains active in issue #20.

Target: Genshin Impact 7.1.0 Global / Windows x64, bound to the pinned `NativeProfile`.

## Exact 7.1 QuestExcel wire

The exact `Data/_ExcelBinOutput/QuestExcelConfigData` asset is recovered as `MiHoYoBinData/3b87ae83.dat`.

- raw size: 2,824,192 bytes;
- serialized payload: 2,824,188 bytes;
- payload SHA256: `07ab4816ee1eaa68fefd636b92dcfa923fe58a15731d18de0c0fb26863791fe5`;
- 33,214 native rows;
- all recovered `subId` values are unique;
- every row is structurally consumed end to end by the recovered 7.1 decoder;
- every row ends with `raw_tail == b""`.

This closes the framing question. There is no hidden unparsed QuestExcel row region that can contain ordinary `acceptCond`, `beginExec`, `finishCond`, `failCond`, `finishExec` or `failExec` arrays.

Full byte consumption proves the wire boundary. It does not justify semantic names for still-obfuscated scalar fields.

## Exact ordinary full-Quest source

The separate `Data/_BinOutput/Quest/351` source is byte-exactly consumed on the pinned sample:

- payload size: 920 bytes;
- root reader: `AFIOOHMJHDM`, RVA `0x10409D40`;
- root decode: 920/920 bytes;
- ordinary sub-quest array begins at offset 59;
- array count: `0xA74F0AC3 XOR 0xA74F0ACB = 8`;
- `LAIMPNDEFCL[]` wrapper: RVA `0x9C15C80`;
- ordinary row reader: RVA `0x9C15DF0`.

The ordinary row owns exactly four relevant object arrays:

- `failExec`;
- `failCond`;
- `finishCond`;
- `finishExec`.

Exact Quest 351 controls match the decoded values, including `35101 TEAM_DEAD -> ROLLBACK_QUEST 35100`.

No fifth QuestExec array exists for `beginExec`, and the current runtime-type census finds no ordinary `acceptCond` owner.

The same ownership test rejects the three legacy condition-combination fields for ordinary 7.1 Quest rows. Exact metadata gives `LAIMPNDEFCL` 35 fields and none has type `PCBNKHFKLHI` (the current logic-combination enum). In contrast, `RandomQuestExcelConfig` explicitly owns `_acceptCondComb`, `_finishCondComb` and `_failCondComb`, all with type `PCBNKHFKLHI`. Ordinary product JSON must therefore not synthesize `acceptCondComb`, `finishCondComb` or `failCondComb` from the native Quest payload.

## Full native Quest decoder checkpoint

The maintained 7.1 ordinary Quest decoder now consumes the complete recovered corpus:

- 4,417 / 4,417 MainQuest payloads full-consumed;
- 0 parse failures;
- 0 mainId mismatches;
- 9,087,239 payload bytes consumed;
- all observed AFIO/LAIM presence bits covered by the exact client readers.

The decoder also has exact same-version type-name mappings for every Quest content/exec ID
observed in this corpus: 93 QuestContent IDs and 100 QuestExec IDs. The mapping was derived by
aligning native 7.1 entries against Dimbreath 7.1 commit
`792978e5503ecfba73dcb3562ed44a0d35a2abe2` on mainId, subId, field and array position:
71,051 entries compared, zero type-name conflicts.

One reference mismatch is intentionally not imported into the native decoder. Dimbreath row
`701609` contains one `failCond` and three `failExec` entries, while the exact 7.1 native row
has presence bits `[0,3,12,19,25,26,31,34,35,39,48]`; bits 51/55 are absent. The official
native row therefore owns neither fail array. Treat those four reference entries as
conversion/additional-layer data, not native Quest fields.

## Positive control

The condition format itself still exists in 7.1 and the maintained QuestCond decoder recovers its native wire.

A separate current type, `MoleMole.Config.RandomQuestExcelConfig`, still owns named `_acceptCond : RandomQuestCond[]` plus named begin/fail/finish exec/cond fields. It also retains named `_acceptCondComb`, `_finishCondComb` and `_failCondComb`.

This is a positive control for metadata quality: when these fields genuinely exist, the current metadata pipeline preserves their names and types.

## Historical removal boundary

Exact-client controls put ordinary prerequisite removal between 2.8 and 3.0:

- exact 2.8 QuestExcel still carries Quest 351 prerequisite conditions;
- exact 3.0/3.2/3.4 Quest 351 no longer carries them;
- exact 7.1 ordinary full-Quest source still has no `acceptCond` owner.

Therefore modern ordinary `acceptCond` and `beginExec` values are compatibility-restoration data, not 7.1 client-native fields.

## Downstream Asta materialization

The first flattened Asta import already follows a synthetic physical-order chain on most rows: first row uses `QUEST_COND_STATE_EQUAL [0,3]`, later rows point to the previous physical row with state 3.

For Quest 351 this yields:

`35104 -> 35100 -> 35107 -> 35101 -> 35106 -> 35105 -> 35103 -> 35102`.

That chain differs from historical branch/convergence semantics and must not be promoted as recovered source data.

Later AstaPS-Resource PR #9 explicitly extended the same fallback to newly materialized rows because current BinOutput lacks `acceptCond` and `beginExec`.

Root-cause classification:

- missing ordinary `acceptCond` / `beginExec` / `acceptCondComb` / `finishCondComb` / `failCondComb` in 7.1: **native ownership/format change**;
- previous-row prerequisite chains in modern Asta-derived QuestExcel: **downstream synthetic compatibility materialization**;
- retained finish/fail condition/execution arrays: **recoverable from exact 7.1 ordinary Quest source**.

Issue #8 is closed on this boundary.

## Current upstream-fieldset audit

A corpus-wide comparison was run against exact Dimbreath 7.1 commit
`792978e5503ecfba73dcb3562ed44a0d35a2abe2` and the current AstaPS-Resource
materialization snapshot used by this investigation.

- exact Dimbreath 7.1: 4,417 Quest files, 33,214 ordinary rows;
- AstaPS-Resource snapshot: 4,421 Quest files, 33,217 ordinary rows;
- Asta therefore contains additional materialized data and is not a pure native 7.1 schema oracle;
- the five ordinary-row controls present in Asta without a 7.1 `LAIMPNDEFCL` owner are
  `acceptCond`, `beginExec`, `acceptCondComb`, `finishCondComb` and `failCondComb`;
- after excluding those five compatibility/source-layer controls, every Asta ordinary-row
  information field has a native counterpart that the maintained decoder reads and preserves,
  either under a recovered semantic name or under its still-obfuscated native key;
- the native decoder additionally recovers current fields that the Asta snapshot still leaves
  obfuscated or omits semantically, including `failParent`, `forcePaimonGuidePriority`,
  `unfinishedHintShow`, `extraShowType` and `sharedNpcList`.

NPC ownership has an additional historical continuity result. Across rows shared with the
readable GCResource corpus, the current 7.1 `npcId` list matches historical
`exclusiveNpcList` exactly on 6,944 of 7,023 comparable rows (98.9%). The 79 differences are
list-content changes between game versions, not structural mismatches; the independent
`sharedNpcList` positive control is 106/106 exact. Product JSON therefore keeps the current
`npcId` spelling for compatibility and also exposes `exclusiveNpcList` as its semantic alias.
This is relevant to quest NPC ownership/conflict handling.

The scalar `DABNIJGHAPJ` is **not** promoted to `exclusiveNpcPriority`: no historical row
intersection proves that identity, and its 7.1 value distribution (for example 1314, 1321, 1335,
2222) does not follow the older priority distribution strongly enough to justify a rename.

This establishes an information-superset boundary for ordinary 7.1 Quest rows. It does not mean
all remaining native fields have recovered semantic names; unresolved values stay explicit in
`unknown` rather than being dropped or guessed.

### MainQuest root boundary

The same 4,417 exact 7.1 MainQuest IDs were compared at the root level against the AstaPS-Resource
snapshot. Asta has four additional materialized Quest files, so only the 4,417 shared exact-client
IDs are used for the native boundary.

Every root information field present in those shared Asta entries has a value source in the exact
7.1 `AFIOOHMJHDM` payload and is read by the maintained decoder. Confirmed root mappings include:

- `NBOJMAHCCGM -> descTextMapHash`: 3,741/3,741 identical presence and values;
- `DOOCLIPFECE -> titleTextMapHash`: 4,288/4,288 identical presence and values;
- `AKEAJELNNEN -> freeStyleDic`: 1,225/1,225 identical presence and values;
- `DKKIDDFEHMD -> forcePreloadLuaList`: 1,624/1,624 identical presence;
- `JNHHOJAPDPP -> preloadLuaList`: 1,824/1,824 identical presence;
- `DLLABGGCEBM -> talks`: 3,098/3,098 identical presence;
- `PCIAMAFDDAA -> dialogList`: 464/464 identical presence. The dialog element reader now also
  exposes its recovered `id` and `talkContentTextMapHash` fields;
- `JIJKODHIEED -> sub-quest array`: 4,381/4,381 identical presence.

The root `showRedPoint` name needed an independent historical control because current resource
converters disagree. Exact 7.1 layout places `HMJOIJHMGJD` at object offset `0xD5` and
`INFDFLBGLPD` at `0xA5`. Across 1,180 Quest IDs shared with the readable 2.2 corpus, historical
`showRedPoint` and the 7.1 `HMJOIJHMGJD` field have exact presence and value agreement on all
144 rows that carry the field. The `INFDFLBGLPD` field intersects historical `showRedPoint`
on only 2 rows. Therefore `HMJOIJHMGJD` is the supported `showRedPoint` mapping. The Asta
snapshot's `INFDFLBGLPD -> showRedPoint` rename is rejected; `INFDFLBGLPD` remains explicit
and unresolved until its own semantic identity is proved.

This establishes a MainQuest-root information-superset boundary for the exact 7.1 corpus. A
literal semantic-name superset is intentionally not claimed where a downstream label conflicts
with exact-client/historical evidence.

### Private-server runtime relevance

AstaPS still declares `trialAvatarList` and `gainItems` on its QuestData model, but the current
7.1 AstaPS-Resource `QuestExcelConfigData.json` contains neither field on any of its 33,217 rows.
Exact 7.1 client metadata likewise has no ordinary Quest field owner named for either list
(`_awardItems` survives only on `RandomQuestExcelConfig`). These two members are therefore
legacy compatibility slots for the current 7.1 private-server path, not missing native Quest
semantics. They are intentionally excluded from further recovery work unless a concrete 7.1
consumer/source appears.

For private-server quest progression, the remaining required data is already covered by either
the native Quest decoder (finish/fail conditions and execs, rewind/parent state, ordering, NPC/place
ownership, guide metadata) or the separately materialized QuestExcel compatibility layer
(`acceptCond`, `beginExec` and the condition-combination controls).

## Mondstadt private-server handler audit

The complete Mondstadt regression manifest currently contains 39 MainQuest files. Against the
reviewed AstaPS-Resource PR #14 snapshot
`6dc4400126f3b006028d24349faba8018cf9cecf`, their materialized finish/fail condition and
begin/finish/fail exec lists use only the following runtime type families:

- 19 QuestContent types: `ADD_QUEST_PROGRESS`, `CLEAR_GROUP_MONSTER`, `COMPLETE_TALK`,
  `DESTROY_GADGET`, `ENTER_DUNGEON`, `ENTER_MY_WORLD`, `ENTER_ROOM`,
  `FAIL_DUNGEON`, `FINISH_DUNGEON`, `FINISH_PLOT`, `GAME_TIME_TICK`,
  `INTERACT_GADGET`, `LUA_NOTIFY`, `NOT_FINISH_PLOT`, `OBTAIN_ITEM`, `SKILL`,
  `TEAM_DEAD`, `TRIGGER_FIRE`, and `UNLOCK_TRANS_POINT`;
- 20 QuestExec types: `ADD_CUR_AVATAR_ENERGY`, `ADD_QUEST_PROGRESS`,
  `CHANGE_AVATAR_ELEMET`, `DEL_PACK_ITEM`, `DEL_PACK_ITEM_BATCH`,
  `GRANT_TRIAL_AVATAR`, `LOCK_POINT`, `NOTIFY_GROUP_LUA`, `REFRESH_GROUP_MONSTER`,
  `REFRESH_GROUP_SUITE`, `REMOVE_TRIAL_AVATAR`, `ROLLBACK_QUEST`, `SET_IS_FLYABLE`,
  `SET_IS_GAME_TIME_LOCKED`, `SET_IS_WEATHER_LOCKED`, `SET_OPEN_STATE`,
  `SET_QUEST_GLOBAL_VAR`, `SET_WEATHER_GADGET`, `UNLOCK_AREA`, and `UNLOCK_POINT`.

AstaPS PR #71's CI-validated runtime tree
`4259b332fdfe9431eca12760cfb5c929ea6a7172` contains a registered implementation class for
every one of these 39 required types. No remaining Mondstadt mainline blocker is therefore explained
by a missing QuestContent/QuestExec handler class. Future client failures should be investigated in
resource values, condition/exec parameters, scene/Lua behavior, quest scheduling, or protocol/world
state before adding more generic handlers.

## Compatibility recovery boundary

Compatibility restoration is tracked in issue #20 and must preserve provenance classes:

- `client-native`;
- `compatibility`;
- `inferred`;
- `synthetic`;
- `unresolved`.

Current recovery checkpoint:

- `acceptCond`: 15,400 compatibility values, 12,913 compatibility/historical-empty classifications, 4,901 unresolved;
- `beginExec`: 4,838 compatibility values, 28,264 compatibility/historical-empty classifications, 112 unresolved.

Do not synthesize a previous-row chain and label it recovered. Do not treat agreement among related Luna/Asta resource descendants as independent version-native evidence.

## Rejected paths

- Do not search the QuestExcel row tail for prerequisite arrays; complete row consumption rejects that path.
- Do not force the `LAIMPNDEFCL` runtime/full-Quest layout onto the serialized QuestExcel wire.
- Do not treat public JSON field names as a native schema oracle.
- Do not infer current native ownership from historical community carry-forward.

## Maintenance state

The old topic-specific `probe-quest-table-assets.yml` workflow reached its retirement condition once the exact asset, row framing and ownership boundary became durable. Git history preserves its orchestration.

Further Quest compatibility work should use reusable code and focused evidence under #20. Temporary workflows require a new concrete orchestration need and retirement condition under `docs/governance.md`.
