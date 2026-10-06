# Quest native-resource research handoff

Checkpoint: 2026-10-06 12:10 +08:00

This file is the resumable handoff for the current Quest native-resource investigation. Continue from the branch and evidence below; do not restart the earlier manifest/XMF/ctable guessing work.

## Working branch

- Repository: `RinoPaw/Genshin-Reverse`
- Branch: `probe/quest-blb3-binoutput`
- Latest focused comparison head: `324f916b0d6caabb1b23e87d632bf01cd0278e81`
- Head message: `ci: require QuestExcel source comparison evidence`
- CI passed:
  - validate / tests: run `37411379239`
  - focused probe: run `37411379300`, job `112100344621`
- Focused probe artifact: `quest-row-prereq-schema`, artifact id `11389790544`, zip SHA256 `cb220b0a6def6c20f13daa37e7cf4c5ef61db40d02d59aff283c8181006231a3`.
- Durable #8 analysis:
  - `versions/7.1.0-global/windows-x64/analyses/quest-extraction/README.md`
  - `versions/7.1.0-global/windows-x64/analyses/quest-extraction/representative-comparison.json`

## #8 QuestExcel extraction / prerequisite corruption

Current status: **QuestExcel native asset extraction is solved. The earlier 351 prerequisite-corruption hypothesis has been materially weakened by exact 7.1 evidence; ExcelBin still needs direct verification.**

### Exact 7.1 QuestExcel asset chain — confirmed

The current deterministic chain is:

```text
Data/_ExcelBinOutput/QuestExcelConfigData
  -> MiHoYo 40-bit name hash 0x3B87AE8396
  -> design asset index 31049741.blk
  -> Raw MiHoYoBinData export 0000006f.dat
  -> sub_asset_id 178
  -> block_id 25539185
  -> group_id 0
  -> AssetBundles/blocks/00/25539185.blk
  -> Raw MiHoYoBinData export 3b87ae83.dat
  -> QuestExcel serialized payload
```

`.github/workflows/probe-quest-table-assets.yml` now asserts the chain above directly.

Exact recovered values from the pinned 7.1 Global sample:

- path: `Data/_ExcelBinOutput/QuestExcelConfigData`
- hash: `0x3B87AE8396`
- design index block: `31049741.blk`
- design-index Raw export: `MiHoYoBinData/0000006f.dat`
- `sub_asset_id = 178`
- `block_id = 25539185`
- `group_id = 0`
- QuestExcel Raw export: `MiHoYoBinData/3b87ae83.dat`
- Raw object size: `2,824,192` bytes
- payload size after MiHoYoBinData length prefix: `2,824,188` bytes
- leading unsigned varint: `7473`

The extraction step itself no longer depends on public `ExcelBinOutput` dumps.

### Asset-index format — confirmed enough for this chain

Reusable parser added in `genshinre/assetindex.py`, with tests in `tests/test_assetindex.py`.

Important 7.1 observations:

- `mihoyo_name_hash()` reproduces the current 40-bit asset-name hash.
- The 7.1 index remains structurally close to the Dedicatus545 / YSAssetIdx family.
- After the dependency count, current 7.1 data contains two `u32` words before dependency records.
- Each asset-to-block reference is currently parsed as:
  `asset_id, block_id, unknown0, unknown1`.
- In the observed design index, both trailing words are zero for all 536 records.

**Correction to an earlier hypothesis:** `unknown0` / `unknown1` are not proven byte `offset` / `size`. The exact 7.1 sample has both zero, so do not build payload slicing around them.

AnimeStudio can identify/export the target object inside `25539185.blk` directly, using the hash-derived Raw filename `3b87ae83.dat`.

### What is solved vs. still open

Solved:

1. exact Sophon block reconstruction;
2. exact asset-name hashing;
3. current 7.1 asset-index parsing;
4. `QuestExcelConfigData` -> native block resolution;
5. extraction of the exact current QuestExcel Raw object;
6. stripping the MiHoYoBinData length wrapper;
7. stable size / leading-varint invariants for regression checks.

Still open:

1. exact table container semantics after the leading varint;
2. per-row framing / row boundaries;
3. exact 7.1 Quest row deserializer;
4. prerequisite-related fields (`acceptCond`, payloads, combination mode, ordering/nesting);
5. deciding whether the prerequisite corruption originates in source data, native decode/schema, public extraction/post-processing, or AstaPS-Resource handling.

### 2026-10-06 update — exact 7.1 semantic control changed

This update invalidates several earlier assumptions about quest 351 prerequisites.

#### Exact same-version external control — confirmed

GitHub commit:

`DimbreathBot/AnimeGameData@792978e5503ecfba73dcb3562ed44a0d35a2abe2`

has commit title:

`CNRELWin7.1.0_R48379043_S48511369_D48533839`

Therefore it is a same-version **7.1.0 CNRELWin** data dump and is acceptable as a strong same-version cross-check.

Its `BinOutput/Quest/351.json` shows:

- subquests `35100` through `35107` all exist;
- **none of those rows has `acceptCond`**;
- `35101` still has `QUEST_CONTENT_TEAM_DEAD`;
- that failure still executes `QUEST_EXEC_ROLLBACK_QUEST 35100`;
- `35104` is still a hidden rewind-capable quest;
- the old prerequisite graph
  `35104 -> 35100 -> 35101`,
  plus `35102 OR` / `35103 AND`,
  is not present in current 7.1 BinOutput.

This directly means historical 3.x-era quest 351 prerequisite rows are not valid 7.1 semantic controls.

#### AstaPS-Resource current BinOutput agrees

`RinoPaw/AstaPS-Resource/BinOutput/Quest/351.json` was fetched directly and agrees with the 7.1 Dimbreath file on the points above:

- `35100..35107` have no `acceptCond`;
- `35101 TEAM_DEAD -> QUEST_EXEC_ROLLBACK_QUEST 35100`;
- order / guide / finish / rewind semantics match the same-version dump.

So the 7.1 BinOutput layer is internally consistent across both repositories.

#### AstaPS ExcelBin provenance — HIGH_CONFIDENCE downstream root cause

Focused run `37411379300` directly downloaded the current AstaPS file and confirmed:

- file size in the run: **51,009,089 bytes**;
- top-level rows: **33,217**;
- `35100..35107` all still contain legacy linear `QUEST_COND_STATE_EQUAL` prerequisites;
- `35104.acceptCond = [0,3]`.

Repository history then identified the assembly mechanism.

Upstream commit:

`MeChen618/AstaPS-Resource@7465e29b2d58058ab9973187c112abf2717ada03`

is `Update QuestExcelConfigData from BinOutput/Quest (#9)`.

Its PR body explicitly states:

- the old QuestExcel table lacked **7,956** subquests present in `BinOutput/Quest`, including the 7.x quest population;
- those rows were appended to reach 33,217 rows;
- because BinOutput had no `acceptCond` / `beginExec`, newly appended rows synthesized:
  - first step -> `QUEST_COND_STATE_EQUAL [0,3]`;
  - later step -> `QUEST_COND_STATE_EQUAL [previous step,3]`;
- existing rows kept their order/format and did not have `acceptCond` rewritten.

Therefore current AstaPS QuestExcel is a **mixed synthetic resource**: a legacy pre-7.x baseline plus later BinOutput-derived augmentation.

The current quest-351 rows sit at indices 9019..9026. Since PR #9 appended 7,956 rows to a pre-existing 25,261-row table, those 351 rows predate the augmentation. Their prerequisite graph is legacy-baseline contamination, not an exact 7.1 native decode.

This classifies the AstaPS-side prerequisite corruption mechanism as **HIGH_CONFIDENCE legacy resource/materialization drift**. It does not yet prove the exact client's native prerequisite representation.

#### Native class/type assumptions corrected

Several exploratory probes tested whether the normal QuestExcel row could be identified as:

- literal `QuestExcelConfig`;
- an owner with preserved fields such as `_subId`, `_mainId`, `_acceptCond`;
- an owner whose runtime field type is `QuestCond[]`;
- a direct native caller of `QuestCond.FromBinary(reader, kind_0x1D)`.

All four assumptions failed in current 7.1 metadata/native code:

1. no literal `QuestExcelConfig` type was found;
2. no preserved field-signature candidate was found;
3. no field runtime-typed as `QuestCond[]` was found;
4. direct xref scanning found no external caller of
   `QuestCond.FromBinary(reader, kind_0x1D) @ 0x115828F0`.

The only direct call found was the wrapper's self-chain:

`QuestCond.FromBinary(reader, kind_0x1D) @ 0x115828F0`
`-> QuestCond.FromBinaryInner(reader, kind_0x1D) @ 0x11582950`

This suggests either:

- the normal Quest row type/field types are more deeply obfuscated in 7.1;
- the array reader is reached through an indirect/vtable/function-pointer call;
- or the normal QuestExcel path uses a different condition representation than the historical `QuestCond[]` assumption.

Do not keep extending direct-call xref probes around `0x115828F0` unless new evidence points there.

#### RandomQuest investigation status

The earlier reverse work on `RandomQuestExcelConfig` and `RandomQuestCond` remains valid **for those concrete 7.1 types**, including their field layouts and binary transforms.

However, it is **not evidence that the normal `QuestExcelConfigData` table uses those types**. Keep that distinction explicit.

#### Current issue #8 interpretation

Two public/downstream corruption classes are now separated:

1. **AstaPS QuestExcel:** HIGH_CONFIDENCE legacy/synthetic resource contamination, proven by repository history and direct current-row comparison.
2. **Dimbreath same-version QuestExcel:** HIGH_CONFIDENCE field-name/schema misalignment. Representative evidence:
   - public `35104.acceptCondComb` contains a guide-shaped object;
   - public `35100.failParent = 573649119`, matching AstaPS `descTextMapHash = 573649119`;
   - public `35104.failCondComb = QUEST_HIDDEN`, matching the show-type family.

The guide-shaped `acceptCondComb` is incompatible with the exact native named-control constraint that accept/finish/fail combiners share type `PCBNKHFKLHI`.

The native client verdict remains UNRESOLVED because #8's promotion gate requires direct decode of the exact QuestExcel payload with the ordinary-row schema.

### Current native reverse direction

Do not continue treating `RandomQuestExcelConfig` as the ordinary/story Quest row.

Issue #19 / branch `research/quest-config-ownership-7.1` has a better exact-sample anchor:

```text
ordinary-row candidate       LAIMPNDEFCL
typeDefinition               17589
binary deserializer          GMENPOPMKAA(FNIAHJGHFAK)
deserializer RVA             0x9C15DF0
unified runtime facade       BEAEOMIOFDE
runtime consumer             MoleMole.QuestProxy
confirmed mainId offset      +0x70
confirmed subId offset       +0x74
confirmed order offset       +0xA8
```

The named `QuestProxy` getters and the ordinary-row deserializer provide exact native evidence for these mappings.

The next decisive #8 step is to bind `LAIMPNDEFCL.GMENPOPMKAA` to the exact
`Data/_ExcelBinOutput/QuestExcelConfigData` loader/table path, recover the condition/combiner fields, and decode the 2,824,188-byte payload with full consumption or an equally strong invariant.

Do not infer current field order from public JSON or historical class layouts.

### Resume here

1. Start from `probe/quest-blb3-binoutput` and read:
   - this handoff;
   - `versions/7.1.0-global/windows-x64/analyses/quest-extraction/README.md`;
   - #19 / `research/quest-config-ownership-7.1` evidence for `LAIMPNDEFCL`.
2. Treat AstaPS current QuestExcel as a mixed legacy/synthetic resource, not a 7.1 native dump.
3. Treat Dimbreath same-version Excel public field names as schema-drifted until native mappings validate them.
4. Reuse `LAIMPNDEFCL` typeDefinition 17589 and deserializer `0x9C15DF0`.
5. Bind that deserializer to the exact QuestExcel asset/table loader.
6. Recover native accept/finish/fail condition fields and combiner fields from exact read/access sites.
7. Decode representative rows from the exact 2,824,188-byte payload and require complete consumption.
8. Compare direct decode against:
   - current same-version BinOutput;
   - Dimbreath public Excel;
   - AstaPS mixed QuestExcel;
   - historical controls only where version-valid.
9. Promote #8 to CONFIRMED only after that direct-decode gate.
10. Do not mutate AstaPS-Resource prerequisites from public JSON alone.

### Known dead ends / do not repeat

- Do not use historical quest 351 prerequisite edges as 7.1 truth; exact 7.1 BinOutput has no `acceptCond` on `35100..35107`.
- Do not assume the normal QuestExcel row is literal `QuestExcelConfig`, has preserved `_subId/_mainId/_acceptCond` field names, or exposes a runtime `QuestCond[]` field.
- Do not continue scanning direct callers of `QuestCond.FromBinary(reader, kind_0x1D) @ 0x115828F0`; current executable has no external direct call to it.
- Do not guess `.xmf` manifest paths. The exact Sophon manifest exposes the needed `.blk` objects directly.
- Do not infer QuestExcel location from block filename order or block size.
- Do not return to speculative `ctable` guessing unless native evidence points there.
- Do not treat the two trailing asset-ref words as `offset/size`; current exact evidence contradicts that interpretation.
- Do not use old prerequisite values from historical 3.7/4.0 data for chapter 1301; those values degenerate to `QUEST_COND_UNKNOWN [0,0]` and are not safe restoration evidence.
- Do not mutate AstaPS-Resource prerequisites yet.

### Semantic controls already useful

For main quest 351 in current published resource evidence:

- `35101` has `QUEST_CONTENT_TEAM_DEAD`.
- That failure executes `QUEST_EXEC_ROLLBACK_QUEST 35100`.
- `Quest/351.json` and `QuestBrief/351.json` agree.
- `suggestTrackMainQuestList: [352]` is tracking/navigation metadata, not a prerequisite edge.

Use these only as semantic controls after native row structure is recovered.

## #9 Quest 351 persistent Return-to-quest-point state

Current status: `UNRESOLVED`. Keep this separate from QuestExcel extraction.

Exact 7.1 Global fresh-born anchor:

```text
DoSetPlayerBornDataNotify
CmdId               22899
client type         ONKOPMILDMF
typeDefinition      87483
handler owner       LLCGIEDMIIG
handler method      MACAMCMOKOL(ONKOPMILDMF)
handler RVA         0x0C227790
method index        322028
```

Historical restored clients show `LoadingManager.OnDoSetPlayerBornData()` calling `QuestModule.ResetTrackingLocalData([351])`. Treat this as a navigation clue only.

The resource relation `35101 TEAM_DEAD -> rollback 35100` is a separate gameplay rewind mechanism. Do not use it to explain the always-visible return button unless the current UI/state path directly links them.

Resume #9 only after or independently of #8:

1. trace direct callees from `0x0C227790`;
2. locate current quest tracking/navigation/rewind state writes;
3. map current equivalents of historical `ResetTrackingLocalData([351])`;
4. trace `UI_STC_MAIN_RETURN_TO_QUEST` state reads back to the enabling state;
5. build a truth table for fresh born, `35104 -> 35100 -> 35101`, actual rewind, and normal tracking;
6. patch lifecycle/protocol state only with current evidence.

## Repository / CI rules for the next session

- Keep exact-sample reverse evidence and durable conclusions in `Genshin-Reverse`.
- Temporary probe workflows may stay on this probe branch while the investigation is active; retire them when evidence becomes reusable code/docs.
- Use focused probes for reverse work; do not run heavyweight CI after every exploratory edit.
- Full required CI is mandatory before asking the user to test and before upstream submission.
- If user testing becomes necessary, provide one complete copy-paste command block including remote fetch, branch switch, dependency/build steps, and test/run command.
