# Quest native-resource research handoff

Checkpoint: 2026-10-05 14:55 +08:00

This file is the resumable handoff for the current Quest native-resource investigation. Continue from the branch and evidence below; do not restart the earlier manifest/XMF/ctable guessing work.

## Working branch

- Repository: `RinoPaw/Genshin-Reverse`
- Branch: `probe/quest-blb3-binoutput`
- Head before this handoff update: `0f1043fe71e96fb2357a39afc4b23e33d7389492`
- Head message: `ci: trace compact generic table owner initialization`
- CI at that head passed: run `37270563511`.
- Native-loader probe at that head also passed: run `37270563565`.

## #8 QuestExcel extraction / prerequisite corruption

Current status: **QuestExcel native asset extraction is solved. Row-field decoding and prerequisite semantics are still unresolved.**

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

### Current native reverse direction

The active workflow is `.github/workflows/probe-main-quest-excel-native.yml`.

Latest proven anchors used there:

```text
generic owner slot RVA  0x5AD4E98
type base slot RVA      0x5AD4E90
type resolver RVA       0x51CD50
known runtime type idx  476756
known generic handle    0x12F8
known generic type      List<uint>
```

The latest branch commits moved from the recovered QuestExcel payload into the current client's compact generic table/type registration path. The immediate task is to use these slots and their xrefs to recover the concrete generic owner/type pair for the QuestExcel table and then follow its initialization/read path into the row decoder.

Do not infer current field order from historical class layouts alone. Require native reads plus full-payload/full-row structural validation before assigning semantic names.

### Resume here

1. Start from branch `probe/quest-blb3-binoutput` and read this file plus:
   - `genshinre/assetindex.py`
   - `.github/workflows/probe-quest-table-assets.yml`
   - `.github/workflows/probe-main-quest-excel-native.yml`
2. Inspect artifacts/logs from native-loader probe run `37270563565`.
3. Continue the compact generic owner initialization trace from slot `0x5AD4E98` and resolver `0x51CD50`.
4. Resolve the actual QuestExcel table generic owner/type metadata pair.
5. Follow registration/initialization to the table reader and concrete Quest row deserializer.
6. Decode enough rows to prove framing and full consumption. Use representative quest ids with known semantics as controls.
7. Recover prerequisite fields only after structure is proven.
8. Compare direct exact-client decode with current published `ExcelBinOutput`, `BinOutput/Quest`, and AstaPS-Resource.
9. Only then classify and patch the prerequisite defect.

### Known dead ends / do not repeat

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
