# Quest native-resource research handoff

Checkpoint: 2026-10-07 20:12 +08:00

> This section supersedes the old #8 resume instructions below. The older
> 2026-10-05 material is retained as investigation history.

## 2026-10-07 active Quest handoff

Branch: `decoder/questexcel-native-71`

Checkpoint head before this handoff update:
`a15165181a086555161a841328393e340d64acb1`
(`probe: recover unresolved Quest fields from history`).

### What is closed

#### Exact 7.1 QuestExcel wire

The exact `Data/_ExcelBinOutput/QuestExcelConfigData` asset is recovered as
`MiHoYoBinData/3b87ae83.dat`.

- raw size: 2,824,192 bytes;
- serialized payload: 2,824,188 bytes;
- payload SHA256:
  `07ab4816ee1eaa68fefd636b92dcfa923fe58a15731d18de0c0fb26863791fe5`;
- 33,214 native rows;
- all recovered `subId` values are unique;
- every row is structurally consumed end to end by
  `genshinre.questexcel71`;
- every row ends with `raw_tail == b""`.

Therefore there is no hidden unparsed region in this QuestExcel wire that can
contain ordinary `acceptCond`, `beginExec`, `finishCond`, `failCond`,
`finishExec`, or `failExec` arrays.

Do not resume by searching the QuestExcel tail for those arrays.

#### Exact 7.1 ordinary full-Quest source

The separate full-Quest source path is proven on exact Quest 351.

- `Data/_BinOutput/Quest/351` payload size: 920 bytes;
- root reader `AFIOOHMJHDM` at RVA `0x10409D40`;
- root decode consumes 920/920 bytes;
- ordinary sub-quest array starts at offset 59;
- its count word `0xA74F0AC3 XOR 0xA74F0ACB = 8`;
- `LAIMPNDEFCL[]` wrapper: RVA `0x9C15C80`;
- ordinary row reader: RVA `0x9C15DF0`.

The four Quest object arrays on `LAIMPNDEFCL` are closed:

- `CNPOFCKIBDL : KIMCPAKMJMH[]` -> `failExec`;
- `KHEBAEMAPPJ : JPGNLOPMNHN[]` -> `failCond`;
- `DDFGFCPCNEH : JPGNLOPMNHN[]` -> `finishCond`;
- `FAPCNCGCEBJ : KIMCPAKMJMH[]` -> `finishExec`.

An exact runtime-type census found no fifth QuestExec array for
`beginExec` and no QuestCond owner for ordinary `acceptCond`.

The condition wire itself still exists and is decoded by
`genshinre.questcond71`. This is not contradictory: the format survives,
while the ordinary quest row no longer owns an `acceptCond` container.

Positive control: `MoleMole.Config.RandomQuestExcelConfig` still owns named
`_acceptCond : RandomQuestCond[]` and named begin/fail/finish exec/cond
fields in the same exact 7.1 metadata. The metadata pipeline therefore does
preserve those names when the field really exists.

#### Historical removal boundary

Exact-client evidence puts ordinary Quest prerequisite removal between 2.8
and 3.0.

- exact 2.8 QuestExcel still carries Quest 351 prerequisite conditions;
- exact 3.0/3.2/3.4 Quest 351 no longer carries them;
- exact 7.1 ordinary full-Quest source still has no `acceptCond` owner.

So modern ordinary `acceptCond` values are compatibility restoration data,
not 7.1 client-native fields.

### Asta synthetic-chain provenance

The initial flattened Asta import is:

`8c85a82f37341a422002a0352c89a142c4017e53`
(`Add ExcelBinOutput part 3 of 5`).

Its 25,261-row `QuestExcelConfigData.json` already follows the synthetic
physical-order rule almost everywhere:

- 24,588 / 25,261 rows = 97.335814%;
- first row -> `QUEST_COND_STATE_EQUAL [0,3]`;
- later row -> previous physical row subId, state 3;
- 2,759 / 3,099 main-quest groups match this rule on every row.

For Quest 351 that becomes the single chain:

`35104 -> 35100 -> 35107 -> 35101 -> 35106 -> 35105 -> 35103 -> 35102`.

This must never be promoted as recovered source semantics.

`MeChen618/AstaPS-Resource` PR #9, merge commit
`7465e29b2d58058ab9973187c112abf2717ada03`, then adds 7,956 rows from
BinOutput. Its PR description explicitly says current BinOutput has no
`acceptCond` / `beginExec`, then deliberately applies the same first-row /
previous-row fallback. This is the exact downstream expansion point of the
synthetic convention.

Historical repair controls are pinned to:

- `TomyJan/GCResource` `3700`:
  `609730bf63568baee1eb77a605b6c273a064dbc1`;
- `TomyJan/GCResource` `4000`:
  `ede70f1e23c1a494fe4258837d963b1d63004911`.

Their Quest 351 files are the identical Git blob
`1349ca8a9f15fc5ca6590cd8ce4ecdb04d0fae61`.

### Recovery model now in code

`genshinre.questrecovery71` keeps three evidence classes separate:

1. same-version client-native retained fields;
2. historical/community compatibility carry-forward;
3. unresolved fields.

It does not synthesize a previous-row chain.

Native 7.1 retained ordinary fields over 33,214 rows:

- `finishCond`: 32,683 non-empty;
- `failCond`: 5,156 non-empty;
- `finishExec`: 12,326 non-empty;
- `failExec`: 3,896 non-empty.

The later multi-source + leaked-TSV consensus run
`37615663201` reduced the compatibility gaps to:

- `acceptCond`:
  - 15,400 compatibility values;
  - 10,923 compatibility-empty;
  - 6,891 unresolved;
- `beginExec`:
  - 4,838 compatibility values;
  - 28,251 compatibility-empty;
  - 125 unresolved.

Do not use the older 10,657-row unresolved count as the current checkpoint.

The next historical-gap probe, run `37618117611`, checked those remaining
gaps against pinned older snapshots:

- `Hiro420/Binoutput_Deobfuscated@fe642068...`;
- `wangshengjj/Grasscutter3.4@8122c9aa...`;
- `TomyJan/GCResource@609730bf...`;
- `Kei-Luna/LunaGC_Resources_4.6.0@e7e0204a...`;
- `Rafs-kk/LunaGC-6.6-res@b0501c5d...`.

It found no new non-empty values and no conflicts, but it produced additional
historical-empty evidence:

- `acceptCond`: 1,990 more rows can be classified historical-empty,
  leaving 4,901 still unresolved;
- `beginExec`: 13 more rows can be classified historical-empty,
  leaving 112 still unresolved.

These last numbers are probe results at this checkpoint. They have not yet
been promoted into the durable recovery manifest policy.

### Useful semantic progress around Quest rows

`tools/decode_quest_json71.py` now maps additional MainQuest structural
fields including `talks`, `freeStyleDic`, `forcePreloadLuaList`, and
`dialogList`. These are likely useful for the remaining 4,901 / 112 rows,
because further progress now needs a different evidence class: quest topology,
talk/script relations, leaked design/server-side tables, or explicit semantic
inference.

QuestExcel/QuestGuide semantic promotion also recovered same-version
obfuscated names such as `FABHGLLGFHN`, `GCPCNAONCCJ`,
`HBCFHMLPNDB`, `OEPAPDEPHDO`, `MIEPHKGCBKC`, `CPHABDHIDKC`,
and `AEJMPEBJIHE`. Keep obfuscated names when the real semantic name is not
proved; an exact obfuscated owner is stronger evidence than a guessed English
name.

### Investigation lessons to keep

1. **Wire identity and runtime-object identity are separate.**
   `LAIMPNDEFCL` is the ordinary runtime/full-Quest row, but its wrapper is
   not the serialized `3b87ae83.dat` QuestExcel reader. Never force one
   layout onto the other.

2. **Full byte consumption is the strongest framing gate.**
   Require exact consume or an equally strong invariant before declaring that
   a field is absent or present.

3. **Public JSON is a control, not a schema oracle.**
   It may omit native fields, carry old fields forward, rename obfuscated
   fields, or inject synthetic compatibility data.

4. **Repository agreement is not independent evidence by default.**
   Luna/Asta/GC resources often share ancestry. Pin repository refs and,
   where useful, Git blob SHAs before calling two resources independent.

5. **No row is not the same as an empty field.**
   Treat historical absence as empty evidence only when a source actually
   contains the row and its serializer/default behavior supports that
   interpretation.

6. **`QUEST_COND_UNKNOWN [0,0]` is a placeholder.**
   Filter it from recovered prerequisite semantics.

7. **Never silently synthesize prerequisites.**
   A physical previous-row `STATE_EQUAL` chain is compatibility policy at
   best. It must never be labeled native or recovered.

8. **Keep provenance classes explicit.**
   Client-native, historical compatibility, inferred, and synthetic values
   must remain distinguishable in generated data.

9. **Do not let temporary CI policy slow reverse engineering.**
   Focused probe workflows are acceptable during research. Before asking the
   user to test or before upstream submission, retire/clean temporary probes
   as needed and run the required full CI.

### Resume from here

Priority order:

1. Promote the 1,990 `acceptCond` and 13 `beginExec`
   historical-empty decisions only if the evidence policy accepts the
   multi-snapshot absence rule.
2. Work the remaining 4,901 `acceptCond` and 112 `beginExec` rows from a
   new evidence class. Do not spend more time searching the already-exhausted
   known Luna/Asta siblings.
3. Use MainQuest `talks`, quest topology, script/Lua relations and other
   source-side resources to classify whether a missing field should be empty
   or has recoverable semantics.
4. Keep any graph-derived reconstruction explicitly `inferred`; do not mix
   it into the recovered/native layers.
5. Only after the recovery policy is stable, apply it to AstaPS-Resource.
6. Before user testing or upstream submission, run full required CI and give a
   complete fetch/branch/build command block.

---

Checkpoint: 2026-10-05

This file preserves the current resumable state for issues #8 and #9. It records only evidence that was reproduced or independently checked during the current investigation. Do not use it to justify AstaPS-Resource data edits until the promotion gates below are met.

## #8 QuestExcel extraction / prerequisite corruption

Current status: `UNRESOLVED`, active native-resource investigation.

### Confirmed resource-access progress

- The exact 7.1 Global Sophon manifest contains 2744 files.
- 1987 entries are under `AssetBundles/blocks/**/*.blk`.
- The earlier `blocks.xmf` / `.xmf` manifest-path assumption is rejected for this sample; that probe returned no usable `.xmf` candidate.
- `.github/workflows/probe-quest-table-assets.yml` now reconstructs small exact-sample AssetBundle block entries directly through `genshinre.samplefetch.reconstruct` instead of assuming an index filename.
- Workflow run `37225861093` at head `4a6a41774b2a9b34d8fd70c29ad8f1c63d96945a` completed successfully. This proves the small-block reconstruction path works against the pinned manifest/chunk source. Content classification of those reconstructed blocks is still pending.

Do not infer QuestExcel storage from block filename order, block size, or public dump layout. The next proof step is to identify the block/index relationship and the exact table blob or loader path.

### Exact/current quest evidence already useful as controls

Pinned 7.1 published resource evidence for main quest 351 gives a useful semantic control:

- `35101` has a `QUEST_CONTENT_TEAM_DEAD` fail condition.
- That failure executes `QUEST_EXEC_ROLLBACK_QUEST 35100`.
- `Quest/351.json` and `QuestBrief/351.json` agree on this relationship.
- `suggestTrackMainQuestList: [352]` is tracking/navigation metadata and must not be reinterpreted as a prerequisite edge.

This evidence is useful for validating a recovered Quest row schema, but it does not prove where prerequisite corruption is introduced.

### Important boundaries

- Public `BinOutput/Quest/*` and `ExcelBinOutput/QuestExcelConfigData.json` remain separate evidence layers.
- Missing/shifted public fields are not negative evidence for exact-client serialization.
- Field ordinal/name assumptions from older extractors are unsafe. Recover current field reads from the exact 7.1 row deserializer and validate by full-byte consumption or an equivalently strong invariant.
- Chapter 1301 remains an important current-version control because historical 3.7/4.0 prerequisite data degenerates to `QUEST_COND_UNKNOWN [0,0]`; do not restore those old values.
- No new AstaPS-Resource quest prerequisite mutation is justified by the current native-resource work yet.

### Resume here

1. Inspect the artifacts from run `37225861093` and classify the reconstructed small `.blk` files by magic/header/contained strings or tables.
2. Use the block/index relationship from current client tooling or independently reconstructed format knowledge to locate the exact `Data/_ExcelBinOutput/QuestExcelConfigData` payload.
3. Locate the exact 7.1 path literal, loader, and row deserializer in the pinned executable/metadata sample.
4. Recover prerequisite-related row fields (`acceptCond`, payloads, combination mode, ordering/nesting) from native reads.
5. Require full payload consumption or an equally strong structural validation before semantic naming.
6. Compare representative rows across direct exact-client decode, current published Excel JSON, current `BinOutput/Quest`, and historical consensus.
7. Only after that classify the defect as client-table, schema/decoder, post-processing, or unresolved.

## #9 Quest 351 persistent Return-to-quest-point state

Current status: `UNRESOLVED`. Keep this problem separate from the QuestExcel extraction problem.

### Confirmed/current anchors

The exact 7.1 Global client anchor already known for the fresh-born entrypoint is:

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

Historical restored clients show `LoadingManager.OnDoSetPlayerBornData()` calling `QuestModule.ResetTrackingLocalData([351])`, touching a tracking/navigation state cluster. This remains a high-value navigation clue only; it is not current-7.1 proof.

The exact 351 resource relationship `35101 TEAM_DEAD -> rollback 35100` is a separate gameplay rewind mechanism. Do not use it as an explanation for the always-visible return button unless the current client UI/state path explicitly links them.

### Resume here

1. Trace direct callees from `0x0C227790` with the pinned 7.1 executable.
2. Identify current methods that touch quest tracking/navigation/rewind state or carry main-quest id `351`.
3. Map the current state transition against the historical `ResetTrackingLocalData([351])` structural clue.
4. Trace `UI_STC_MAIN_RETURN_TO_QUEST` presentation/state reads back to the enabling flag/state.
5. Build a minimal truth table for fresh born, `35104 -> 35100 -> 35101`, actual rewind, and normal tracking.
6. Only then recommend an AstaPS lifecycle/protocol correction. Do not suppress the UI heuristically.

## Server-side cross-check still open

AstaPS contains an `ExecRollbackQuest` implementation, but this checkpoint has not yet completed the full audit of how `QUEST_CONTENT_TEAM_DEAD` is emitted/consumed in the current server path. Do not conclude that the server-side rollback path is complete or broken from the resource evidence alone.

## Repository hygiene

- Keep exact-sample evidence and durable conclusions in Genshin-Reverse.
- Keep investigation-only probes/workflows temporary and retire them after their outputs become durable artifacts or reusable tools.
- Do not use CI as the normal interactive reverse loop. Cheap focused probes are acceptable during research; full required validation is mandatory before asking the user to test, upstream submission, or canonical artifact publication.