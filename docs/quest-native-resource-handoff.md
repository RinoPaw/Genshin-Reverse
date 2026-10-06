# Quest native-resource research handoff

Checkpoint: 2026-10-06 18:28 +08:00

This file is the resumable handoff for the current Quest native-resource investigation. Continue from the branch and evidence below; do not restart the earlier manifest/XMF/ctable guessing work.

## Working branch

- Repository: `RinoPaw/Genshin-Reverse`
- Branch: `probe/quest-blb3-binoutput`
- Latest native-schema head with both total CI and focused probe passing:
  `0e93a4a9d40c483a97cb7e8093d0facb68db57c5`
- Head message: `ci: fix RandomQuest enum field sizing`
- CI passed:
  - total CI: #970 / run `37414435136`
  - focused ordinary-row probe: run `37414435078`
- Focused artifact:
  - name: `quest-ordinary-row-native`
  - artifact id: `11390607376`
  - SHA256: `e23221c2f491161bf30b49340c21cddfc1e3bd349f48d6fe1df3701321a30474`
- Earlier source-comparison evidence remains:
  - run `37411379300`
  - artifact id `11389790544`
  - SHA256 `cb220b0a6def6c20f13daa37e7cf4c5ef61db40d02d59aff283c8181006231a3`.
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

#### Ordinary finish/fail arrays — exact native cross-variant mapping

Focused run `37414435078` resolved the previously unknown ordinary-row object arrays:

- `495576 = KIMCPAKMJMH[]`, whose element carries `QuestExecType` and string params;
- `495577 = JPGNLOPMNHN[]`, whose element carries the current `QUEST_CONTENT_*` enum family.

The unified facade then cross-maps ordinary and named random-quest variants in the same methods:

```text
FPNFFCCCGMO @ 0x8E9F6B0
  LAIMPNDEFCL +0x10  <->  RandomQuestExcelConfig._failExec +0x28

EKGLIKLEEPG @ 0x8E9B300
  LAIMPNDEFCL +0x18  <->  RandomQuestExcelConfig._failCond +0x50

LNFDDNGBBNG @ 0x8E9D890
PIEPOFGEGIK @ 0x8E9B7A0
  LAIMPNDEFCL +0x20  <->  RandomQuestExcelConfig._finishCond +0x30

GGPGGIOLACH @ 0x8E9F810
  LAIMPNDEFCL +0x58  <->  RandomQuestExcelConfig._finishExec +0x48
```

Therefore:

```text
LAIMPNDEFCL +0x10 = failExec
LAIMPNDEFCL +0x18 = failCond
LAIMPNDEFCL +0x20 = finishCond
LAIMPNDEFCL +0x58 = finishExec
```

This is stronger than field-order inference: both facade branches perform the same semantic operation.

No direct ordinary `acceptCond` / `beginExec` object-array slot is present in this recovered field family. Do not project the legacy public QuestExcel schema onto the ordinary 7.1 row.

The next decisive #8 step is now narrower: bind `LAIMPNDEFCL.GMENPOPMKAA` to the exact
`Data/_ExcelBinOutput/QuestExcelConfigData` loader/table path, then establish table/row framing and decode the 2,824,188-byte payload with full consumption or an equally strong invariant.

#### Runtime Quest binary index and per-ID slices — exact native chain

Subsequent exact-sample probes show that the client does **not** deserialize the
2,824,188-byte QuestExcel payload directly as an `FNJLMNMEKLN[]` table.

The runtime Quest path has a separate binary index layer:

```text
ODJJEFFIPFA.HGBAJLEGHGA(uint32,uint64) @ 0x9F891F0
  quest/main id
  -> static index slot +0x312E0
  -> search by id
  -> 24-byte runtime index entry
  -> first qword = uint64 binary handle

PMOALIJHONP.GCJPJCKPGLI(uint64,int32,int32) @ 0x10175A00
  handle
  -> CommonMiscs / Runtime LoadBinData
  -> FNIAHJGHFAK reader

ODJJEFFIPFA.PFPFCHBANIH(uint32) @ 0x9F88D40
  -> new FNJLMNMEKLN
  -> FNJLMNMEKLN.GMENPOPMKAA(reader) @ 0x1269C5F0
  -> ODJJEFFIPFA.BECFLOFNBMM
  -> FNJLMNMEKLN.KICDJCPGADJ(AFIOOHMJHDM) @ 0x1269C4A0
  -> AFIOOHMJHDM runtime expansion
```

The direction of `KICDJCPGADJ` is **FNJ -> AFIO**. Earlier exploratory notes that
read it in the opposite direction are superseded.

The full and brief indexes are separate native resources and must not be
conflated:

```text
Data/_BinOutput/IndexDic/MainQuestIndex
  literal index 64807
  string usage slot RVA 0x5A57B98
  LAABEAMHPJG bootstrap A @ 0xFCBBB40
  -> static ODJJEFFIPFA +0x31350
  -> LFDEMLPDDFL(uint32,uint64) @ 0x9F92800
  -> LDJGPDBKIEO(uint32,Action,bool) @ 0x9F9A130
  -> AFIOOHMJHDM full config

Data/_BinOutput/IndexDic/MainQuestBriefIndex
  literal index 64809
  string usage slot RVA 0x5A57BA8
  LAABEAMHPJG bootstrap @ 0xFCBC530
  -> PMOALIJHONP.GCJPJCKPGLI(string,0,0)
  -> LDABEPAGBGK.GMENPOPMKAA(reader, generic-inst)
  -> static ODJJEFFIPFA +0x312E0
  -> HGBAJLEGHGA(uint32,uint64) @ 0x9F891F0
  -> PFPFCHBANIH(uint32) @ 0x9F88D40
  -> FNJLMNMEKLN brief config
```

The recovered protected-string usage table satisfies
`slot_rva = 0x59D9260 + literal_index * 8` for these adjacent literals, so
the resource-name-to-static-slot binding is exact. Earlier notes that treated
`+0x312E0` as the full MainQuest index are superseded.

For quest 351, continue the full-data path through `MainQuestIndex/+0x31350`,
not the brief `+0x312E0` path.


The exact specialized `LDABEPAGBGK` reader at `0x77F7860` recovers the
serialized index format:

```text
encoded_count : u32
count = (encoded_count XOR 0x5785D208) + 0x0A34766E

repeat count times:
    encoded_id     : u32
    encoded_handle : u64

    id     = encoded_id XOR 0x92C938B5
    handle = encoded_handle + 0x2B6567EA
```

The decoded pairs are inserted into the runtime ID -> uint64 handle container.
This matches the later 24-byte runtime search entries and the handle-based
`LoadBinData` path.

This index resource is a **different resource layer** from the exact
`Data/_ExcelBinOutput/QuestExcelConfigData` asset. Applying the index decoder
to the QuestExcel payload's first four bytes produces an impossible count, so do
not interpret the QuestExcel leading `7473` as this index count without a
separate direct linkage.

Current source-authority model:

```text
QuestExcelConfigData raw asset
    [exact extraction confirmed; native projection still unresolved]

separate Quest binary index resource
    id -> uint64 handle
        -> per-id binary slice
        -> FNJ compact config
        -> AFIO runtime expansion
        -> LAIMPNDEFCL[] ordinary subquests
```

A second source-shaped native type, `GPCFGOEJFJK` (typeDefinition 82662), has
36 fields and shares many exact obfuscated field names with `FNJLMNMEKLN`,
while also retaining extra strings/arrays. It has its own binary reader at
`0xCAB9080`. This is now the strongest candidate for an intermediate
source/runtime projection layer; its exact relation to QuestExcel/FNJ/AFIO is
being traced and is **UNRESOLVED**.

Do not infer current field order from public JSON or historical class layouts.

The exact ordinary-array readers additionally recover the current count transforms:

```text
KIMCPAKMJMH[] / QuestExec[]:
  count = raw_u32 + 0xB0F7C9F4                  (mod 2^32)

JPGNLOPMNHN[] / QuestContent[]:
  count = (raw_u32 + 0x9278C6C1) XOR 0x415C14AA
```

Both readers then deserialize exactly `count` scalar elements. Preserve these
transforms when implementing the direct 351 decoder.

### Direct native Quest 351 decode — current decisive evidence

The full 7.1 resource is now extracted through the exact MainQuestIndex handle:

```text
Data/_BinOutput/Quest/351
handle     0x14B93FDA285D0829
block      24230448
group      0
payload    920 bytes
reader     AFIOOHMJHDM.GMENPOPMKAA @ 0x10409D40
```

The AFIO ordinary-row field contains eight `LAIMPNDEFCL` entries. The encoded
row count at `0x3B` decodes to 8 with `raw XOR 0xA74F0ACB`; row 0 starts
at `0x3F`. Native row starts are currently:

```text
35100 0x03F
35101 0x0A9
35102 0x136
35103 0x196
35104 0x1F8
35105 0x24F
35106 0x2B2
35107 0x327
row-array end 0x384
```

The decisive 35101 failure data is directly decoded from the full binary:

```text
35101.failCond[0]
  QuestContentType 21 = QUEST_CONTENT_TEAM_DEAD
  params [0,0]

35101.failExec[0]
  QuestExecType 14 = QUEST_EXEC_ROLLBACK_QUEST
  params ["35100"]
```

The scalar exec reader reconstructs the five encoded parameter bytes to literal
`"35100"`; this is not copied from public JSON.

Other directly decoded core arrays:

```text
35100 finishCond = FINISH_PLOT [35100,0], TRIGGER_FIRE [1053,0]
35101 finishCond = TRIGGER_FIRE [1100,0]
35102 finishCond = TRIGGER_FIRE [1017,0]
35103 finishCond = TRIGGER_FIRE [1016,0]
35104 finishCond = FINISH_PLOT [35104,0]
35105 finishCond = TRIGGER_FIRE [1016,0]
35106 finishExec = LOCK_POINT ["3","1720"]
35106 finishCond = UNLOCK_TRANS_POINT [3,6]
35107 finishExec = REFRESH_GROUP_SUITE ["3","133003429,1"]
35107 finishCond = TRIGGER_FIRE [1101,0]
```

This promotes the 35101 team-death rollback behavior itself to direct native
evidence.

The ordinary-row array ends at `0x384`, after row 35107. The remaining
20 bytes are AFIO outer fields and decode exactly as:

```text
bit49 uint64[] count = 1
  value = 14457059026087496718
bit37 u32 = 1001
bit40 u32 = 1008400655
```

They correspond to `JNHHOJAPDPP[0]`, `resId`, and outer
`NBOJMAHCCGM`. The AFIO reader therefore consumes the complete 920-byte
payload through `0x398` with zero unexplained trailing bytes.

The directly recovered core finish/fail arrays match the same-version
`BinOutput/Quest/351.json` materialization exactly. Treat same-version
BinOutput core runtime fields as validated by native evidence for these tested
fields; this still does not validate AstaPS QuestExcel's legacy `acceptCond`
chain.

Remaining #8 work is to apply the same direct-decode invariant to additional
representative main quests and close the QuestExcel-vs-BinOutput
source-authority/projection relation.

### Resume here

1. Start from `probe/quest-blb3-binoutput` and read:
   - this handoff;
   - `versions/7.1.0-global/windows-x64/analyses/quest-extraction/README.md`;
   - #19 / `research/quest-config-ownership-7.1` evidence for `LAIMPNDEFCL`.
2. Treat AstaPS current QuestExcel as a mixed legacy/synthetic resource, not a 7.1 native dump.
3. Treat Dimbreath same-version Excel public field names as schema-drifted until native mappings validate them.
4. Reuse `LAIMPNDEFCL` typeDefinition 17589 and deserializer `0x9C15DF0`.
5. Keep the exact QuestExcel raw asset and the separate runtime ID->handle binary-index resource distinct until a projection bridge is proven.
6. Trace the strongest current bridge candidate `GPCFGOEJFJK` to FNJ/AFIO/LAIMPNDEFCL or to the QuestExcel loader.
7. Treat `+0x10 failExec / +0x18 failCond / +0x20 finishCond / +0x58 finishExec` as solved; do not reopen them without contradictory exact evidence.
8. Recover QuestExcel table/row framing and decode representative rows from the exact 2,824,188-byte payload with complete consumption.
9. Compare direct decode against:
   - current same-version BinOutput;
   - Dimbreath public Excel;
   - AstaPS mixed QuestExcel;
   - historical controls only where version-valid.
10. Promote #8 to CONFIRMED only after that direct-decode gate.
11. Do not mutate AstaPS-Resource prerequisites from public JSON alone.

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


## 2026-10-06 18:28 +08:00 checkpoint — legacy QuestExcel lineage localized

Research head immediately before this handoff update:

`0b5f86392410ad67694907e5594f812daca033ff`

At that head:

- total CI `#1082` / run `37450023931`: **SUCCESS**
- focused `Probe 3.0 legacy QuestExcel binary reader #4` / run
  `37450024126`: **SUCCESS**
- artifact: `quest-legacy-30`
- artifact id: `11406805727`
- artifact digest:
  `sha256:be844250454ee20083c97103bc49fabd95aa0d0198340eeedb834b9ef23bdaca`

This checkpoint supersedes the earlier instruction that called
`GPCFGOEJFJK` the strongest direct QuestExcel bridge candidate. GPC remains a
useful Quest-shaped peer, but current evidence does not bind it to the legacy
`acceptCond/beginExec` schema.

### Current #8 status

The 7.1 runtime/BinOutput side is effectively closed for the tested fields:

```text
MainQuestIndex
  -> per-main-quest uint64 handle
  -> Data/_BinOutput/Quest/<mainId>
  -> AFIOOHMJHDM
  -> LAIMPNDEFCL[]
```

Quest 351 has a full direct-native decode with zero unexplained trailing bytes.
The decisive fields remain:

```text
LAIMPNDEFCL +0x10 = failExec
LAIMPNDEFCL +0x18 = failCond
LAIMPNDEFCL +0x20 = finishCond
LAIMPNDEFCL +0x58 = finishExec
LAIMPNDEFCL +0x70 = mainId
LAIMPNDEFCL +0x74 = subId
LAIMPNDEFCL +0xA8 = order
```

For 35101 the exact 7.1 binary directly gives:

```text
failCond:
  QUEST_CONTENT_TEAM_DEAD [0,0]

failExec:
  QUEST_EXEC_ROLLBACK_QUEST ["35100"]
```

No direct ordinary-row `acceptCond` or `beginExec` array has been recovered in
the current 7.1 runtime row family.

### 7.1 current Quest Excel family — split resources

Current protected literals and loader probes identify live split Quest Excel
resources:

```text
Data/_ExcelBinOutput/MainQuestExcelConfigData
Data/_ExcelBinOutput/RandomQuestExcelConfigData
Data/_ExcelBinOutput/RandomMainQuestExcelConfigData
```

Current parser anchors:

```text
MainQuestExcelConfigData:
  HBGNNDLNDMA
  GMENPOPMKAA(FNIAHJGHFAK) @ 0xF955AF0

RandomQuestExcelConfigData:
  parser @ 0x9623050

RandomMainQuestExcelConfigData:
  parser @ 0x7B73030
```

For the current MainQuest loader, the table count is a native encoded `u32`
with the recovered transform:

```text
count = raw_u32 + 0x5D73654C   (mod 2^32)
```

Applying this current MainQuest loader to the exact legacy
`QuestExcelConfigData` payload head is invalid. The two resources do not share
the same table-loader constant/schema.

The exact 7.1 legacy asset still exists and remains extractable:

```text
Data/_ExcelBinOutput/QuestExcelConfigData
  -> hash 0x3B87AE8396
  -> block 25539185
  -> MiHoYoBinData/3b87ae83.dat
  -> payload 2,824,188 bytes
```

Its first four payload bytes are:

```text
raw_u32 = 0x40233AB1
```

Earlier interpretation of the first two bytes as a decisive
`uvarint = 7473` is **not a valid table-framing conclusion**. Native
ExcelBin loaders use encoded fixed-width count fields; retain 7473 only as an
observed byte-level value, not as row count.

The generic 7.1 candidate scans have not yet bound this payload to a live
`GMENPOPMKAA(FNIAHJGHFAK)` table loader. Do not infer that a complex count
transform is proven merely from those negative scans; several probe generations
were intentionally heuristic.

### GPCFGOEJFJK — downgrade from bridge candidate to Quest-shaped peer

`GPCFGOEJFJK`:

- typeDefinition `82662`
- 36 fields
- reader `GMENPOPMKAA(FNIAHJGHFAK) @ 0xCAB9080`
- shares many exact obfuscated field names with `FNJLMNMEKLN` / `AFIOOHMJHDM`

Representative shared fields include:

```text
IENDGAGOPMJ
OCIOMMBJGIJ
HCFFFJKMFPA
PDAOJONCGCJ
IFJEOOCLPHH
PHDIEJAPFJO
LCBNMMFPDFH
HGFFNBIGPJK
IOICBPNECAN
JICOFLMHAHF
KOKIIBLEHDM
HPJFIEEJAFG
AAGCICLNBHF
AIAHJOILLJA
NPILKCNEAAJ
NMNCIHHMLFP
FDOABBFPPKE
NEFEPBJBEPO
```

However:

- no metadata method directly cross-references GPC with FNJ/AFIO/LAIMPNDEFCL;
- GPC metadata does not expose named `acceptCond`, `beginExec`,
  `QuestCond`, or `QuestExec` evidence;
- its observed owners include gameplay/UI holders such as
  `JAJJIOOBGKA`, `JKHINCCKNLI`, and `NAJINHNANJA`.

Classification: **Quest-shaped peer / possible projection-related type, not a
proven legacy QuestExcel row.** Do not spend the next session trying to force
GPC into the old prerequisite schema without a new caller/path linkage.

### 7.1 source-row metadata ranking

The metadata ranking probe found the named
`MoleMole.Config.RandomQuestExcelConfig` as the strongest named control.
Its 28 fields explicitly include:

```text
_beginExec
_guideHint
_acceptCond
_failExec
_finishCond
_awardItems
_guide
_finishExec
_failCond
_unfinishedHintShow
_mainId
_showType
_subId
_showGuide
_titleTextMapHash
_banType
_acceptCondComb
_descTextMapHash
_failParent
_isRewind
_finishParent
_exclusiveNpcPriority
_forcePaimonGuidePriority
_finishCondComb
_failParentShow
_failCondComb
_order
_subIdSet
```

This remains useful as a named schema control only. It still must not be
projected directly onto ordinary 7.1 `LAIMPNDEFCL`.

### Version-lineage evidence — 6.7

Exact 6.7 Global sample:

```text
GenshinImpact.exe
  size   411,117,480
  sha256 3345106f56bc453264a15971333235b6c05f20dcfd116d6279605d2b2bf533d0

global-metadata.dat
  size   77,269,160
  sha256 1c6098f3238fae352ad883eace6503049e3fbf8966d6b534b2483573c3492689
```

Protected literal recovery succeeded for **80,971 literals** using pinned peer:

`kuma-dayo/gi-stringliteral@1008fd7db28dcbc55729d5bb6b3a585dab86cf8b`

Recovered Quest-related literals include:

```text
Data/_ExcelBinOutput/RandomQuestExcelConfigData
Data/_ExcelBinOutput/MainQuestExcelConfigData
Data/_ExcelBinOutput/RandomMainQuestExcelConfigData
Data/_ExcelBinOutput/LanV4QuestExcelConfigData
Data/_ExcelBinOutput/RainbowPrinceQuestExcelConfigData
Data/_ExcelBinOutput/ReunionV2QuestExcelConfigData
Data/_ExcelBinOutput/MarionetteTeaTimeQuestExcelConfigData
Data/_ExcelBinOutput/SorushTrialQuestExcelConfigData
Data/_ExcelBinOutput/TribalReputationQuestExcelConfigData
Data/_ExcelBinOutput/ThemeParkSimAvatarQuestExcelConfigData
Data/_ExcelBinOutput/ActivityTradeShowBonusQuestExcelConfigData
Data/_ExcelBinOutput/ActivityRockBoardExploreQuestExcelConfigData
Data/_ExcelBinOutput/ReputationQuestExcelConfigData
```

It also recovers named strings:

```text
acceptCondComb
acceptCond
beginExec
```

But the recovered literal set does **not** contain:

```text
Data/_ExcelBinOutput/QuestExcelConfigData
```

This is strong evidence that the monolithic ordinary QuestExcel path had already
been retired from the live literal-driven loader family by 6.7, while the named
RandomQuest schema still retained prerequisite-related fields.

### Version-lineage evidence — 4.2

Exact 4.2 sample selection reached the native Windows player layout:

```text
code:
  GenshinImpact_Data/Native/UserAssembly.dll
  size   237,787,152
  sha256 5d5293f53f908237eea7fae9ae0d1d636fc0f2b2777482bc5840422df275951b

metadata:
  GenshinImpact_Data/Managed/Metadata/global-metadata.dat
  size   45,598,888
  sha256 07a5c77a391fa2750d4991abc01be74af9da6b0aaa72fbb315160a8677d869d1
```

The pinned protected-string recovery method does not support this 4.2
obfuscation generation:

```text
ERROR: could not extract decryption logic ... (a new obfuscation generation)
```

Raw scans of the selected UserAssembly and metadata did not expose QuestExcel
names. Classification: **UNRESOLVED transition point**, not negative schema
evidence.

### Version-lineage evidence — 3.0 breakthrough

The successful 3.0 probe finally recovers the old monolithic QuestExcel loader
and named legacy field family directly from the client.

Exact 3.0 sample:

```text
UserAssembly.dll
  size   177,601,560
  sha256 b368b8959442f351143d16eb67d514520064897d1eeb37e0d3f544688bd4510b

global-metadata.dat
  size   49,356,392
  sha256 efd5a35bed23de3f1444d40ebf4eaa1dfb338c84d7a168a0264678f94cca5a2a
```

Named native anchors:

```text
QuestExcelConfigLoader.FILE_LOCATION
  RVA 0x10FC970

QuestExcelConfigLoader.FromBinary(ByteArray)
  RVA 0x10FD580
```

The 3.0 named field-target inventory contains the historical ordinary Quest
schema, including:

```text
subId
mainId
order
subIdSet
isMpBlock
descTextMapHash
stepDescTextMapHash
guideTipsTextMapHash
showType
banType

acceptCondComb
acceptCond
finishCondComb
finishCond
failCondComb
failCond

guide
showGuide
finishParent
failParent
failParentShow
isRewind

finishExec
failExec
beginExec

exclusiveNpcList
sharedNpcList
exclusiveNpcPriority
trialAvatarList
exclusivePlaceList
```

The focused field-access probe finds concrete native access windows for the key
legacy prerequisite members:

```text
acceptCond      : 26 observed instruction windows
acceptCondComb  : 2 observed instruction windows
beginExec       : 1 observed instruction window
```

It also observes accesses for finish/fail condition and exec families. The
current artifact did not recover a useful direct `mainId` access window, so do
not claim every listed field has an exact runtime offset yet.

This is decisive historical evidence that **`acceptCond`,
`acceptCondComb`, and `beginExec` were genuine members of the old ordinary
QuestExcel schema**. Their existence in old AstaPS-style QuestExcel material is
therefore not itself a public-dump naming accident.

### Updated root-cause model for AstaPS quest 351

The evidence now forms a coherent versioned chain:

```text
3.0 client:
  monolithic QuestExcelConfigLoader exists
  ordinary schema genuinely has acceptCond / acceptCondComb / beginExec

        ↓ schema/resource architecture evolves

6.7 client:
  monolithic Data/_ExcelBinOutput/QuestExcelConfigData path absent from
  recovered live literals
  split MainQuest / RandomQuest / RandomMainQuest resources exist

        ↓

7.1 client:
  exact legacy QuestExcelConfigData asset is still physically present
  live runtime main-quest authority is instead:
    MainQuestIndex -> per-id BinOutput -> AFIO -> LAIMPNDEFCL[]

        ↓

AstaPS current QuestExcel:
  pre-existing legacy rows retained
  7.x-missing rows later appended from BinOutput
  synthetic prerequisite chain added only for appended rows
```

For quest 351 specifically, its AstaPS rows predate the append operation.
Therefore the old 351 prerequisite chain is now best classified as:

**HIGH_CONFIDENCE legacy QuestExcel-era data inherited into a mixed modern
resource, while the tested 7.1 live runtime/BinOutput representation no longer
carries that prerequisite chain.**

This is stronger than the earlier repository-history-only classification because
the client version lineage now independently proves that the old ordinary
QuestExcel schema really contained those prerequisite members and that the live
resource architecture later split.

Still unproven:

1. whether the exact 7.1 packaged
   `Data/_ExcelBinOutput/QuestExcelConfigData` payload itself still contains
   the old 351 prerequisite chain;
2. whether that packaged asset is live compatibility data, dead/stale content,
   or consumed by a loader no longer reachable through the recovered literal
   path;
3. the exact 7.1 serialization mapping of its legacy
   `acceptCond/acceptCondComb/beginExec` fields.

Do not mutate AstaPS-Resource until one of those final direct checks closes the
source-authority question.

### Resume exactly here

Primary goal: close the last gap between the **3.0 named legacy row schema** and
the **7.1 physically present legacy QuestExcel asset**.

Recommended order:

1. Preserve the successful 3.0 artifact and continue from
   `QuestExcelConfigLoader.FromBinary(ByteArray) @ 0x10FD580`.
2. Recover the actual 3.0 row object layout/types for:
   - `subId`
   - `mainId`
   - `acceptCond`
   - `acceptCondComb`
   - `beginExec`
   - finish/fail condition and exec controls as cross-checks.
3. Identify the row-container/table reader called by the 3.0 loader and its
   count/row framing.
4. Test whether the exact 7.1
   `3b87ae83.dat` payload follows the same legacy serialization family.
5. If compatible, locate/decode 35100..35107 directly in the 7.1 legacy asset
   and compare the prerequisite bytes against:
   - old AstaPS rows;
   - 3.0 named schema;
   - current 7.1 per-id BinOutput.
6. If incompatible, locate the first version where the monolithic loader
   disappears. 4.2 remains the unresolved transition sample.
7. Promote #8 to CONFIRMED when either:
   - the 7.1 packaged legacy asset directly reproduces the old 351 prerequisite
     chain, proving stale legacy asset ingestion; or
   - the 7.1 asset does not, and a downstream schema/materialization transform
     is identified that creates the AstaPS chain.

Do not reopen:

- ordinary 7.1 finish/fail mappings;
- 35101 team-death rollback semantics;
- MainQuestIndex/full-vs-brief binding;
- GPC as a direct prerequisite-schema candidate without new caller evidence;
- the old `7473 = row count` hypothesis.

