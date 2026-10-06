# QuestExcel extraction / prerequisite corruption

Status: **CONFIRMED downstream prerequisite synthesis/materialization; exact 7.1 legacy row wire still UNRESOLVED**

Issues: #8, with #19 as the ordinary-row schema dependency.

Target: Genshin Impact 7.1.0 Global / Windows x64.

Pinned exact-client sample:

- EXE SHA256: `08a3086d5f3fe695f01dab61efa42e442006b18e5e475b2520df356f6a073b7d`
- global-metadata SHA256: `05ae04d7a91b91cc880217a56b0b01f3e67f845b06e894216654ec5d160e0da0`

## Exact native asset extraction

The exact 7.1 Global asset chain is confirmed:

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

Recovered invariants:

- Raw object size: 2,824,192 bytes
- payload after MiHoYoBinData length prefix: 2,824,188 bytes
- raw SHA256: `f068fc7f5dc0a0560ef0b145cdca14ee12910d0a3bc25a6332e2546f37650c87`
- payload SHA256: `07ab4816ee1eaa68fefd636b92dcfa923fe58a15731d18de0c0fb26863791fe5`
- the first bytes can be interpreted as unsigned varint `7473`, but this is **not** a confirmed table row count

This solves location/extraction of the exact asset. It does not yet solve the 7.1 legacy row framing or schema.

## Focused public-source comparison

Focused run `37411379300`, head
`324f916b0d6caabb1b23e87d632bf01cd0278e81`, completed successfully.

Artifact:

- name: `quest-row-prereq-schema`
- artifact id: `11389790544`
- artifact SHA256: `cb220b0a6def6c20f13daa37e7cf4c5ef61db40d02d59aff283c8181006231a3`

The comparison downloaded:

1. `DimbreathBot/AnimeGameData@792978e5503ecfba73dcb3562ed44a0d35a2abe2`
   - commit title: `CNRELWin7.1.0_R48379043_S48511369_D48533839`
   - QuestExcel JSON size in the run: 7,903,186 bytes
   - top-level rows: 17,814
2. current `RinoPaw/AstaPS-Resource/main`
   - QuestExcel JSON size in the run: 51,009,089 bytes
   - top-level rows: 33,217

## AstaPS-Resource QuestExcel is a mixed synthetic resource

The current AstaPS file must not be treated as an exact 7.1 native ExcelBin dump.

Upstream commit:

`MeChen618/AstaPS-Resource@7465e29b2d58058ab9973187c112abf2717ada03`

is titled:

`Update QuestExcelConfigData from BinOutput/Quest (#9)`

Upstream PR #9 explicitly states:

- the previous QuestExcel file was missing **7,956** subquests that were present in `BinOutput/Quest`;
- those missing rows included the 7.x quest population;
- new rows were appended until the table reached **33,217** rows;
- because BinOutput carried no `acceptCond` / `beginExec`, the PR synthesized:
  - first step: `QUEST_COND_STATE_EQUAL [0,3]`
  - later step: `QUEST_COND_STATE_EQUAL [previous step,3]`
- existing rows kept their order and formatting;
- only selected finish/fail condition/exec fields on existing rows were refreshed from BinOutput.

Therefore the current file combines:

1. a legacy pre-7.x QuestExcel baseline;
2. later BinOutput-derived rows;
3. heuristic prerequisite synthesis for the appended rows.

This is direct repository provenance, not an inference from gameplay.

### Consequence for quest 351

Current AstaPS QuestExcel still contains:

```text
35104 <- [0,3]
35100 <- [35104,3]
35107 <- [35100,3]
35101 <- [35107,3]
35106 <- [35101,3]
35105 <- [35106,3]
35103 <- [35105,3]
35102 <- [35103,3]
```

Those rows are at indices 9019..9026 in the current 33,217-row file.

PR #9 added 7,956 rows by appending them, so the pre-PR table had 25,261 rows. The 351 rows therefore predate that augmentation. PR #9 also says existing rows did not have their `acceptCond` rewritten. The current 351 prerequisite chain is therefore legacy-baseline data, not a current 7.1 native decode and not newly created by PR #9.

Current same-version `BinOutput/Quest/351.json` in both Dimbreath and AstaPS has no `acceptCond` on `35100..35107`.

This classifies the AstaPS 351 prerequisite drift as **legacy resource contamination/materialization drift** with HIGH_CONFIDENCE.

## Historical-native provenance closes the Quest 351 prerequisite question

The prerequisite provenance can now be classified independently of the still-unresolved
7.1 legacy row wire.

### Exact native 2.8

The exact official 2.8 QuestExcel asset is fully decoded with the historical wire:

- raw size: 3,830,872 bytes
- raw SHA256: `d11516d19a77e38c41f3b88aabc6fb6fe1277a57798633a96bc9da17e1df9877`
- single-byte XOR key: `0x98`
- row count: 12,158
- complete payload consumption: confirmed

Quest 351 contains historical prerequisite conditions in 2.8. The graph is not a simple
linear chain. In particular:

- 35100 depends on 35104;
- 35107 depends on 35100;
- 35101 depends on 35100;
- 35106 depends on 35101;
- 35105 depends on 35106;
- 35103 combines state-equal 35106 with state-not-equal 35105;
- 35102 accepts through an OR-style combination of 35103 and 35105.

### Exact native 3.2 and 3.4

The exact official assets were independently extracted and decoded with the same historical
QuestExcel family:

```text
3.2
  raw SHA256 891d83000eb3eb7382d7781bff12213b55159e7053c22312857a371fa4243c36
  XOR key    0x93
  row count  15818
  Quest 351 acceptCond: absent on all eight rows

3.4
  raw SHA256 c034b6ea8714f04d3c3ea8e31e3a944969ecef4fa804156ff046ffd516beaa64
  XOR key    0x95
  row count  16727
  Quest 351 acceptCond: absent on all eight rows
```

Therefore the old 351 prerequisite schema was already removed from the official client
QuestExcel by 3.2. A later resource that labels the old chain as 3.2+ data is a downstream
materialization.

### Community materialization path

A pinned community resource tool provides direct provenance evidence.

`233-Jerry/Grasscutter-Resources/Tool/QuestGC.js` loads both newer Quest data and
`QuestExcelConfigData_2.8.json`. For any subquest already present in 2.8 it explicitly
copies the old:

```text
acceptCond
finishCond
failCond
guide
finishExec
failExec
beginExec
```

into the newer materialized quest row.

The same repository documents its QuestExcel as modified and describes 3.0+ quest data as
incomplete. Its `MergeQuests.js` then uses a materialized
`QuestExcelConfigData (3.2).json` as the baseline when rebuilding
`BinOutput/Quest/*.json`. This explains how old prerequisite data propagated across both
public Excel and BinOutput directories.

### AstaPS initial resource is an additional synthesis

AstaPS first imported `QuestExcelConfigData.json` at commit
`8c85a82f37341a422002a0352c89a142c4017e53` with 25,261 rows.

Its Quest 351 prerequisite graph is:

```text
35104 <- [0,3]
35100 <- [35104,3]
35107 <- [35100,3]
35101 <- [35107,3]
35106 <- [35101,3]
35105 <- [35106,3]
35103 <- [35105,3]
35102 <- [35103,3]
```

This is a pure previous-row/order chain. It differs from the exact 2.8 native graph above,
so it cannot be described as an unmodified 2.8 carry-forward.

A full-table audit shows that the rule is systemic across the initial resource:

```text
mainId groups                         3,099
rows with STATE_EQUAL acceptCond     25,261 / 25,261
first rows exactly [0,3]              3,099 / 3,099
non-first exact previous-row [*,3]   21,489 / 22,162
all rows matching the linear rule    24,588 / 25,261 = 97.34%
groups fully matching the rule        2,759 / 3,099
```

This distribution is incompatible with a direct native-table dump. The previous-row
prerequisite is a repository-wide materialization convention with a minority of
exceptions/overrides, not a Quest 351 anomaly.

Later AstaPS-Resource PR #9 explicitly documents the same heuristic for newly appended
quests: first row gets `QUEST_COND_STATE_EQUAL [0,3]`, then each later row depends on the
previous row. The PR says this follows the "convention of the existing rows". Quest 351
predates PR #9, so PR #9 did not create its chain; it documents and reuses the already
present synthesis convention.

### Provenance verdict

For AstaPS Quest 351, the prerequisite chain is now **CONFIRMED downstream
synthetic/materialized data**.

This verdict does not require the exact 7.1 legacy row decoder:

1. official 2.8 preserves a more complex historical prerequisite graph;
2. official 3.2 and 3.4 no longer contain 351 `acceptCond`;
3. community tooling explicitly grafts old 2.8 quest logic into newer materializations;
4. AstaPS's initial 351 graph is a simplified order-derived chain, distinct from native 2.8;
5. AstaPS PR #9 explicitly identifies that same order-derived rule as an existing resource
   convention.

The exact 7.1 `3b87ae83.dat` decoder remains useful format archaeology, but it no longer
blocks the AstaPS provenance classification.

## Published 7.1 Excel field names are also misaligned

The same-version Dimbreath QuestExcel dump cannot be trusted by public field name alone.

Representative exact comparison:

- Dimbreath `35104.acceptCondComb` is a guide-shaped object:
  `{"guideScene":3,"param":["1005",...],"type":"QUEST_GUIDE_NPC"}`
- the corresponding AstaPS row places the same structure under `guide`.
- Dimbreath `35100.failParent = 573649119`;
- AstaPS `35100.descTextMapHash = 573649119`.
- Dimbreath `35104.failCondComb = "QUEST_HIDDEN"`;
- AstaPS `35104.showType = "QUEST_HIDDEN"`.

This is incompatible with exact native type constraints already recovered from the named
`RandomQuestExcelConfig` control: accept/finish/fail combiners share native type
`PCBNKHFKLHI`, so a guide-shaped value cannot be a valid `acceptCondComb`.

Classification: published 7.1 Excel JSON has **schema/field-name misalignment**.

This does not prove what the exact native ordinary Quest row stores. It proves that the
public JSON field labels are not a safe schema oracle.

## Ordinary Quest row direction

Do not continue using `RandomQuestExcelConfig` as the normal/story row.

Research from #19 provides the current high-value exact-sample candidate:

- typeDefinition: `17589`
- type: `LAIMPNDEFCL`
- ordinary binary deserializer candidate/confirmed binary-read method:
  `GMENPOPMKAA(FNIAHJGHFAK) @ 0x9C15DF0`
- unified runtime facade:
  `BEAEOMIOFDE`
- runtime consumer:
  `MoleMole.QuestProxy`

Named `QuestProxy` getter machine code confirms:

- `LAIMPNDEFCL +0x70 = mainId`
- `LAIMPNDEFCL +0x74 = quest config id / subId`
- `LAIMPNDEFCL +0xA8 = order`

Focused run `37414435078` (artifact `quest-ordinary-row-native`,
artifact id `11390607376`, SHA256
`e23221c2f491161bf30b49340c21cddfc1e3bd349f48d6fe1df3701321a30474`)
also resolves the four ordinary Quest content/exec arrays by exact facade branch
cross-mapping against the named `RandomQuestExcelConfig` variant.

The decisive `BEAEOMIOFDE` methods are:

- `FPNFFCCCGMO @ 0x8E9F6B0`
  - ordinary branch: `[facade+0x8] -> LAIMPNDEFCL +0x10`
  - random branch: `[facade+0x10] -> RandomQuestExcelConfig +0x28 (_failExec)`
- `EKGLIKLEEPG @ 0x8E9B300`
  - ordinary branch: `LAIMPNDEFCL +0x18`
  - random branch: `RandomQuestExcelConfig +0x50 (_failCond)`
- `LNFDDNGBBNG @ 0x8E9D890`
  - ordinary branch: `LAIMPNDEFCL +0x20`
  - random branch: `RandomQuestExcelConfig +0x30 (_finishCond)`
- `KKHAHMGGOBL @ 0x8E9D6B0`
  - ordinary branch: `LAIMPNDEFCL +0x58`
  - random branch: `RandomQuestExcelConfig +0x48 (_finishExec)`

Therefore the ordinary-row mapping is:

```text
LAIMPNDEFCL +0x10 = failExec
LAIMPNDEFCL +0x18 = failCond
LAIMPNDEFCL +0x20 = finishCond
LAIMPNDEFCL +0x58 = finishExec
```

Runtime type evidence independently agrees:

- `+0x10` and `+0x58` are `KIMCPAKMJMH[]`; the element type contains
  `QuestExecType` plus its parameter payload.
- `+0x18` and `+0x20` are `JPGNLOPMNHN[]`; the element type contains the
  `IPONFOFHKIJ` enum whose literals are the current `QUEST_CONTENT_*`
  family, including `QUEST_CONTENT_TEAM_DEAD`.

This is strong exact-native evidence that the ordinary 7.1 row directly carries
finish/fail content and exec data. It does **not** expose named equivalents of
the random-row `_acceptCond` or `_beginExec` fields among these four arrays.
Do not project the historical seven-list QuestExcel schema onto `LAIMPNDEFCL`.

Focused runs on head `0e93a4a9d40c483a97cb7e8093d0facb68db57c5`
(`CI #970`, focused run `37414435078`) also resolved the two previously unknown
ordinary-row object-array element types:

- runtime type index `495576 = KIMCPAKMJMH[]`;
  `KIMCPAKMJMH` contains `QuestExecType` plus string parameters;
- runtime type index `495577 = JPGNLOPMNHN[]`;
  `JPGNLOPMNHN` contains the current `QUEST_CONTENT_*` enum family, including
  `QUEST_CONTENT_TEAM_DEAD`.

The unified facade `BEAEOMIOFDE` then provides exact cross-variant mappings against
the named `RandomQuestExcelConfig` fields:

- `FPNFFCCCGMO @ 0x8E9F6B0`:
  ordinary `LAIMPNDEFCL +0x10` and random `_failExec +0x28` feed the same execution-content search path;
- `EKGLIKLEEPG @ 0x8E9B300`:
  ordinary `LAIMPNDEFCL +0x18` and random `_failCond +0x50` feed the same condition search path;
- `LNFDDNGBBNG @ 0x8E9D890` and `PIEPOFGEGIK @ 0x8E9B7A0`:
  ordinary `LAIMPNDEFCL +0x20` and random `_finishCond +0x30` feed the same condition path;
- `GGPGGIOLACH @ 0x8E9F810`:
  ordinary `LAIMPNDEFCL +0x58` and random `_finishExec +0x48` feed the same execution path.

Therefore the ordinary 7.1 row mappings are now:

```text
LAIMPNDEFCL +0x10 = failExec
LAIMPNDEFCL +0x18 = failCond
LAIMPNDEFCL +0x20 = finishCond
LAIMPNDEFCL +0x58 = finishExec
```

These are native cross-variant semantic mappings, not field-order guesses.

The ordinary row exposes no equivalent direct `acceptCond` or `beginExec` object-array
slot among these quest condition/execution fields. This materially strengthens the conclusion
that legacy public QuestExcel schemas cannot be projected onto the 7.1 ordinary row.

### Full/brief runtime index binding

Exact 7.1 native bootstrap and lookup evidence separates the full and brief
MainQuest binary indexes:

```text
Data/_BinOutput/IndexDic/MainQuestIndex
  string literal index 64807
  usage slot RVA 0x5A57B98
  LAABEAMHPJG bootstrap A @ 0xFCBBB40
  -> ODJJEFFIPFA static +0x31350
  -> ODJJEFFIPFA.LFDEMLPDDFL(uint32,uint64) @ 0x9F92800
  -> full loader LDJGPDBKIEO(uint32,Action,bool) @ 0x9F9A130
  -> AFIOOHMJHDM

Data/_BinOutput/IndexDic/MainQuestBriefIndex
  string literal index 64809
  usage slot RVA 0x5A57BA8
  LAABEAMHPJG bootstrap @ 0xFCBC530
  -> ODJJEFFIPFA static +0x312E0
  -> ODJJEFFIPFA.HGBAJLEGHGA(uint32,uint64) @ 0x9F891F0
  -> brief loader PFPFCHBANIH(uint32) @ 0x9F88D40
  -> FNJLMNMEKLN
```

The current 7.1 string-literal usage table satisfies
`slot_rva = 0x59D9260 + literal_index * 8` for these adjacent protected
literals, which independently binds the bootstrap slots to the recovered resource
names.

Do not use the brief `+0x312E0` path as the full MainQuest source. The full
351 resource lookup must follow `MainQuestIndex -> +0x31350 -> AFIOOHMJHDM`.

The native ordinary condition/exec array readers also recover their count
transforms:

```text
QuestExec[]:
  count = raw_u32 + 0xB0F7C9F4              (mod 2^32)

QuestContent[]:
  count = (raw_u32 + 0x9278C6C1) XOR 0x415C14AA
```

Each array then allocates exactly `count` elements and calls the corresponding
scalar `GMENPOPMKAA(FNIAHJGHFAK)` reader for every element.

### Quest 351 — direct native full-resource decode

The exact 7.1 full MainQuest resource is now directly extracted and decoded:

```text
Data/_BinOutput/Quest/351
MainQuestIndex handle  = 0x14B93FDA285D0829
design AssetIndex row  = 48670
bundle_hash            = 1
block_id               = 24230448
group_id               = 0
full payload size      = 920 bytes
```

The full payload starts directly with the `AFIOOHMJHDM` binary object.
Its 64-bit presence mask is:

```text
raw  = 0x28063327CE673865
mask = raw + 0xB19CC79B
     = 0x2806332880040000
```

The ordinary subquest array begins at file offset `0x3B`:

```text
encoded count = 0xA74F0AC3
count = encoded XOR 0xA74F0ACB = 8
first LAIMPNDEFCL row = 0x3F
```

The eight native rows are ordered `35100..35107`. Exact row starts are:

```text
35100  0x03F
35101  0x0A9
35102  0x136
35103  0x196
35104  0x1F8
35105  0x24F
35106  0x2B2
35107  0x327
row-array end 0x384
```

The row `subId` anchors independently agree with the native transform
`subId = raw_u32 XOR 0xAB3097F8`.

Core condition/exec arrays decoded directly from this payload are:

```text
35100 finishCond:
  QUEST_CONTENT_FINISH_PLOT   [35100, 0]
  QUEST_CONTENT_TRIGGER_FIRE  [1053, 0]

35101 failCond:
  QUEST_CONTENT_TEAM_DEAD     [0, 0]

35101 failExec:
  QUEST_EXEC_ROLLBACK_QUEST   ["35100"]

35101 finishCond:
  QUEST_CONTENT_TRIGGER_FIRE  [1100, 0]

35102 finishCond:
  QUEST_CONTENT_TRIGGER_FIRE  [1017, 0]

35103 finishCond:
  QUEST_CONTENT_TRIGGER_FIRE  [1016, 0]

35104 finishCond:
  QUEST_CONTENT_FINISH_PLOT   [35104, 0]

35105 finishCond:
  QUEST_CONTENT_TRIGGER_FIRE  [1016, 0]

35106 finishExec:
  QUEST_EXEC_LOCK_POINT       ["3", "1720"]

35106 finishCond:
  QUEST_CONTENT_UNLOCK_TRANS_POINT [3, 6]

35107 finishExec:
  QUEST_EXEC_REFRESH_GROUP_SUITE ["3", "133003429,1"]

35107 finishCond:
  QUEST_CONTENT_TRIGGER_FIRE  [1101, 0]
```

For the decisive 35101 failure path, the bytes independently recover:

```text
failCond element @ 0x0E7:
  QuestContentType = 21 = QUEST_CONTENT_TEAM_DEAD
  params = [0, 0]

failExec element @ 0x106:
  element mask = 0x24
  string[] count = 1
  decoded string = "35100"
  QuestExecType = 14 = QUEST_EXEC_ROLLBACK_QUEST
```

The numeric enum mapping is cross-checked against the current native enum names
and a pinned peer enum definition; it no longer depends on the published
Quest JSON for the failure semantics.

This directly confirms the 7.1 runtime behavior previously seen only as a
same-version semantic control: subquest 35101 fails on team death and rolls
the quest back to 35100.

The ordinary-row array itself consumes exactly `0x3F..0x383`; row 35107 ends
at `0x384`. The remaining 20 bytes are AFIO outer-container fields and decode
exactly as:

```text
0x384 bit49 uint64[]:
  encoded count = 0x740F8887
  count = encoded + 0x8BF0777A = 1
  element raw = 0xC8A1CA9556855C39
  value = (raw XOR 0xA6AA5B5A) + 0x729DC4AB
        = 14457059026087496718

0x390 bit37:
  0x321706FD XOR 0x32170514 = 1001

0x394 bit40:
  0x571F74B2 XOR 0x6B058DBD = 1008400655
```

These values correspond to the same-version materialized fields
`JNHHOJAPDPP = [14457059026087496718]`, `resId = 1001`, and outer
`NBOJMAHCCGM = 1008400655`.

The full 920-byte `Data/_BinOutput/Quest/351` payload therefore reaches
`0x398` with **zero unexplained trailing bytes**. This closes the native
full-consumption invariant for the representative MainQuest 351 resource.

All recovered ordinary-row finish/fail condition and execution arrays also
match the same-version `BinOutput/Quest/351.json` values exactly. For these
tested core runtime fields, the published same-version BinOutput is therefore
a faithful materialization of the native per-ID binary. This does not restore
or validate the legacy `acceptCond` chain in AstaPS QuestExcel.

The remaining #8 proof step is to bind this ordinary-row deserializer to
`Data/_ExcelBinOutput/QuestExcelConfigData` and decode the exact 2,824,188-byte payload
with full consumption or an equally strong invariant.

## Classification

Current layer-by-layer classification:

| layer | classification |
| --- | --- |
| exact 7.1 QuestExcel asset location/extraction | CONFIRMED |
| AstaPS current QuestExcel provenance | **CONFIRMED synthetic/materialized resource lineage** |
| AstaPS quest 351 prerequisite graph | **CONFIRMED downstream synthesis/materialization** |
| same-version Dimbreath QuestExcel public field labels | HIGH_CONFIDENCE schema/field-name misalignment |
| exact native ordinary finish/fail condition+exec representation | CONFIRMED field families/offsets |
| direct ordinary-row acceptCond / beginExec representation | no direct slot found; table-source relation still UNRESOLVED |
| exact 7.1 legacy QuestExcel row wire | UNRESOLVED; independent format archaeology |

The AstaPS Quest 351 prerequisite provenance is **CONFIRMED** from historical-native and
repository/tooling evidence. The exact 7.1 legacy table wire remains unresolved as a
separate format-research item; do not infer its physical 351 `acceptCond` contents until
that row format is decoded directly.

## Next steps

1. Treat the AstaPS prerequisite provenance as closed: the 351 order-chain is downstream
   synthesis/materialization.
2. Audit how broadly the same previous-row heuristic affects the 25,261-row initial resource
   and the 7,956 rows appended by PR #9 before changing AstaPS resources.
3. Check AstaPS runtime dependencies on synthetic `acceptCond`/`beginExec` before removal;
   current 7.1 native BinOutput/runtime conditions must remain the authority.
4. Keep exact 7.1 legacy `3b87ae83.dat` decoding as an independent format-research task.
   Do not force the 2.8/3.x row schema onto it: the current devkit scan tested 13,411 reader
   methods / 262 candidates and found no schema that consumed all Quest 351 windows exactly.
   A second pass built 342 plausible 7.1 reader schemas and found zero 8/8 field-transform
   matches for the observed 351 `subId` anchors.
5. If continuing the wire research, identify the 7.1 table container/reader from native
   registration or dynamic loading evidence, then require full-row and full-table structural
   consumption.
