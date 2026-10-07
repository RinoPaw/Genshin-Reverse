# QuestExcel extraction checkpoint

Status: `UNRESOLVED`

Target: Genshin Impact 7.1.0 Global / Windows x64, using the pinned `NativeProfile` for this version directory.

This note preserves exploratory parameters from temporary GitHub Actions before those one-off orchestration shells are retired. The values below are research anchors only. They are not semantic promotion evidence and must be revalidated against the exact sample before use in a conclusion.

## Active hosted orchestration

`probe-quest-table-assets.yml` remains `active-temporary` for issue #8. Workflow run `37225861093` at commit `4a6a41774b2a9b34d8fd70c29ad8f1c63d96945a` successfully reconstructed small exact-sample AssetBundle block entries. Classification of those reconstructed blocks and recovery of the block/index relationship are still pending.

## Retired one-off workflow classification

| Workflow | Classification | Durable replacement / reason |
| --- | --- | --- |
| `probe-blocks0.yml` | `retire-now` | Superseded by the current small-block reconstruction path in `probe-quest-table-assets.yml`; the older single-file `blocks0.blk` inspection is no longer the active storage hypothesis. |
| `probe-quest-accept-loader.yml` | `retire-now` | One-shot disassembly/call-edge orchestration. Generic disassembly and call-edge tooling remains available; candidate RVAs are preserved below. |
| `probe-quest-excel-metadata.yml` | `retire-now` | Pure queries over committed metadata CSVs; no hosted exact-sample orchestration is required. |
| `probe-quest-excel-native.yml` | `retire-now` | One-shot exact-sample disassembly using retained generic tooling; candidate RVAs/type indexes are preserved below. |
| `probe-random-quest-cond.yml` | `retire-now` | One-shot exact-sample disassembly/call-edge probe; retained generic tooling covers the operation. |
| `scan-7.1-field-displacements.yml` | `retire-now` | Generic implementation already lives in `tools/scan_field_displacements.py`. |
| `trace-7.1-native-call-edges.yml` | `retire-now` | Generic implementation already lives in `tools/trace_native_call_edges.py`. |

Git history preserves the retired orchestration and console-oriented probe code. Do not treat the presence of a historical workflow as evidence that its old interpretation was correct.

## Preserved exploratory native anchors

These addresses and type indexes came from the retired Quest probes and are kept only to make the investigation resumable:

| Label used by probe | Exploratory anchor |
| --- | --- |
| `RandomQuestExcelConfig` candidate type | typeDefinition `36711` |
| `QuestCond` candidate type | typeDefinition `54128` |
| XLua Quest-row wrapper candidate | typeDefinition `73929` |
| `RandomQuestCond` candidate type | typeDefinition `76090` |
| `RandomQuestExcelConfig.FromBinaryInner(reader)` candidate | RVA `0x0CF246E0` |
| `QuestCond.FromBinary(reader)` candidate | RVA `0x11582570` |
| `QuestCond.FromBinaryInner(reader)` candidate | RVA `0x115825D0` |
| accept-condition loader candidate | RVA `0x0B6473F0` |
| `RandomQuestCond.FromBinaryInner(reader)` candidate | RVA `0x0B647530` |

None of these anchors proves that the decoded row is the exact serialized `Data/_ExcelBinOutput/QuestExcelConfigData` row required by issue #8. In particular, earlier field-name and loader assumptions may refer to adjacent RandomQuest/config paths rather than the target QuestExcel table.

## Current evidence boundary

The current durable handoff is `docs/quest-native-resource-handoff.md`. It establishes that the exact 7.1 Sophon manifest contains 1,987 `AssetBundles/blocks/**/*.blk` entries and that direct small-block reconstruction works. It also rejects the earlier `.xmf` manifest-path assumption for this sample.

The next accepted proof step remains:

1. identify the current block/index relationship;
2. locate the exact QuestExcel table blob or exact load path;
3. bind the target row deserializer from current native evidence;
4. recover prerequisite-related fields without relying on old field ordinals/names;
5. require full payload consumption or an equivalently strong structural invariant;
6. compare direct exact-client decode against published Excel JSON, `BinOutput/Quest`, and historical controls.

Until that gate is met, prerequisite corruption root cause stays `UNRESOLVED`.


## 2026-10-07 exact 7.1 wire checkpoint

The exact serialized QuestExcel object is now framed reproducibly by
`genshinre.questexcel71`.

Exact-client invariants:

- Raw MiHoYoBinData export: 2,824,192 bytes.
- Serialized payload: 2,824,188 bytes.
- Payload SHA256: `07ab4816ee1eaa68fefd636b92dcfa923fe58a15731d18de0c0fb26863791fe5`.
- Four-byte table header: `0x40233AB1`.
- Native row count: 33,214.
- First row start: payload offset `0x4`.
- Every row ends with a four-byte transformed identity:
  `subId = raw_u32 XOR 0xB1571A55`.
- All 33,214 recovered subIds are unique.
- The last recovered row ends exactly at payload offset 2,824,188.
- Therefore row framing consumes the complete payload. This proves framing,
  not complete row semantic decoding.

The current conservative parser additionally validates these prefix rules:

- raw mask bit 37: an optional uint32 array matching same-version
  `exclusivePlaceList`; count is `raw XOR 0xB51E6D91`, each element is
  `raw - 0x449FCFB9 (mod 2^32)`;
- raw mask bit 29: optional scalar with exact raw value `0x8BFDD679`,
  matching the same-version `PREFER_AREA2_GUIDE_SCENE` population;
- raw mask bit 57: `order` presence, 33,213/33,213 same-version matches,
  decoded as `raw_u32 - 0x732ED834`;
- raw mask bit 52: `isMpBlock = true`, 2,923/2,923 matches, encoded by
  the single byte `0xDA`;
- raw mask bit 34: 46/46 same-version occurrences of the extra-show value
  `QUEST_SHOW_ON_FOCUS_REQ`, encoded by `0x074282C5`. The package keeps
  this field structurally named until native semantic ownership is closed.

The exact-asset parser run reports 2,074,613 row-body bytes still opaque after
the currently proven prefix rules. Unknown bytes are deliberately retained
instead of being assigned public field names.

### LAIMPNDEFCL reader is not this serialized QuestExcel wire

Issue #19 proves that `LAIMPNDEFCL` is the ordinary/non-random runtime quest
config variant. That runtime identity must not be confused with serialized
source identity.

Exact disassembly of its array wrapper at RVA `0x9C15C80` reads a four-byte
count as:

`count = raw_u32 XOR 0xA74F0ACB`

and then repeatedly invokes `LAIMPNDEFCL.GMENPOPMKAA` at RVA
`0x9C15DF0`. The exact QuestExcel table header `0x40233AB1` does not
decode to 33,214 under that rule, so this wrapper cannot directly consume the
`3b87ae83.dat` payload.

The inner reader is independently incompatible with the observed QuestExcel
row prefix. It transforms its eight-byte mask with `+0x2244ECE7` and, for
common exact QuestExcel row masks, its early active-field sequence would
consume the second post-mask u32 under a different field transform. In the
exact QuestExcel payload that position is already independently validated as
`order` with `raw - 0x732ED834`.

Therefore the current `0x9C15C80 / 0x9C15DF0` reader pair is rejected as the
direct serialized reader for this exact QuestExcel blob. `LAIMPNDEFCL` may
still be a downstream runtime projection/consumer; that materialization path
remains open.

This negative binding is important: do not force the 35-field runtime object
layout onto `3b87ae83.dat`.

### Next decoder gate

The next target is the real serialized QuestExcel table/row reader or an
equivalent byte-exact reconstruction of its remaining row body. Public
QuestExcel/BinOutput JSON remains comparison evidence only. A field is not
promoted solely because a public label correlates with a raw offset.

## 2026-10-07 complete QuestExcel row-consumption checkpoint

This checkpoint supersedes the earlier statement that 2,074,613 row-body bytes
remain opaque. The exact 7.1 `3b87ae83.dat` row body is now structurally
consumed end to end by `genshinre.questexcel71`.

Exact-client invariants now include:

- all 33,214 rows still use the previously proven framing and unique transformed
  `subId` suffix;
- the physical guide boundary is derived directly from the outer row mask and
  preceding fields; the maintained parser no longer searches for a plausible
  guide start;
- `QuestGuideHint71` and `QuestGuide71` are decoded with their recovered
  native masks, scalar transforms, string lengths, block transforms, and field
  order;
- the outer row sequence between guide-hint and guide is closed as
  `subIdSet -> EOFPICJEHLP -> failParentShow -> showGuide -> DABNIJGHAPJ ->
  fixed u32 A -> mainId -> optional LBEFPHGELAN`, with absent optional fields
  skipped according to the recovered row mask;
- the sole bit-61 row uses one byte `0x87` for `LBEFPHGELAN = true`;
- `mainId = ((raw + 0x0001B716) mod 2^32) XOR 0x32238F7D` matches
  33,214/33,214 same-version controls;
- present `subIdSet` decodes as
  `((raw XOR 0x01B9521A) + 0xA5772739) mod 2^32` and matches
  1,570/1,570 same-version controls;
- the row +8 slot decodes as
  `descTextMapHash = raw XOR 0x2AC0BB5D`; all 29,124 controls that retain
  that field match exactly. The remaining 4,090 downstream controls omit the
  field even though the native slot still carries a value;
- `stepDescTextMapHash = raw XOR 0xABB3B4F1` and the trailing
  `guideTipsTextMapHash = raw XOR 0x59B7A2F4` are fixed physical slots even
  when downstream projections omit them;
- after parsing the recovered fields and preserving the one still-unresolved
  fixed-core u32 structurally, every row has `raw_tail == b""`.

The last point is a byte-consumption result, not a claim that every obfuscated
scalar already has a semantic name. Unknown values remain explicit raw
fields until their native ownership is proved.

### Consequence for condition and execution arrays

The complete native row layout has no remaining unparsed byte region that can
hold in-row object arrays corresponding to downstream
`acceptCond`, `beginExec`, `finishCond`, `failCond`, `finishExec`,
or `failExec`.

This does not prove that the game has no such quest logic. It proves that those
downstream arrays are not serialized as unparsed arrays inside this exact
`3b87ae83.dat` QuestExcel row wire. They must be supplied by another source,
a downstream full-quest materialization path, or a merge/projection stage.

That boundary is consistent with the independent historical evidence:
Quest 351 has native prerequisite conditions in the exact 2.8 QuestExcel
asset, while exact 3.0/3.2/3.4 controls no longer carry those Quest 351
prerequisites, and Asta-derived modern resources later re-materialize a
predecessor chain.

### Remaining semantic work

The direct 7.1 QuestExcel decoder is now structurally complete. Remaining work
is semantic promotion and source ownership:

1. identify the first fixed-core u32 that remains structurally preserved;
2. close the native names for bit 34, bit 40, and any still-obfuscated guide
   scalars;
3. trace the separate full-quest source/materialization path that supplies
   condition and execution arrays;
4. compare that path against AstaPS/resource merge logic to locate the exact
   prerequisite-corruption boundary.

## 2026-10-07 exact 7.1 full-quest source checkpoint

The separate full-quest source path is now byte-exactly demonstrated on Quest
351.

The exact `Data/_BinOutput/Quest/351` serialized payload is 920 bytes. After
registering the exact 7.1 BinConfig string helper (RVA `0xFD53090`) and
managed-array allocator (RVA `0x50B230`) with the pinned schema analyzer,
the native `AFIOOHMJHDM` root reader at RVA `0x10409D40` consumes
**920/920 bytes**.

The ordinary sub-quest array begins at payload offset 59. Its count word is
`0xA74F0AC3`; the native `LAIMPNDEFCL[]` wrapper at RVA
`0x9C15C80` decodes it as:

`0xA74F0AC3 XOR 0xA74F0ACB = 8`.

That array consumes offsets 59..900 and yields the eight Quest 351 ordinary
rows. The root reader consumes the remaining 20 bytes and ends exactly at
offset 920.

Native call-site writes bind the four object-array fields in
`LAIMPNDEFCL.GMENPOPMKAA`:

- `this + 0x58`: `KIMCPAKMJMH[]` / QuestExec array, matching
  same-version `finishExec`;
- `this + 0x18`: `JPGNLOPMNHN[]` / QuestContent array, matching
  `failCond`;
- `this + 0x10`: `KIMCPAKMJMH[]` / QuestExec array, matching
  `failExec`;
- `this + 0x20`: `JPGNLOPMNHN[]` / QuestContent array, matching
  `finishCond`.

The exact decoded values agree with the pinned same-version Quest 351
BinOutput control. Representative native values include:

- 35100 `finishCond`: type codes 4 and 6 with params
  `[35100, 0]` and `[1053, 0]`;
- 35101 `failCond`: type code 21 with params `[0, 0]`;
- 35101 `failExec`: type code 14 with string params `["35100"]`;
- 35106 `finishExec`: type code 17 with string params
  `["3", "1720"]`;
- 35106 `finishCond`: type code 23 with params `[3, 6]`;
- 35107 `finishExec`: type code 19 with string params
  `["3", "133003429,1"]`.

The ordinary native row reader contains exactly these four QuestExec /
QuestContent object-array calls. No fifth or sixth Quest object-array field is
present for `acceptCond` or `beginExec`. This independently closes the
same boundary already implied by complete QuestExcel row consumption:
modern 7.1 ordinary Quest 351 source does not contain native
`acceptCond` / `beginExec` object arrays in this row type.

The remaining provenance question is downstream: identify the exact resource
generation or merge step that re-materialized predecessor `acceptCond`
chains in older Asta-derived QuestExcel data.

## 2026-10-07 ordinary `acceptCond` ownership closure

The native 7.1 condition wire still exists, but ordinary quest rows no longer
own it.

The maintained `genshinre.questcond71` decoder is bound to the native
`QuestCond` binary reader and recovers:

- a two-byte presence mask;
- optional uint32 parameter arrays;
- optional `QuestCondType` scalar values;
- the surrounding `QuestCond[]` count transform.

This proves that the condition record format itself survives in the 7.1
client. It does **not** imply that ordinary quest rows still serialize an
`acceptCond` field.

Exact runtime-type ownership scans close that distinction:

- `LAIMPNDEFCL`, the ordinary full-quest row, owns exactly four relevant
  object arrays: two `KIMCPAKMJMH[]` / QuestExec arrays and two
  `JPGNLOPMNHN[]` / QuestContent arrays;
- those four arrays are byte-exactly bound to `failExec`, `finishExec`,
  `failCond`, and `finishCond`;
- no `QuestCond[]` field exists anywhere in the 7.1 runtime field census;
- no direct single-object field whose type is `QuestCond` or any other
  `QuestCondType` record exists;
- no ordinary full-quest owner (`LAIMPNDEFCL` or `AFIOOHMJHDM`) owns an
  array of any of the recovered condition-record types.

The two generic-inst fields on the `AFIOOHMJHDM` full-quest root were also
checked so that a prerequisite collection could not hide behind erased
metadata:

- type index `577923` is reused by
  `InteractionManager._curLoadFreeStyleDic`, identifying it as a generic
  collection unrelated to quest condition records;
- the exclusive root generic at type index `629808` is read by RVA
  `0x7808380`; its element loop consumes four-byte scalars directly and
  applies
  `((raw + 0xC35B495C) mod 2^32) XOR 0x08CA1CAA`. It invokes no
  `QuestCond` or condition-record sub-reader.

Therefore there is no remaining ordinary 7.1 full-quest field or container
that can represent `acceptCond`.

A separate native type does retain the concept:
`MoleMole.Config.RandomQuestExcelConfig` has a named
`_acceptCond : RandomQuestCond[]` field in the same exact 7.1 metadata.
It also retains named `_beginExec`, `_failExec`, `_finishExec`,
`_finishCond`, and `_failCond` fields. This is useful negative/positive
control: the metadata and runtime-type recovery do preserve an
`acceptCond` field when one genuinely exists.

Historical exact-client controls place the ordinary-quest removal boundary
between 2.8 and 3.0:

- exact 2.8 QuestExcel still serializes Quest 351 prerequisite conditions;
- exact 3.0, 3.2, and 3.4 Quest 351 rows no longer carry those
  `acceptCond` prerequisites;
- exact 7.1 ordinary full-quest rows remain without an `acceptCond`
  container.

Consequently, predecessor-style ordinary `acceptCond` chains seen in modern
Asta-derived QuestExcel resources are historical/downstream materialization,
not a faithful decode of the 7.1 ordinary quest source. Asta's repair tooling
independently states that the current 7.1 BinOutput lost `acceptCond` and
reconstructs prerequisites from older resource graphs; that downstream
statement is corroborating evidence, not the basis of the native conclusion.

The remaining prerequisite investigation is now narrower: identify and audit
the exact historical-resource merge/materialization step that chooses which
old prerequisite graph to project into modern server resources.
## 2026-10-07 downstream Asta prerequisite materialization provenance

The downstream provenance is now closed far enough to identify both the
pre-existing synthetic convention and the later code-review step that copied
it into newly materialized rows.

The first `AstaPS-Resource` import of the flattened table is commit
`8c85a82f37341a422002a0352c89a142c4017e53`
(`Add ExcelBinOutput part 3 of 5`). That commit adds
`ExcelBinOutput/QuestExcelConfigData.json` as a static 1,905,666-line file;
its parent does not contain the table. The repository does not preserve the
external generator that produced that initial file, so provenance before this
import remains unknown.

A focused audit of that exact imported file found:

- 25,261 rows across 3,099 main-quest groups;
- 24,588 / 25,261 rows (**97.335814%**) exactly match the synthetic rule
  *first row -> `QUEST_COND_STATE_EQUAL [0,3]`; later row -> previous
  physical row subId, state 3*;
- all 3,099 first rows use the `[0,3]` form;
- 21,489 / 22,162 non-first rows (**96.96327%**) point exactly to the
  preceding physical row;
- 2,759 / 3,099 main-quest groups (**89.028719%**) match that synthetic
  rule on every row.

Quest 351 is a direct example. The imported table serializes it as the single
chain:

`35104 -> 35100 -> 35107 -> 35101 -> 35106 -> 35105 -> 35103 -> 35102`.

That differs from the intact historical branch/convergence graph and cannot be
treated as source-authored prerequisite semantics.

The next materialization step is explicit rather than inferred.
`MeChen618/AstaPS-Resource` PR #9,
`Update QuestExcelConfigData from BinOutput/Quest`, merged as
`7465e29b2d58058ab9973187c112abf2717ada03`, adds 7,956 BinOutput
subquests that were absent from the flattened table. Its PR description states
that current BinOutput carries no `acceptCond` / `beginExec`, then defines
the generated fallback used for those new rows: first step
`QUEST_COND_STATE_EQUAL [0,3]`, each later step
`QUEST_COND_STATE_EQUAL [previous step,3]`. PR #9 therefore knowingly extends
the already-present flattened-table convention; it does not recover those
edges from 7.1 native quest data.

The historical repair controls can also be bound to exact public refs:

- `TomyJan/GCResource` branch `3700`:
  `609730bf63568baee1eb77a605b6c273a064dbc1`;
- `TomyJan/GCResource` branch `4000`:
  `ede70f1e23c1a494fe4258837d963b1d63004911`.

For `BinOutput/Quest/351.json`, both refs resolve to the identical Git blob
`1349ca8a9f15fc5ca6590cd8ce4ecdb04d0fae61`. This is byte-level 3.7/4.0
consensus for the historical Quest 351 graph. The separate `3700-Full`
branch resolves that file to
`393b602027f93b8b8efec4abfcb64df69043be20` and has the later
obfuscated/field-loss shape; it is not the prerequisite consensus control used
for this comparison.

Upstream PR #11 later repairs evidence-backed rows from those historical
graphs. Its first large repair commit,
`abbc237458361f5d9a054d622bb7e9e1ed91ed7a`, introduces the explicit
repair manifests and audit tooling. Those repairs are downstream restoration
policy, not evidence that ordinary 7.1 native quest rows still own
`acceptCond`.

The resulting provenance chain is therefore:

`ordinary native acceptCond removed by the 3.0-era client data`
-> `7.1 ordinary native Quest/QuestExcel still has no acceptCond owner`
-> `initial Asta flattened import already contains a nearly universal physical-order chain`
-> `PR #9 explicitly copies that convention into 7,956 newly materialized rows`
-> `later repair manifests selectively restore historical graphs from pinned old controls`.

This closes the origin of the modern Asta predecessor chain inside the
repository history. The remaining unknown is the external generator that
created the pre-import flattened file before commit `8c85a82f`.
## 2026-10-07 ordinary Quest content/exec ownership closure

The remaining four ordinary Quest object-array semantics are now closed
independently of the public field names.

The exact 7.1 runtime type array resolves the four `LAIMPNDEFCL` array fields
as:

- `CNPOFCKIBDL : KIMCPAKMJMH[]` -> `failExec`;
- `KHEBAEMAPPJ : JPGNLOPMNHN[]` -> `failCond`;
- `DDFGFCPCNEH : JPGNLOPMNHN[]` -> `finishCond`;
- `FAPCNCGCEBJ : KIMCPAKMJMH[]` -> `finishExec`.

The semantic binding is verified against the pinned same-version Quest 351
control. For example, `CNPOFCKIBDL` contains the rollback exec on 35101,
`KHEBAEMAPPJ` contains its team-dead fail condition, and
`FAPCNCGCEBJ` contains the lock-point / refresh-group finish execs on
35106/35107.

A full metadata/runtime-type census then resolves every `SZARRAY` field whose
element type is either `KIMCPAKMJMH` or `JPGNLOPMNHN`. The entire 7.1
client contains exactly **four** such array fields, all four on
`LAIMPNDEFCL`. There is no second ordinary Quest row/container with another
QuestExec or QuestContent array that could hide `beginExec`.

Together with the separate condition-owner census, the client-side boundary is
therefore closed:

- native 7.1 ordinary Quest source retains `finishCond`, `failCond`,
  `finishExec`, and `failExec`;
- native 7.1 ordinary Quest source has no `acceptCond` owner;
- native 7.1 ordinary Quest source has no fifth QuestExec array for
  `beginExec`.

This is an ownership result over the exact 7.1 runtime metadata and native
reader, not an inference from missing JSON keys.

## Historical carry-forward evidence boundary

Later community resources must not be counted as independent version-native
proof for `acceptCond` or `beginExec`.

A direct Quest 351 check shows that the 4.6, 5.0, 6.6 and nominal 7.0 Luna
resource snapshots all retain the old prerequisite graph that exact-client
evidence shows was already removed from ordinary native Quest data by 3.0.
For Quest 351:

- TomyJan 3.7 and 4.0 refs share blob
  `1349ca8a9f15fc5ca6590cd8ce4ecdb04d0fae61`;
- Kei-Luna 4.6 and 5.0 plus Rafs-kk 6.6 share blob
  `10aaff303a017090fb941f14e50c733a81d20a82`;
- Merprose2's later resource has a different file blob but the same carried
  Quest 351 prerequisite graph.

Therefore agreement across those repositories/versions is useful evidence for
a **historical compatibility graph**, but it is not independent evidence that
the corresponding version's client still serialized the field.

The recovery policy for private-server use should keep the sources distinct:

1. `finishCond/failCond/finishExec/failExec`: decode from exact 7.1 native
   ordinary Quest source;
2. `acceptCond/beginExec`: use historical/community values only with explicit
   provenance and compatibility status;
3. never generate a physical previous-row `STATE_EQUAL` chain and label it as
   recovered data;
4. leave rows unresolved when no historical evidence exists rather than
   silently fabricating prerequisites or begin execs.

This preserves two separate products: a faithful 7.1 client-native dataset and
an optional compatibility-restoration layer for server gameplay.
## 2026-10-07 provenance-preserving recovery manifest

`genshinre.questrecovery71` now turns the ownership boundary above into a
machine-readable recovery layer. It deliberately keeps client-native and
compatibility-only data separate.

The pinned full run used:

- raw 7.1 client projection:
  `DimbreathBot/AnimeGameData@792978e5503ecfba73dcb3562ed44a0d35a2abe2`;
- community 7.1 merged resource:
  `capyb2222/LunaGC-Resources@395a5ee6442142a803691f60d541ee1706ae9cd7`;
- community 7.0 predecessor:
  `chenlin996/LunaGC-Resources7.0@0991d8a9d82b37a7400774764c0b6e04e7c66a9d`.

The full 33,214-row result is:

- `finishCond`: 32,683 non-empty native 7.1 rows;
- `failCond`: 5,156 non-empty native 7.1 rows;
- `finishExec`: 12,326 non-empty native 7.1 rows;
- `failExec`: 3,896 non-empty native 7.1 rows;
- `acceptCond`: 15,384 compatibility carry-forward values, 7,173 proven
  compatibility-empty rows, and 10,657 unresolved rows;
- `beginExec`: 4,837 compatibility carry-forward values, 17,720 proven
  compatibility-empty rows, and 10,657 unresolved rows.

The unresolved file therefore contains 10,657 rows / 21,314 field
occurrences. No previous-row prerequisite synthesis is performed.
`QUEST_COND_UNKNOWN [0,0]` placeholders are filtered rather than promoted.

The focused generation run was GitHub Actions run `37609718112`; its four
unit tests passed and it emitted the recovery manifest plus unresolved set.
The workflow shell is temporary orchestration only. The durable implementation
is `genshinre.questrecovery71` plus `tests/test_questrecovery71.py`.
## 2026-10-07 public community resource exhaustion

Additional 7.0/7.1 community resource censuses do not recover more
`acceptCond` or `beginExec` values.

For pinned 7.0 resources:

- `chenlin996/LunaGC-Resources7.0@0991d8a9...`: 22,557 rows;
- `nyakochao/LunaGC-Resources-7.0@15e8fedc...`: 33,073 rows;
- `Merprose2/LunaGCR-Resources@a64cf90a...`: 33,066 rows.

Across the union, all three repositories agree on every non-empty
`acceptCond` / `beginExec` value they expose. The only recovered non-empty
sets remain exactly 15,384 `acceptCond` rows and 4,837 `beginExec` rows.
There are zero cross-repository conflicts. The extra rows in the larger
7.0 resources do not add another non-empty value for either missing field.

For pinned 7.1 siblings:

- `capyb2222/LunaGC-Resources@395a5ee6...`;
- `invoker-bot/LunaGC-Resources@e2c1d3ca...`.

Both expose the same 33,073 normalized rows and agree across all 33,214
native subIds after missing rows are treated as empty lookup results.
Both contain exactly the same 15,384 non-empty `acceptCond` rows and
4,837 non-empty `beginExec` rows. Neither fills any gap left by the other.

Therefore the remaining unresolved set cannot be reduced by searching these
known Luna/Asta-derived public Quest JSON siblings. Further progress must come
from a different evidence class: server-side source, independently preserved
historical data, or semantic reconstruction from the Quest graph / scripts.
