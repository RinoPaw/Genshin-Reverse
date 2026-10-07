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
