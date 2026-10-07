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
