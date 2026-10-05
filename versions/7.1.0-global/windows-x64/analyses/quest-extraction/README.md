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
