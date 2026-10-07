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

A separate current type, `MoleMole.Config.RandomQuestExcelConfig`, still owns named `_acceptCond : RandomQuestCond[]` plus named begin/fail/finish exec/cond fields.

This is a positive control for metadata quality: when an `acceptCond` field genuinely exists, the current metadata pipeline preserves it.

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

- missing ordinary `acceptCond` / `beginExec` in 7.1: **native ownership/format change**;
- previous-row prerequisite chains in modern Asta-derived QuestExcel: **downstream synthetic compatibility materialization**;
- retained finish/fail condition/execution arrays: **recoverable from exact 7.1 ordinary Quest source**.

Issue #8 is closed on this boundary.

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
