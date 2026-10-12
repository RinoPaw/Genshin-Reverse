# Mondstadt 7.1 prologue integration — historical audit archive

State: **ARCHIVED / do not merge as a resource patch**. Checked 2026-10-12.

This directory preserves a self-contained static audit and the associated integration contract from `RinoPaw/AstaPS-Resource@dd263d7547e23e9645ff2d397efa54185b797e26`. It is historical compatibility evidence, not native 7.1 prerequisite extraction or proof of complete client playability. The original documents/tools are copied unchanged for provenance; their statements about then-pending runtime work may be stale.

## Repository and release anchors

- Resource production baseline: [MeChen618/AstaPS-Resource@5ff5f0b0](https://github.com/MeChen618/AstaPS-Resource/tree/5ff5f0b083fd3683aca894e4ebc2ba602306820f).
- Original investigation: [integration branch at dd263d75](https://github.com/RinoPaw/AstaPS-Resource/tree/dd263d7547e23e9645ff2d397efa54185b797e26).
- Server baseline: [MeChen618/AstaPS@7cc148d1](https://github.com/MeChen618/AstaPS/tree/7cc148d1f752a43d4b9146b3b73f26875902546f); runtime work merged via [#71](https://github.com/MeChen618/AstaPS/pull/71), [#87](https://github.com/MeChen618/AstaPS/pull/87), and [#84](https://github.com/MeChen618/AstaPS/pull/84).
- Resource compatibility changes merged in [#13](https://github.com/MeChen618/AstaPS-Resource/pull/13) and [#14](https://github.com/MeChen618/AstaPS-Resource/pull/14); later [#17](https://github.com/MeChen618/AstaPS-Resource/pull/17) restored 314 reviewed flattened prerequisite rows.
- Existing Genshin-Reverse [native Quest ownership analysis](../../../windows-x64/analyses/quest-extraction/README.md): ordinary 7.1 full Quest retains `failExec`, `failCond`, `finishCond`, `finishExec`, not legacy `acceptCond`/`beginExec`.

## Exact current-tree comparison

Direct Git tree/blob and row-content comparison between the **two pinned Resource commits** (not a merge-base commit diff) gives:

- Of **4,421 `BinOutput/Quest` files**, only `384.json` differs. Old integration adds `38402.failExec = QUEST_EXEC_ROLLBACK_QUEST [38401]`; neither branch has a `38402.failCond`. [Resource PR #14](https://github.com/MeChen618/AstaPS-Resource/pull/14) **explicitly removed this dead compatibility action**, after verifying both current native 7.1 and flattened QuestExcel lack a failure path. **Do not restore it.**
- `ExcelBinOutput/QuestExcelConfigData.json`: **33,217 IDs preserved**, **438 existing rows differ** (437 rows in `acceptCond`, 38 in `acceptCondComb`, 4 in `beginExec`; overlaps exist). These are older derived compatibility values, not proven current defects. Example: `35901` still has `[0,3]` in the archived integration's flattened acceptance but the production file uses `[35725,3,0]`. No wholesale overlay is appropriate.
- `ExcelBinOutput/DungeonExcelConfigData.json`: one row (`id=2001`) differs: archived key `DBMHBKIDAJH` versus production `passJumpDungeon`, both with value 2002.
- `Scripts/Scene/3/scene3_group133007230.lua` differs **only by its final newline**.
- `Scripts/Gadget/tree.lua` still has the previously fixed undefined `length`; the production script correctly tests `count`.
- The production branch has the Fontaine 40770–40773 scene starter scripts and related validation tooling, absent from this older integration baseline. These are upstream-only additions, not missing work to restore from the archive.
- Remaining `BinOutput/` and Mondstadt scene/gameplay Lua blob content is already identical to upstream at these revisions. Repository-wide merge-base file statistics greatly overstate the outstanding work.

## Archived methods and verification limits

- [historical-integration-contract.md](historical-integration-contract.md): original 225-line working design and per-quest hypotheses. Treat dated claims as historical.
- [audit_mondstadt_prologue.py](audit_mondstadt_prologue.py): source- and Lua-linkage static gate across 40 scoped MainQuests; includes action/content handler census.
- [report_mondstadt_quest_drift.py](report_mondstadt_quest_drift.py), [test_mondstadt_drift.py](test_mondstadt_drift.py): classify historical compatibility versus flattened QuestExcel differences, with tests for zero-padding, missing evidence, and combinator mismatches.

The unmodified archive tools assume the current working directory is a **Resource checkout**, not Genshin-Reverse; they are not the canonical version-independent recovery pipeline. The original integration commit had a [successful static Actions run](https://github.com/RinoPaw/AstaPS-Resource/actions/runs/37816775940) on 2026-10-08. This CI does **not** validate the 2026-10-12 resource baseline or a complete 7.1 client playthrough. The user previously verified the opening through arriving in Mondstadt with Amber; later acts remain unverified end-to-end.

## Disposition

No surviving integration-only production code was justified for upstream promotion at this checkpoint. Keep the core compatibility/native boundary in [the prerequisite index](../README.md). Future functional fixes require a reproduced current-client issue, native or corroborated compatibility evidence, narrow diff, relevant CI, and then actual game testing. Do not replay the old `38402` rollback, `35301` Amber grant, or broad QuestExcel generator.

## Earlier Rino compatibility branch (same checkpoint)

A separate tree/row comparison also examined [`fix/mondstadt-71-rino-compat` at `71765773`](https://github.com/RinoPaw/AstaPS-Resource/tree/7176577352b0907906980d39117bbe9a7887fb02) against the same upstream `5ff5f0b0` baseline. Only **three** source Quest JSON files differ among the 4,421 files:

- `382.json` / `38201.finishCondComb`: the older branch lacks upstream's `LOGIC_OR`.
- `384.json` / `38402.failExec`: the older branch retains `QUEST_EXEC_ROLLBACK_QUEST(38401)`. Both historical GCResource `3700` and `4000` have byte-identical MQ384 blobs (`d1e9558fbdc32c674da2c3352036e7103a66321c`) including this action, but neither current 7.1 source nor flattened QuestExcel defines a corresponding `failCond`. Resource [PR #14](https://github.com/MeChen618/AstaPS-Resource/pull/14) intentionally removed it.
- `398.json` / `39807.finishCondComb`: the older branch lacks upstream's `LOGIC_OR`.

The old branch's other gameplay and quest field differences reflect already-merged fixes, older ability/gadget, routing and Fontaine resource snapshots, or deprecated flattened QuestExcel and tooling. Its earlier Mondstadt audit (`b27dc228`, 482 lines) is superseded by the exact later `d24e472f` audit (523 lines) preserved here. The earlier branch also retains obsolete QuestExcel rewriting workflows and the duplicated native `quests.json`; neither should be promoted.

**Disposition:** both the earlier compatibility and the later integration research branches may be retired as active Resource branches after confirming their remote heads remain at the pinned SHAs. Their exact research commits and code evidence are anchored above; keep current resources on upstream `main`. This conclusion is static evidence only and does not establish complete client progression.
