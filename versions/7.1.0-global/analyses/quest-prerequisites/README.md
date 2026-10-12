# 7.1 quest prerequisite provenance

State: **ACTIVE**. These are compatibility investigations for **derived AstaPS resource data**, not reverse-engineered native 7.1 `acceptCond` / `beginExec` fields.

The 7.1 client resource ownership boundary is documented in [the quest native-resource handoff](../../../../docs/quest-native-resource-handoff.md). Prior to 7.1, community quest snapshots exposed prerequisite conditions, but mapping those historical edges into modern AstaPS is a server compatibility policy. Distinguish **historical consensus**, **derived 7.1 resource state**, and **client-validated 7.1 behavior**.

## Current work

- [Chapter 1301 / MQ3000–3006](chapter1301/README.md): 110 historically identical prerequisite rows; the derived 7.1 quest files lack meaningful `acceptCond` on those rows and add current-only `300012`. Its historical graph has **not** been validated as a 7.1 runtime fix.
- [Chapter 1301 structured evidence](chapter1301/evidence.json): claim-specific status and source pins.

- [Mondstadt 7.1 prologue integration archive](mondstadt-prologue/README.md): original 40-quest static gate, compatible field provenance, and exact current-tree differences. Source-archived only; no production patch pending.

## Previous AstaPS resource repair

[AstaPS-Resource PR #17](https://github.com/MeChen618/AstaPS-Resource/pull/17), merged at `5ff5f0b083fd3683aca894e4ebc2ba602306820f`, changed the **derived, flattened** `ExcelBinOutput/QuestExcelConfigData.json` for 314 existing subquest rows, affecting only `acceptCond` and `acceptCondComb`. Of those, 34 compound-condition restorations were cross-checked against GCResource 3.7 and 4.0. CI was run; a complete 7.1 client progression test was **not** run. Do not label the PR's compatibility fields native 7.1.

The resource `play/rino` history also contains the earlier investigative notes, preserved in Git history for provenance:

- [Prerequisite audit handoff](https://github.com/RinoPaw/AstaPS-Resource/blob/891ec4c0377bca1854d879cf124a52b3967e1776/docs/quest-prerequisite-audit-handoff.md)
- [Prologue-to-Liyue next batch](https://github.com/RinoPaw/AstaPS-Resource/blob/891ec4c0377bca1854d879cf124a52b3967e1776/docs/quest-prerequisite-next-batch.md)

These notes date from October 4, 2026 and describe work that predates PR #17. They are **historical handoffs**, not instructions to rerun stale resource generators.

## Rules for future compatibility repairs

1. Pin current AstaPS-Resource SHA and reference resource SHAs.
2. Require two-source prerequisite agreement where evidence allows; exclude newer-only subquests.
3. Keep the original 7.1 `BinOutput/Quest` ownership boundary distinct from historical `acceptCond` materialization.
4. Make overlays narrow, idempotent, reject unexpected input and show exact changed fields.
5. Run CI before any upstream submission or client test. Never auto-write from exploratory discovery workflows.
