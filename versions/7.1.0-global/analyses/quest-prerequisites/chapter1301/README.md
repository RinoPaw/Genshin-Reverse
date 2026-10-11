# Chapter 1301 prerequisite provenance (MQ3000–3006)

State: **ACTIVE**. Target: **Genshin 7.1.0 Global**. Last checked: **2026-10-12**.

This is a **historical-compatibility investigation**, not an extracted 7.1 native prerequisite table. The ordinary 7.1 full Quest payload does not own `acceptCond` or `beginExec`; see [the native-resource handoff](../../../../../docs/quest-native-resource-handoff.md) for the ownership boundary. Do not call a restored historical edge "native 7.1".

## Verified static findings

At `RinoPaw/AstaPS-Resource@5ff5f0b083fd3683aca894e4ebc2ba602306820f`, MQ3000–3006 contain **111 subquests**. The matching historical main quests in `TomyJan/GCResource` refs `3700` and `4000` contain **110**. Across the seven historical files, each pair is **byte-identical** by Git blob SHA and their 110 normalized `acceptCond` / `acceptCondComb` signatures therefore agree. Every one of these 110 rows lacks a meaningful `acceptCond` in the current 7.1 `BinOutput/Quest` files.

| MQ | Historical rows | 7.1 rows | 3.7/4.0 blob SHA |
| --- | ---: | ---: | --- |
| 3000 | 11 | 12 | `11ffe581ffac2a13f3b5eb79942a38bb467c12d7` |
| 3001 | 11 | 11 | `865b924575083a41c6ed5b98c404517226b7b19b` |
| 3002 | 13 | 13 | `7ce7f4edd2108d15a3037e52a6048c692095fd31` |
| 3003 | 21 | 21 | `4ba2b9973bbeece96c1f224a409f712cc2597aff` |
| 3004 | 22 | 22 | `a73d54eb10f7ac1d5d083b566858ffbefb8cf60d` |
| 3005 | 17 | 17 | `9513aca687b60d736c29530c9afcbe6d6dbf2343` |
| 3006 | 15 | 15 | `d66635bbe540bfc05f7767e6cffd39d0051dea74` |

The extra current subquest is **300012** under MQ3000. Neither historical file has that row. Its prerequisites must be investigated independently; never synthesize them from the old quest order.

The comparison above is confined to source `BinOutput/Quest`. It does **not** establish whether the **flattened** current `ExcelBinOutput/QuestExcelConfigData.json` preserves those 110 edges or whether they reproduce the 7.1 client's intended progression. The AstaPS flattened 33,217-row file is a separate downstream materialization; the native 7.1 QuestExcel extraction has a different ownership and row contract.

## Research inputs to preserve

- Current source: [AstaPS-Resource MQ3000–3006](https://github.com/RinoPaw/AstaPS-Resource/tree/5ff5f0b083fd3683aca894e4ebc2ba602306820f/BinOutput/Quest).
- Historic sources: [GCResource `3700`](https://github.com/TomyJan/GCResource/tree/3700/BinOutput/Quest) and [`4000`](https://github.com/TomyJan/GCResource/tree/4000/BinOutput/Quest). All seven corresponding files have identical blobs.
- Previous one-off [GCResource discovery workflow](https://github.com/RinoPaw/AstaPS-Resource/blob/891ec4c0377bca1854d879cf124a52b3967e1776/.github/workflows/discover-chapter1301.yml).
- Previous one-off [decoded snapshot comparison workflow](https://github.com/RinoPaw/AstaPS-Resource/blob/891ec4c0377bca1854d879cf124a52b3967e1776/.github/workflows/chapter1301-decoded-consensus.yml). Its external inputs are `wander-in-wind/TsvParser@249e7cb402c31f0f21ac649d5879a6f91007dc12` and `capyb2222/LunaGC-Resources@395a5ee6442142a803691f60d541ee1706ae9cd7`. Its assertions (including 110-row consensus) are **historical test expectations**, not proof that this workflow passed or that the later references were independently verified here.

## Safe next steps

1. Run a **read-only** row-by-row comparison of the current flattened MQ3000–3006 entries against the 110 historical signatures; classify `match`, `missing`, `drift`, and `current-only`. Record a reproducible result artifact, rather than relying on the old workflow's assertions.
2. Inspect the extra 7.1 row `300012` and 7.1-specific chapter/quest triggers before proposing any compatibility overlay.
3. Confirm the server's `acceptCondComb` handling, particularly mixed/default combiners. Historical `LOGIC_NONE` handling is not automatically equivalent to a 7.1 native field.
4. Only propose a resource patch for proven defects with a narrow manifest and population, field-diff, idempotence and CI guards. No global `[0,3]` workaround; no unsupervised QuestExcel rewriting.

**No resource patch was made as part of this investigation.** Keep the native/client ownership and server compatibility policy separate.
