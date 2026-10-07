# Maintainer research queue

This is the maintainer-curated queue for reverse-engineering work that should be claimable by researchers without making repository maintenance depend on one person doing every investigation.

The maintainer owns prioritization, task boundaries, evidence contracts, reusable tooling, review and promotion. The researcher who claims an item owns the executable/resource investigation until the stated evidence gate is met or the path is rejected.

## Priority model

- **P0 — integration blocker:** current AstaPS behavior is blocked or risks implementing a materially wrong protocol/lifecycle rule.
- **P1 — fidelity:** the server has a fallback/approximation and current-client evidence can replace it with a native model.
- **P2 — coverage:** useful current-version semantics/data or infrastructure that improve completeness but do not block gameplay.
- **P3 — exploratory:** interesting work without a current integration consumer.

A task moves up when it blocks an AstaPS change. It moves down or pauses when a resource-level answer closes the gameplay need without further client reversing.

## Active delegated investigations

| Priority | Investigation | Current state | Integration value |
| --- | --- | --- | --- |
| P0 | [#12 WorldPlayerReviveRsp runtime confirmation](https://github.com/RinoPaw/Genshin-Reverse/issues/12) | HIGH_CONFIDENCE | static identity is narrowed to S2C CmdId 7003 / GFPMFMJPNMA / retcode field 14; one live 5232 -> 7003 transaction remains |
| P0 | [#11 Monster drowning packet](https://github.com/RinoPaw/Genshin-Reverse/issues/11) | UNRESOLVED | identifies the exact 7.1 environmental-death message so drowned monsters complete authoritative death/despawn/drop without a follow-up player hit |
| P0 | [#9 Quest 351 persistent “Return to quest point” client state](https://github.com/RinoPaw/Genshin-Reverse/issues/9) | UNRESOLVED | identifies the exact 7.1 client state/transition needed to stop the return prompt being permanently visible in AstaPS fresh-player intro |
| P1 | [#1 CmdId 186 / GetActivityInfoReq candidate](https://github.com/RinoPaw/Genshin-Reverse/issues/1) | HIGH_CONFIDENCE | closes a repeated fresh-born/login packet with exact-Global semantic evidence; no current gameplay path is blocked by the remaining semantic edge |
| P1 | [#4 Barbara C6 exact AbilityInvokeEntry / revive wire path](https://github.com/RinoPaw/Genshin-Reverse/issues/4) | UNRESOLVED wire edge; config-confirmed trigger model | lets AstaPS retire Barbara-specific trigger emulation once the native Ability path is proven |
| P1 | [#5 Artifact main/sub-stat weighting source of truth](https://github.com/RinoPaw/Genshin-Reverse/issues/5) | UNRESOLVED parent; historical continuity and restored tables documented | gives AstaPS provenance-backed artifact generation instead of community/historical probability tables |
| P1 | [#10 ReliquaryMainProp exact weight field / consumer](https://github.com/RinoPaw/Genshin-Reverse/issues/10) | UNRESOLVED | first narrow #5 closure: bind the historical main-prop weight field and weighted-selection semantics on exact Global 7.1 |
| P1 | [#20 remaining ordinary Quest compatibility acceptCond/beginExec gaps](https://github.com/RinoPaw/Genshin-Reverse/issues/20) | ACTIVE / UNRESOLVED | recover or classify the remaining 4,901 acceptCond and 112 beginExec compatibility gaps without collapsing provenance classes |
| P1/P2 | [#7 Structural protobuf recovery from obfuscated metadata](https://github.com/RinoPaw/Genshin-Reverse/issues/7) | EVALUATION | can recover richer field/container/oneof structure for unknown packets and future version migration |
| P2 | [#6 Version-independent MHY string-literal recovery](https://github.com/RinoPaw/Genshin-Reverse/issues/6) | EVALUATION | may provide reusable semantic anchors and reduce per-version metadata reverse work |

`UnlockTransPointRsp` remains paused in the 7.1 unresolved report because the corrected waypoint gameplay path no longer depends on it. Do not spend reverse-engineering time on it unless a concrete consumer reappears.

External projects and newly discovered methods are triaged in [`external-intelligence.md`](external-intelligence.md). That log is for navigation and method discovery; actionable work belongs in a focused issue such as the entries above.

Current method notes created from reconnaissance:

- [`methods/structural-protobuf-recovery.md`](methods/structural-protobuf-recovery.md) — generated-code invariants and composite protobuf fingerprints under obfuscation.
- [`methods/binconfig-extraction-validation.md`](methods/binconfig-extraction-validation.md) — exact-client resource-table extraction, schema validation and corruption-boundary classification.

## Maintainer operating order

The queue is AstaPS-driven. Work in this order unless new evidence changes the integration impact:

1. Close the narrowest active P0 blocker with a reproducible current-client result. The current death-lifecycle pair is #12 first, then #11; both share runtime reproduction context and should reuse any recovered packet tooling.
2. Return to #9 after the death-lifecycle blockers because it is a larger client-state investigation with an upstream integration consumer.
3. Treat #8 as closed extraction/ownership work. Work #20 only from new evidence classes; do not reopen exhausted QuestExcel-tail or sibling-resource searches.
4. Use #10 as the next narrow P1 data-fidelity target; promote into parent #5 only after the exact field consumer is proven.
5. Keep #4 available for gameplay fidelity, but do not prioritize it above a current reproducible P0.
6. Work on #7 or #6 only when the resulting infrastructure directly shortens an active protocol/native investigation or when no higher-priority consumer is waiting.

Do not keep more than one broad infrastructure investigation active merely because the tooling is interesting. A reusable method earns maintenance cost by closing concrete current-version questions.

## Status ownership

See [governance.md](governance.md). Issues own scope and promotion gates; target analyses own durable sample-bound conclusions. This queue is only an index and must be updated in the same maintenance change when those sources materially change.

## Default-branch and workflow hygiene

`main` is the durable evidence/infrastructure branch. It should contain stable code, schemas, canonical artifacts, method documentation and the smallest practical Actions surface.

Use `research/<topic>` for investigation-specific checkpoints and `maintenance/<topic>` for repository/infrastructure work when isolation helps. Before promotion, update the branch from `main`, preserve rejected paths that prevent duplicate work, and move durable results into the canonical version/analysis tree.

Topic-specific GitHub Actions are temporary orchestration. They require an active investigation, a concrete reason that the work cannot be done efficiently with local/reusable tools, and an explicit retirement condition. Once the reusable logic and unique evidence are committed, remove the workflow shell; Git history preserves it.

Do not use CI as the normal interactive reverse-engineering loop. Prefer local commands and maintained tools for iteration. Full required validation is mandatory before asking the user to test, before preparing an upstream submission, and before publishing/regenerating canonical target artifacts.

## Intake from AstaPS

When AstaPS reaches an unknown behavior, use this order before opening a reverse task:

1. Check current 7.1 resources/config and existing `versions/7.1.0-global/windows-x64/` artifacts.
2. Check whether the question is already answered by an existing analysis or canonical protocol row.
3. If the remaining uncertainty is client/protocol/native behavior, open one focused Genshin-Reverse issue.
4. Put exact sample identity, confirmed anchors, desired artifacts and a promotion gate in the issue before asking anyone to investigate it.
5. Keep server-side experiments in AstaPS; only portable evidence/methods belong here.

Do not create reverse tasks for questions already closed by resource evidence. The skip-intro lifecycle bug is an example: the required rule is already known — presentation skipping must preserve the normal scene-ready/PostEnterSceneRsp/onPlayerBorn lifecycle — so additional reversing needs a new concrete uncertainty, not a generic request to inspect intro again.

A resource discrepancy can still justify a reverse task when the uncertainty is in the extraction boundary itself. Issue #8 is the completed model: exact-client extraction closed the ownership boundary, after which remaining compatibility reconstruction moved to the narrower #20 task.

## Researcher handoff contract

A delegated issue should be independently actionable. It should contain:

- exact target version/region/platform and sample hashes or a pointer to the pinned profile;
- the smallest precise question to answer;
- confirmed anchors (CmdIds, types, RVAs, resource paths, runtime behavior, historical hints);
- required output format;
- a falsifiable promotion gate;
- known rejected paths so they are not repeated.

Researchers may use disposable scripts locally. A successful reusable method should be promoted into `genshinre/`, `tools/`, or `scripts/`; disposable glue should not become permanent repository surface.

## Maintainer review gate

A research PR/result is accepted when:

1. provenance binds it to the claimed sample/resource revision;
2. machine-readable evidence accompanies prose when practical;
3. `CONFIRMED`/`HIGH_CONFIDENCE`/`CANDIDATE` boundaries match the evidence actually present;
4. historical mappings are treated as cross-checks rather than current-client proof;
5. rejected candidates and the reason for rejection are retained when they prevent duplicate work;
6. canonical data is changed only after the investigation's promotion gate is satisfied.

If the evidence is useful but below the gate, keep it in the analysis/issue and do not force a semantic promotion.

## CI and iteration

Normal investigation should not wait on heavyweight CI. Use cheap local validation while iterating and keep sample-bound reverse jobs opt-in or narrowly triggered.

Before a maintainer asks for user testing, merges a change intended for an upstream submission, or publishes/regenerates canonical target artifacts, run the complete validation appropriate to that change. Failed required validation blocks promotion; it does not block exploratory research from continuing.

## Version bring-up

`7.1.0 Global / Windows x64` remains the maintained exact target. When a new client version becomes a real integration target:

1. record exact executable and metadata hashes;
2. add a fail-closed `NativeProfile` rather than loosening the 7.1 profile;
3. regenerate canonical registry/metadata through the maintained pipeline;
4. carry semantic mappings forward only as hypotheses until current-version evidence revalidates them;
5. create focused migration issues only for regressions or unresolved consumers that matter to AstaPS.

The objective is a durable evidence base and a clean queue of claimable questions, not a growing pile of one-off reverse sessions.
