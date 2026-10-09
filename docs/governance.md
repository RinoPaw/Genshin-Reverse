# Research and maintenance governance

This document defines how exploratory reverse-engineering work becomes maintained repository state.

## Source of truth

Use one authoritative layer for each kind of state:

- **Issue**: question, scope, owner, promotion gate and whether work is active.
- **Version analysis** under `versions/<target>/analyses/`: durable sample-bound evidence and conclusions.
- **Research queue**: priority/index only. It must summarize issues and analyses; it must not carry a competing investigation state.
- **Handoff**: temporary resume context only. A handoff must never be the only place where a confirmed conclusion exists.
- **Git branch**: implementation/work area, not a status database.

When these disagree, the issue and durable version analysis must be corrected first, then the queue/handoff must be synchronized in the same maintenance change.

## Branch policy

Ordinary research lands directly on `main`.

Use a separate branch only when isolation has a concrete benefit, for example:

- a destructive or wide refactor whose intermediate commits would break the maintained tree;
- a decoder/probe that needs several knowingly incomplete checkpoints before it can pass normal tests;
- an experiment that creates temporary workflows or generated artifacts that should not appear on `main`;
- an upstream contribution that needs an independently reviewable patch series.

When a branch is needed, branch from current `main` and use `research/<topic>`, `decoder/<topic>`, or `maintenance/<topic>` as appropriate. Do not create `rino-*` topic branches.

Every temporary branch needs a named exit condition in its issue or analysis. Retire it as soon as its useful result is represented on `main`. Do not use a branch as a long-lived second source of truth.

The `rino` branch is a compatibility/work pointer only. Keep it aligned with `main`; do not queue ordinary research there for later promotion.

## Research promotion

A research result graduates when its evidence gate is met. Promotion is one maintenance operation:

1. write the conclusion and provenance into the target analysis;
2. promote reusable code into `genshinre/`, `tools/` or `scripts/`;
3. add or update regression tests;
4. update or close the tracking issue;
5. update `docs/research-queue.md`;
6. update or retire the handoff;
7. retire temporary workflows whose outputs are now durable;
8. mark superseded branches for deletion after their unique history is no longer operationally needed.

Do not leave a confirmed result only on a research branch.

## Temporary workflow budget

Normal CI is validation, not the interactive reverse-engineering loop.

A topic-specific workflow is allowed only when hosted orchestration is materially useful and the issue states:

- why a local/reusable command is insufficient;
- the exact investigation that owns it;
- the artifact/evidence it must produce;
- the retirement condition.

Prefer one active topic-specific workflow per investigation. Before promotion or upstream submission, retire probes that have reached their retirement condition and run the full required CI.

## Evidence classes

Keep these classes explicit in code and generated data:

- `client-native`: recovered from the pinned current sample;
- `compatibility`: carried from historical/community evidence for server fidelity;
- `inferred`: reconstructed from topology or other indirect evidence;
- `synthetic`: intentionally generated fallback policy.

Never relabel compatibility, inferred or synthetic values as client-native. Unknown is a valid maintained state.

## Status synchronization

A material status change must update all affected durable surfaces in the same change on `main` (or in the same temporary branch when isolation is required):

- tracking issue;
- version analysis;
- research queue;
- handoff when one exists.

Examples of material status changes: `UNRESOLVED -> HIGH_CONFIDENCE`, promotion-gate closure, a rejected owner/schema, or replacement of one research question by a narrower follow-up question.

## Maintenance review checklist

Before completing a maintenance/promotion change:

- no durable conclusion exists only in a handoff or research branch;
- no active issue asks a question already answered by current evidence;
- no queue entry contradicts its issue/analysis;
- retained workflows are listed in `docs/workflows.md`;
- temporary workflows have an active owner and retirement condition;
- reusable logic is not duplicated across workflow YAML files;
- required unit tests and version validation pass.

Git history is the archive. The maintained tree should show the current method and current evidence, not every experimental shell that produced them.
