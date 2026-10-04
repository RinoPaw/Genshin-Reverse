---
name: Reverse-engineering research task
about: Track a concrete protocol, IL2CPP, metadata or xref research question
title: "[RE] "
labels: investigation
---

## Question

State the smallest exact result we want to recover. Avoid broad requests such as "reverse this feature" when one protocol/native uncertainty can be isolated.

## Consumer / priority

- Consumer (for example AstaPS feature/bug):
- Priority: P0 integration blocker / P1 fidelity / P2 coverage / P3 exploratory
- What becomes possible when this closes:

## Target sample

- Game version / region:
- Platform / architecture:
- EXE SHA-256:
- metadata SHA-256:
- Resource revision/path when applicable:

Use the pinned `NativeProfile` when the target already exists under `versions/`.

## Known anchors

List confirmed CmdIds, obfuscated types, methods, RVAs, resource paths, UI/state behaviors or historical clues. Clearly separate current-version evidence from navigation hints.

## Known rejected paths

Record already-tested candidates when repeating them would waste another research session.

## Desired artifacts

List the reusable outputs this task should produce: registry rows, metadata/xref indexes, message shapes, decoded captures, candidates tables, reports, or a justified negative result.

Prefer machine-readable evidence alongside prose when practical.

## Promotion gate

State a falsifiable condition for moving the result into canonical data or calling the semantic claim `CONFIRMED`. A numeric match, historical mapping or plausible call graph is not sufficient by itself unless the gate explicitly proves the missing semantic edge.

## Ownership

- Researcher / claimant:
- Maintainer reviewer:

The researcher owns the focused investigation. Maintainers own evidence format, reusable tooling, review and canonical promotion; opening this issue does not make the maintainer responsible for doing the reverse-engineering work.

## Current status

- [ ] UNRESOLVED
- [ ] CANDIDATE
- [ ] HIGH_CONFIDENCE
- [ ] CONFIRMED
- [ ] REJECTED
