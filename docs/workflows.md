# Workflow map and maintenance policy

GitHub Actions in this repository have a deliberately small surface. Ordinary maintenance must stay fast, and exact-client reverse work must use a single maintained generation path.

Pinned 7.1 sample acquisition is centralized in:

```text
scripts/fetch-7.1-samples.sh
scripts/fetch-7.1-samples.ps1
```

## `ci.yml`

This is the only general push/PR workflow.

Unit tests cover the supported Python range at its minimum and current stable boundary, Python 3.11 and 3.14. The Python 3.12 validation job also runs the full unit suite, committed-version validation, small wire/CLI/protocol-query smoke tests, and cheap Bash/PowerShell syntax checks so repository-level maintenance checks are not repeated across the whole Python matrix.

Markdown-only and issue-template-only changes skip this workflow. CI has read-only repository contents permission, uses per-ref concurrency with `cancel-in-progress: true`, and must not download the full game client, decode full metadata, scan the executable, or run packet-specific investigations.

## `generate-7.1-data.yml`

This is the only canonical exact-sample generation workflow for the current 7.1 Global Windows x64 target.

It performs one fail-closed chain:

1. fetch the pinned exact sample;
2. regenerate metadata/runtime/GetCmdId evidence;
3. recover the exact 4,896 registry constructor/type slots;
4. recover dominant registry-slot xrefs from the regenerated method/GetCmdId data;
5. publish the strict 4,896-row slot/type/CmdId registry;
6. publish the validated metadata/GetCmdId artifacts;
7. validate the complete committed version tree;
8. commit all canonical changes together.

The registry stages used to be split across three write-capable workflows. Those shells were retired after the registry identity path stabilized. The underlying package modules remain the implementation and can still be invoked directly for focused debugging.

The workflow is narrowly path-triggered, uses same-ref stale-run cancellation, and never runs exploratory packet investigations.

## `disassemble-7.1-rva.yml`

This is the retained generic opt-in exact-sample research workflow. It accepts an RVA and size, fetches the pinned client, validates the executable identity, and preserves the requested disassembly as a short-lived artifact.

Packet-specific Actions are not retained after their useful evidence has been committed. CmdId 186, waypoint response recovery, packet framing, scene-handler work, candidate-graph experiments and similar investigations now rely on committed evidence plus reusable package/tools entry points rather than dedicated Actions shells.

## Retirement rule

Retire a workflow when all of the following are true:

1. its reusable algorithm lives in `genshinre/` or a retained `tools/` command;
2. its exact sample/parameters are documented or represented in committed evidence;
3. unique results are durable under `versions/` or a maintained case study;
4. no active investigation depends on the workflow shell itself.

Git history preserves retired orchestration. Do not keep old workflow files as documentation.

## Adding a workflow

A new workflow needs a distinct ongoing orchestration need. Before adding one:

1. put reusable logic in `genshinre/` or `tools/`;
2. reuse the canonical generation workflow for canonical artifacts;
3. keep exact sample hashes and provenance explicit;
4. keep full-client work off ordinary CI;
5. plan to retire packet-specific orchestration once its evidence is durable.

A workflow is orchestration, not the canonical implementation of a reverse-engineering method.
