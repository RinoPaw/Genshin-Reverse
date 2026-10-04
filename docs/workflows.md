# Workflow map and maintenance policy

GitHub Actions in this repository have a deliberately small persistent surface. Ordinary maintenance must stay fast, and exact-client reverse work must use a single maintained generation path. Temporary research workflows may exist while an active investigation depends on their hosted orchestration, but they are not part of the permanent workflow surface.

Pinned 7.1 sample acquisition is centralized in:

```text
scripts/fetch-7.1-samples.sh
scripts/fetch-7.1-samples.ps1
```

## `ci.yml`

This is the only general push/PR workflow.

Unit tests cover the supported Python range at its minimum and current stable boundary, Python 3.11 and 3.14. The Python 3.12 validation job also runs the full unit suite, committed-version validation, small wire/CLI/protocol-query smoke tests, a syntax-only compile pass over `genshinre/` and `tools/`, and cheap Bash/PowerShell syntax checks so repository-level maintenance checks are not repeated across the whole Python matrix.

The Python compile pass intentionally does not import optional research dependencies such as Capstone or Frida. It catches syntax regressions across retained helpers while keeping normal CI lightweight.

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

## Temporary active research orchestration

The default branch currently also contains temporary exact-sample workflows created during active Quest/resource work:

```text
probe-blocks0.yml
probe-quest-accept-loader.yml
probe-quest-excel-metadata.yml
probe-quest-excel-native.yml
probe-quest-table-assets.yml
probe-random-quest-cond.yml
scan-7.1-field-displacements.yml
trace-7.1-native-call-edges.yml
```

These are not permanent workflow commitments. Their cleanup is tracked in issue #13. Keep a temporary workflow only while at least one active investigation still depends on unique hosted orchestration or parameters that have not yet been promoted into reusable tooling and durable evidence.

Do not add another topic-specific workflow when a local command, an existing retained workflow, or a small reusable tool can answer the same question efficiently. CI is not the default interactive reverse-engineering loop.

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

## Validation boundary

Exploratory research may iterate with cheap local checks and opt-in exact-sample jobs. Full validation must not be skipped before asking the user to test a promoted change, before preparing an upstream submission, or before publishing/regenerating canonical target artifacts.
