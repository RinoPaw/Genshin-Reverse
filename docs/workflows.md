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

`tests/test_workflow_policy.py` keeps the workflow surface fail-closed: every retained workflow must be listed in this document, every workflow must declare explicit top-level permissions, push-triggered workflows must cancel stale runs, and `generate-7.1-data.yml` is the only workflow allowed to request repository contents write permission. This is a cheap repository-structure test and does not invoke GitHub Actions or exact-client work itself.

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

## Temporary research orchestration

The temporary class-registration pointer scan for issue #31 completed successfully on the exact SHA-256-pinned Global 7.1 client ([run 39548584709](https://github.com/RinoPaw/Genshin-Reverse/actions/runs/39548584709)). Its negative scope and source-control details are retained in `versions/7.1.0-global/analyses/progression/economy/7.1-chest-scene-row-class-pointer-registration.json`, reproducible with `scripts/probe-7.1-scene-class-pointer-registration.py --check`. That workflow was retired. Separate original-client keywriter and metadata-neighbor artifacts are compared by `scripts/audit-7.1-scene-reader-candidate-intersection.py`; vtable slot `+0xF0` remains unverified. None of these results authenticates server chest loot.

There is currently no topic-specific workflow on the maintained branch. Issue #31's temporary original Global 7.1 SceneTag/SceneExcel row-class studies have completed: [class static xrefs, run 39543986621](https://github.com/RinoPaw/Genshin-Reverse/actions/runs/39543986621), [metadata neighbors and native disassembly, run 39544622842](https://github.com/RinoPaw/Genshin-Reverse/actions/runs/39544622842), and [wrapped-key field stores, run 39545346441](https://github.com/RinoPaw/Genshin-Reverse/actions/runs/39545346441). Their permanent source-scoped evidence and reusable scripts live under `versions/7.1.0-global/analyses/progression/economy/` and `scripts/`. The two one-shot workflows are retired. The original virtual row reader at +0xF0 remains unverified; no original asset bytes or server reward claims were committed.



The exact-7.1 SceneTag/SceneExcel generic field research is complete and its one-shot workflow has been retired. The verified original executable [source run 39544944169](https://github.com/RinoPaw/Genshin-Reverse/actions/runs/39544944169) established distinct genericinst field type indices 666588 and 545412, the matching raw Il2CppType entries, and a shared bool type index 439094. The low 32-bit generic type payloads cannot be treated as file-backed virtual addresses. Permanent research code and evidence remain in `scripts/probe-7.1-scene-manager-genericinst.py` and `versions/7.1.0-global/analyses/progression/economy/7.1-chest-scene-manager-generic-type-evidence.json`. Concrete row classes and virtual method +0xF0 remain unknown.




The former QuestExcel table-assets probe reached its retirement condition after the exact asset, complete row framing and ordinary Quest ownership boundary became durable. Git history preserves the orchestration.

New topic-specific workflows must follow `docs/governance.md`: one concrete owner, a stated hosted-orchestration need, a named output and an explicit retirement condition.

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


## Temporary exact-7.1 chest Lv3 client-table path check (issue #31)

`probe-7.1-chest-lv3-tables.yml` is a temporary, **read-only** main-branch
research runner. It exists only to execute
`scripts/probe-7.1-chest-lv3-native-index.py` against the exact pinned
Global 7.1 original Sophon design index, which is intentionally not
committed to the repository. It uses the maintained hash-checked
Sophon block acquisition/export path; outputs only a small JSON report.
No user test or AstaPS server build depends on this action.

Owner: issue #31. **Retirement gate:** retain the original-asset path
probe result with exact input hashes in the version analysis, and remove
this workflow from main. An absent guessed path will be reported as
`HASH_ABSENT` only, not as absence of the corresponding feature,
scene ownership or original server payout. The workflow grants read-only
repository permissions, never publishes the original asset bytes, and
will be removed rather than kept as another permanent CI job.
