# Workflow map and maintenance policy

GitHub Actions in this repository fall into three classes. Keep the classes separate so ordinary maintenance never turns into a full-client reverse-engineering run.

Pinned 7.1 sample acquisition is centralized in:

```text
scripts/fetch-7.1-samples.sh
scripts/fetch-7.1-samples.ps1
```

Maintained exact-sample workflows call those entry points. Active research workflows may keep their own pinned experiment inputs when a distinct environment or sequence is still useful.

## 1. Fast repository CI

`ci.yml` is the only general push/PR workflow.

It runs:

- Python unit tests;
- committed-version validation;
- small wire/CLI/protocol-query smoke tests;
- cheap Bash and PowerShell syntax checks.

It must not download a game client, decode full metadata, scan the executable, or run packet-specific investigations.

CI uses per-ref concurrency with `cancel-in-progress: true`, so a newer push replaces stale test runs on the same ref.

## 2. Canonical 7.1 data workflows

### `generate-7.1-data.yml`

Maintained exact-sample generation entry point for canonical metadata/runtime/GetCmdId artifacts.

It performs only the canonical chain:

1. fetch the pinned 7.1 sample;
2. decode exact-sample metadata;
3. verify metadata anchors;
4. build the runtime type index;
5. scan constant-return GetCmdId candidates;
6. publish the fixed canonical artifact set;
7. validate the version tree.

Every stage is required. The workflow does not clone AstaPS, run candidate-graph research, perform usage recovery, or continue after a failed canonical stage.

### `recover-7.1-registry-type-slots.yml`

Maintained exact-sample registry constructor/type-slot recovery. It reconstructs the exact indexed 4,896-row type-slot table and its load/store provenance from the pinned client.

Sample identity, contiguous indices `0..4895`, uniqueness and preserved slot controls are hard gates. CmdId identity is closed separately by current GetCmdId candidates plus registry-slot xrefs; this workflow does not infer a second native CmdId representation.

### `recover-7.1-registry-slot-xrefs.yml`

Maintained exact-sample relationship recovery for canonical registry identity. It maps each GetCmdId candidate type to verified registry constructor slots and writes `registry-slot-xrefs.csv` plus its summary.

Recovery fails unless every verified registry slot has a unique dominant candidate-type owner and the preserved current-client anchors match.

### `publish-7.1-registry-xrefs.yml`

Canonical registry identity publisher. It calls `genshinre.registryxrefpublish` and owns the current `registry/registry.csv + registry/registry.summary.json` contract. Publication consumes `registry-slot-xrefs.csv`, verified constructor slots, and evidence-gated known opcodes.

The general artifact publisher requires this canonical registry to already exist and pass its schema/bijection gate.

All maintained exact-sample workflows use same-ref stale-run cancellation when a newer iteration supersedes an older one.

## 3. Research workflows

Research workflows are opt-in or narrowly triggered. They orchestrate reusable tools around a live investigation; they are not the implementation of a reverse-engineering method.

Current retained workflows are:

- `probe-cmd186-external-consumer.yml` for the active CmdId 186 investigation;
- `publish-7.1-candidate-graph.yml` for the maintained GetCmdId structural graph;
- `locate-7.1-game-packet-framing.yml` and `trace-7.1-game-packet-framing-edges.yml` for generic packet-framing provenance;
- `disassemble-7.1-rva.yml` as the generic exact-sample RVA inspection entry point.

The completed/paused waypoint-unlock comparison, scene-handler, field-mapping, RPC-submit and response-resolution workflows were retired after their reusable methods and exact-sample evidence were preserved. The pre-closure metadata-usage/type candidate-convergence chain was also retired after canonical registry identity reached a strict 4,896-row bijection.

A proposed contiguous `ushort[4896]` CmdId plus binary direction-array recovery was also retired. Two exact-sample workflow runs found no CmdId blob satisfying its own uniqueness/nonzero gates, and no such artifact was ever committed. Git history preserves that rejected hypothesis; maintained registry identity continues to use verified constructor slots plus current GetCmdId/slot-xref evidence.

Research workflow output is never silently copied by canonical publication. Each retained workflow owns explicit inputs, outputs and an evidence gate.

Maintainers should retire a research workflow when:

1. its reusable algorithm lives in `genshinre/` or a retained `tools/` command;
2. its exact sample/parameters are documented or represented in an analysis artifact;
3. unique evidence/results are committed under `versions/` or a maintained case study;
4. no active investigation depends on the workflow shell itself.

Repository maintenance may improve shared setup and safety around active research workflows, but it does not own their reverse-engineering conclusions.

Heavy research workflows that download the client or perform long executable scans should use same-ref stale-run cancellation when a newer iteration supersedes an older one.

## Adding a workflow

Before adding a new workflow:

1. implement/test reusable logic in `genshinre/` or `tools/`;
2. use maintained exact-sample workflows only for the artifacts they explicitly own;
3. add a narrowly triggered research workflow only when the investigation genuinely needs a distinct environment or sequence;
4. keep exact sample hashes and provenance explicit;
5. avoid full-client work on unrelated pushes;
6. keep research publication separate from canonical publication.

A workflow is orchestration, not the canonical implementation of a reverse-engineering method.
