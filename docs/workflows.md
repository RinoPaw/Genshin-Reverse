# Workflow map and maintenance policy

GitHub Actions in this repository fall into three classes. Keep the classes separate so ordinary maintenance never turns into a full-client reverse-engineering run.

Pinned 7.1 sample acquisition is centralized in:

```text
scripts/fetch-7.1-samples.sh
scripts/fetch-7.1-samples.ps1
```

Maintained canonical workflows call those entry points. Packet-specific research workflows may keep their own pinned experiment inputs when required by an active investigation.

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

Maintained exact-sample generation entry point.

It performs only the canonical chain:

1. fetch the pinned 7.1 sample;
2. decode exact-sample metadata;
3. verify metadata anchors;
4. build the runtime type index;
5. scan constant-return GetCmdId candidates;
6. publish the fixed canonical artifact set;
7. validate the version tree.

Every stage is required. The workflow does not clone AstaPS, run candidate-graph research, perform usage recovery, or continue after a failed canonical stage.

Full work output is kept as a short-lived Actions artifact for provenance/debugging. The Git publisher writes only the current canonical publication set.

### `publish-7.1-registry-xrefs.yml`

Canonical registry identity publisher. It calls `genshinre.registryxrefpublish` and owns the current `registry/registry.csv + registry/registry.summary.json` contract.

The general artifact publisher requires this canonical registry to already exist and pass its schema/bijection gate.

## 3. Research workflows

All other workflows that inspect, compare, diagnose, map, recover, resolve, refresh, or publish investigation-specific graphs are research workflows unless explicitly promoted into the canonical section above.

Examples include:

- `refresh-7.1-fast.yml`;
- `publish-7.1-candidate-graph.yml`;
- `recover-7.1-type-cache-xrefs.yml`;
- `recover-7.1-metadata-usage-types.yml`;
- the 7.0/7.1 UnlockTransPoint comparison/inspection chain;
- scene-handler comparison work;
- targeted usage/initializer diagnostics.

These workflows may produce useful evidence, but their output is not silently copied by canonical publication. Each research workflow owns its explicit inputs, output paths, and evidence gate.

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
2. use the canonical generation workflow only for canonical artifacts;
3. add a narrowly triggered research workflow only when the investigation genuinely needs a distinct environment or sequence;
4. keep exact sample hashes and provenance explicit;
5. avoid full-client work on unrelated pushes;
6. keep research publication separate from canonical publication.

A workflow is orchestration, not the canonical implementation of a reverse-engineering method.
