# Workflow map and maintenance policy

GitHub Actions in this repository fall into three classes. Keep the classes separate so ordinary maintenance does not accidentally turn every push into a full-client reverse-engineering run.

Pinned 7.1 sample acquisition is centralized in:

```text
scripts/fetch-7.1-samples.sh
scripts/fetch-7.1-samples.ps1
```

Maintained workflows should call that entry point instead of copying the Sophon manifest URL and SHA-256 values into YAML. Packet-specific research workflows may migrate to it when their owners are ready; maintenance does not rewrite active experiment environments solely for deduplication.

## 1. Fast repository CI

`ci.yml` is the only general push/PR workflow.

It may run:

- Python unit tests;
- committed-version validation;
- small wire/CLI smoke tests;
- cheap Bash and PowerShell syntax checks.

It must not download a game client, decode full metadata, scan the executable, or run packet-specific investigations.

## 2. Maintained reusable 7.1 data workflows

These workflows orchestrate reusable tooling and canonical/supporting datasets. Heavy jobs are `workflow_dispatch` or narrowly path-triggered.

### `generate-7.1-data.yml`

Maintained exact-sample generation entry point.

- fetches the pinned 7.1 sample through `scripts/fetch-7.1-samples.sh`;
- runs the required metadata/runtime/GetCmdId regeneration stages;
- permits exploratory registry probes to fail without invalidating canonical metadata;
- publishes compact query-oriented metadata through `genshinre.artifactpublish` while retaining full decoder provenance in `work/`;
- validates the resulting version tree;
- preserves full work output as a short-lived Actions artifact.

This is the general heavy generation workflow. Do not add a second workflow that repeats the same pipeline.

### `refresh-7.1-fast.yml`

Focused refresh for GetCmdId candidates and native registry slot/array support artifacts. It uses reusable Python modules and the shared pinned-sample fetch entry point.

### `publish-7.1-candidate-graph.yml`

Thin publisher for the GetCmdId-only structural candidate graph. The implementation lives in `genshinre.getcmdidgraph`; published artifacts are `registry/getcmdid-candidate-graph.*`.

This graph is intentionally distinct from `registry-candidate-graph.*`, which is reserved for the metadata-usage join implemented by `genshinre.registrygraph`.

### `recover-7.1-type-cache-xrefs.yml`

Focused producer for `registry/type-cache-xrefs.*`. It consumes the published metadata/GetCmdId/slot datasets and scans only the exact executable required for the xref operation. It must not patch source files or regenerate unrelated metadata.

### `recover-7.1-metadata-usage-types.yml`

Focused producer for xref-backed metadata usage/type identities. It consumes published methods and type-cache xrefs.

### `publish-7.1-registry-xrefs.yml`

Canonical registry identity publisher. It calls `genshinre.registryxrefpublish` and owns the current `registry/registry.csv + registry/registry.summary.json` contract.

General artifact publication must preserve this canonical registry in place. Alternate historical recovery paths must not overwrite it.

## 3. Research workflows

Files named `inspect-*`, `compare-*`, `diagnose-*`, `map-*`, or `resolve-*` are research scaffolding unless explicitly promoted above.

They may be packet-, method-, version-, or hypothesis-specific. Maintainers should not silently convert their conclusions into canonical mappings. A research workflow may be retired when:

1. its useful algorithm lives in `genshinre/` or a retained `tools/` command;
2. its exact sample/parameters are documented or represented in an analysis artifact;
3. any unique evidence/results that matter are committed under `versions/`;
4. no active investigation depends on the workflow shell itself.

The current packet-specific workflow families are primarily the 7.0/7.1 `UnlockTransPoint` comparison/inspection chain, scene-handler comparison work, and targeted usage/initializer diagnostics. They remain investigation scaffolding. Repository maintenance may improve shared setup or safety around them, but does not own their reverse-engineering conclusions.

`inspect-native-anchors.yml` still contains a small fixed-target disassembly probe. It is retained as research scaffolding because its targets are investigation-specific; new generally reusable disassembly logic should go into `genshinre/` or `tools/` instead of expanding that YAML.

## Retired workflow debt

The following obsolete shells were retired after their reusable behavior or evidence was preserved elsewhere:

- `generate-7.1-artifacts.yml` — duplicate full 7.1 generation pipeline;
- `publish-7.1-from-artifact.yml` — hard-coded an old Actions run and duplicate publisher;
- `publish-7.1-registry.yml` — inline legacy registry publisher superseded by `genshinre.registryxrefpublish`;
- `inspect-usage-artifact.yml` — hard-coded an old failed-work Actions run and only performed ad-hoc grep/printing;
- `compare-7.0-7.1-typedef-direct.yml` — one-off direct TypeDef-order heuristic whose controls were unstable; its rejected result is preserved in the UnlockTransPoint 7.1 case study and must not drive confirmation;
- the old GetCmdId-only `registry-candidate-graph.*` alias — reproduced under `getcmdid-candidate-graph.*`, leaving `registry-candidate-graph.*` available for the usage-join graph.

## Adding a workflow

Before adding a new workflow, prefer this order:

1. implement/test the reusable operation in `genshinre/` or `tools/`;
2. use an existing maintained workflow if only orchestration changes;
3. add a narrowly triggered research workflow only when the investigation genuinely needs a distinct environment or sequence;
4. keep exact sample hashes and provenance visible through the shared sample fetch entry point or an investigation-specific pinned source;
5. avoid auto-running full-client work on unrelated pushes.

A workflow is orchestration, not the canonical implementation of a reverse-engineering method.
