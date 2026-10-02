# Artifact contract

Every generated dataset should answer four questions without relying on someone's memory:

1. Which exact client sample produced this?
2. Which reusable tool produced it?
3. What transformation was performed?
4. How strong is the semantic conclusion?

## Version provenance

A version/platform directory binds generated data to exact samples through `hashes.json`. The maintained 7.1 publication path also writes `generated-artifacts.json`, recording the publisher, validation result, compact metadata row counts, canonical-registry state, and the fixed canonical files published by that run.

The current manifest contract is version 3:

```text
manifest_version = 3
artifacts = canonical files published by this run
canonical_registry_published = true
```

There is no optional publication surface. Research artifacts are published by their own explicit research workflows and never ride the canonical publisher.

Published paths are relative to the version/platform root, for example:

```text
metadata/methods.csv
metadata/runtime-types.csv
registry/getcmdid-candidates.csv
```

Every path listed in `artifacts` must exist after publication.

The retired fields `files`, `optional_registry_artifacts_published`, and `optional_artifacts_published` are rejected. Current tooling must not emit or depend on them. Ordinary CI validates the committed manifest without downloading the client.

## Work output versus canonical published indexes

Exact-sample regeneration writes rich decoder/provenance data under `work/`. Git-published metadata under `versions/` is a compact query-oriented projection. Detailed decoder provenance stays in work output and explicit summary artifacts.

Canonical publication is fail-closed. It requires the pinned sample hashes, exact metadata counts, complete method-pointer table, runtime/GetCmdId anchors, and the current canonical registry. Research probes are outside this publication path and cannot substitute for a failed canonical gate.

## Stable identities

Obfuscated IL2CPP type names are stable node identities when bound to the same exact sample. Preserve `type_definition_index`, method indexes, RVAs, and the relevant runtime/registration slot identity whenever available. The current canonical registry uses `type_slot_rva`.

Semantic names stay in separate fields so later corrections do not destroy original static identities.

## Addresses

Prefer RVA as the portable stored address. If VA is also useful, record image base and both values explicitly. Never mix RVA and VA in one column.

## Evidence layers

Machine-readable mappings should include a `status` or `confidence` field appropriate to that dataset. Keep evidence layers distinct:

- exact-client static identities and xrefs;
- runtime packet observations;
- target-client confirmed semantic mappings in `proto/known-opcodes.csv`;
- imported comparison/control mappings such as `registry/control-set.csv`;
- historical-version clues.

Membership in an external/control mapping is supporting evidence and does not promote a target-client semantic name by itself.

Focused investigations use `analyses/<topic>/evidence.json` and the promotion rules in `docs/analysis-contract.md`.

## Canonical registry

For current 7.1, `registry/registry.csv` plus `registry/registry.summary.json` is the canonical numeric/type identity dataset. The canonical publication gate requires the exact CSV header, 4,896 rows, 4,896 unique CmdIds, and the strict registry-slot/type-definition/CmdId bijection summary.

Candidate graphs, usage joins, imported control sets, historical comparisons and packet-specific xrefs are research evidence. They remain outside the canonical artifact publisher until a future explicit contract promotes a replacement dataset.

## Keep computation-friendly data

A report may summarize a result, but the underlying compact CSV/JSON should remain available whenever practical. Examples include registry identities, metadata indexes, parser shapes, handler/sender xrefs, candidate lists and rejected-candidate tables.
