# Artifact contract

Every generated dataset should answer four questions without relying on someone's memory:

1. Which exact client sample produced this?
2. Which reusable tool produced it?
3. What transformation was performed?
4. How strong is the semantic conclusion?

## Version provenance

A version/platform directory must bind generated data to exact samples through `hashes.json`. The maintained 7.1 publication path also writes `generated-artifacts.json`, which records the publisher, validation result, compact metadata row counts, canonical-registry publication state, and the files actually published by that run.

The current manifest contract is version 2:

```text
manifest_version = 2
artifacts = all files published by this run
optional_artifacts_published = the optional subset that happened to be present
canonical_registry_published = whether the existing canonical registry passed the publication gate
```

Published paths are relative to the version/platform root, for example:

```text
metadata/methods.csv
registry/getcmdid-candidates.csv
registry/control-set.csv
```

`optional_artifacts_published` uses the same version-root-relative convention and must be a subset of `artifacts`. Every path listed by either field must exist after publication.

The v1 aliases `files` and `optional_registry_artifacts_published` are retired. New tooling must not emit or depend on them. The lightweight `genshinre.artifactmanifest` validator and ordinary CI lock the committed manifest to the v2 contract without requiring a client download.

## Work output versus canonical published indexes

Exact-sample regeneration writes rich intermediate/provenance data under `work/`. Git-published metadata under `versions/` is a compact query-oriented projection. Do not add provenance columns back into canonical CSVs solely because the decoder work file contains them; keep detailed decoder evidence in `work/`, summaries, or focused evidence artifacts.

The maintained publisher validates sample hashes and complete native row counts before publication. Experimental registry recovery may fail without suppressing valid canonical metadata publication.

## Stable identities

Obfuscated IL2CPP type names are valid stable node identities when they are bound to the same sample. Preserve `type_definition_index`, method indexes, RVAs, and the relevant runtime/registration slot identity whenever available. The current canonical registry uses `type_slot_rva`; metadata/runtime research artifacts may also expose type-cache-related addresses where that is the actual recovered identity.

Semantic names should stay in separate fields so later corrections do not destroy original static identities.

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

For focused investigations, use `analyses/<topic>/evidence.json` and the promotion rules in `docs/analysis-contract.md`.

## Canonical registry

For current 7.1, `registry/registry.csv` plus `registry/registry.summary.json` is the canonical numeric/type identity dataset. Candidate graphs, usage joins, layout probes, imported control sets, and historical recovery files remain supporting/intermediate artifacts unless an explicit publication gate promotes a replacement.

General artifact publication must validate and preserve this canonical registry rather than overwrite it through an experimental recovery path.

## Keep computation-friendly data

A report may summarize a result, but the underlying compact CSV/JSON should remain available whenever practical. Examples include registry identities, metadata indexes, parser shapes, handler/sender xrefs, candidate lists and rejected-candidate tables.
