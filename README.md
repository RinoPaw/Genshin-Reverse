# Genshin-Reverse

Reproducible reverse-engineering data, tooling, and protocol research for Genshin Impact.

This repository is a shared workspace for recovering current client protocol behavior, IL2CPP metadata relationships, CmdIds, protobuf layouts, RVAs, parser/vtable relationships, and runtime evidence. The goal is to preserve enough evidence that another researcher with the same client build can reproduce a conclusion instead of trusting an unexplained number.

## What belongs here

- reusable reverse-engineering methods and checklists
- small tools used to fingerprint samples, inspect PE files, decode protobuf payloads, and recover protocol metadata
- version/platform-specific sample manifests and derived indexes
- CmdId observations and verified mappings
- focused investigations for unresolved packets, classes, fields, and call paths
- runtime traces reduced to the evidence needed to reproduce a finding
- case studies that demonstrate a reusable technique

Raw proprietary game executables and `global-metadata.dat` files are not committed. Record cryptographic hashes and commit only derived data that is useful for reproducibility.

## Layout

```text
docs/                 reusable methods and case studies
tools/                small reproducibility tools
versions/             version/platform-specific derived artifacts
cmdids/                current observations and recovered mappings
investigations/        unresolved and completed focused investigations
runtime/               reduced runtime observations and trace formats
.github/ISSUE_TEMPLATE structured reports from other researchers
```

## Evidence states

Findings should carry one of these states:

- `runtime-verified`: observed against the matching client and semantic behavior is confirmed.
- `static-verified`: recovered from the matching client executable/metadata and structurally cross-checked.
- `cross-project-supported`: independently consistent with another implementation, used as supporting evidence.
- `observed-unresolved`: observed at runtime but the semantic name or structure is still unknown.
- `mapped-not-observed`: present in a current mapping but not observed in the runtime trace under discussion.
- `historical-only`: known only from an older client. Numeric CmdIds are routinely remapped between versions.
- `hypothesis`: useful lead awaiting proof.

A final protocol mapping should ideally have matching runtime and static evidence. Historical numeric equality alone is never enough.

## Current sample

The first tracked target is Genshin Impact 7.1.0, Windows x64. See `versions/7.1.0/windows-x64/` for sample fingerprints and derived data.

Current focused investigation: `CmdId 186 (0xBA)` observed client -> server with payload `72 02 d0 27` during the fresh-account born/intro flow.

## Related implementation

Server-side experiments and integration live in [RinoPaw/AstaPS](https://github.com/RinoPaw/AstaPS). This repository keeps the reusable reverse-engineering evidence independent from any one server implementation.
