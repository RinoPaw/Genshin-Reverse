# Genshin-Reverse

Reproducible reverse-engineering data, tools, methods, and protocol research for Genshin Impact.

> Any result that has been reversed once should become an artifact that prevents the next researcher from starting again from the executable.

The repository is designed as a shared, machine-queryable reverse-engineering workspace. It keeps reusable methods at the root and version-specific evidence under `versions/`.

Raw proprietary game binaries are intentionally kept out of Git history. Every derived artifact must record the exact client sample hashes and the tool/revision used to generate it.

## Layout

```text
docs/
  methods/                 reusable reverse-engineering workflows
  case-studies/            worked examples with reusable lessons
  artifact-contract.md     provenance and evidence requirements

tools/                     small reproducible extraction/query tools
schemas/                   canonical CSV/JSON field definitions

versions/
  7.1.0-global/
    windows-x64/
      hashes.json
      registry/            CmdId -> IL2CPP type registry
      metadata/            type/method/field indexes
      proto/               name translations, opcodes, message shapes
      xrefs/               handlers, senders, constructors and xrefs
      analyses/            focused investigations
      reports/             protocol map and unresolved work

.github/ISSUE_TEMPLATE/    structured evidence submissions
```

## Highest-value artifacts

The preferred long-term assets are:

- `registry/registry.csv`: one row per client-registered message, including CmdId, type identity, type cache and `GetCmdId` address when known.
- `metadata/types.csv`, `methods.csv`, `fields.csv`, `type-methods.json`: machine-queryable IL2CPP indexes.
- `proto/message-shapes.json`: protobuf wire shapes recovered from parsers.
- `xrefs/message-handlers.csv` and `message-senders.csv`: message -> consumer/producer relationships.
- `analyses/<topic>/`: evidence, candidates, rejected paths and current status for a concrete research task.

## Evidence states

Use these consistently:

- `CONFIRMED`: static and/or runtime evidence closes the loop.
- `HIGH_CONFIDENCE`: multiple strong independent signals agree; one important confirmation is still missing.
- `CANDIDATE`: plausible lead that needs more evidence.
- `REJECTED`: tested or structurally disproved candidate.
- `UNRESOLVED`: observed problem with no defensible mapping yet.

For machine-readable tables, the more specific provenance states may also be used: `runtime-verified`, `static-verified`, `cross-project-supported`, `observed-unresolved`, `mapped-not-observed`, `historical-only`, `hypothesis`.

Historical CmdId equality is never sufficient evidence for a current version. Genshin remaps packet ids between releases.

## Current target

Initial target: **Genshin Impact 7.1.0 Global / Windows x64**.

Current focused investigations include the fresh-account born flow and an unresolved client-to-server `CmdId 186 (0xBA)` observed with payload `72 02 d0 27`.

Server integration and runtime probes live in [RinoPaw/AstaPS](https://github.com/RinoPaw/AstaPS). This repository keeps the reverse-engineering evidence reusable across server implementations.
