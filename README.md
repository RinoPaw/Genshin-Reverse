# Genshin-Reverse

Reproducible reverse-engineering data, tools, methods, and protocol research for Genshin Impact.

> Any result that has been reversed once should become an artifact that prevents the next researcher from starting again from the executable.

The repository is a shared, machine-queryable reverse-engineering workspace. Reusable methods and tooling live at the root; sample-bound evidence lives under `versions/`.

Raw proprietary game binaries stay out of Git history. Derived artifacts must carry enough provenance to bind them to exact client samples.

## Quick start

Python 3.11+ is enough for the base toolkit:

```bash
git clone https://github.com/RinoPaw/Genshin-Reverse.git
cd Genshin-Reverse
python -m venv .venv
python -m pip install -e .

genshinre wire 7202d027
genshinre query-registry versions/7.1.0-global/windows-x64/registry/registry.csv --cmd-id 26105
genshinre validate versions/7.1.0-global/windows-x64 --allow-partial
```

For the pinned 7.1 client, the reproducible full-registry path is deliberately staged:

```text
regenerate
  -> metadata / usage / GetCmdId / native-layout evidence
close
  -> two independent native exports must agree across all 4,896 rows
publish
  -> direction, control-set and type-identity gates must pass
```

Entry points:

```text
scripts/regenerate-7.1.{sh,ps1}
scripts/close-registry-7.1.{sh,ps1}
scripts/publish-registry-7.1.{sh,ps1}
```

See `docs/getting-started.md` for the exact workflow and `docs/methods/native-registry-layout-71.md` for the current structural evidence.

## Layout

```text
docs/                         methods, case studies, artifact contract
genshinre/                    standard-library CLI/package
schemas/                      canonical artifact schemas
tools/                        focused/legacy helper scripts
tests/                        synthetic regression tests
scripts/                      reproducible target-version workflows
versions/
  7.1.0-global/windows-x64/
    hashes.json
    registry/                  CmdId -> IL2CPP type registry
    metadata/                  type/method/field indexes
    proto/                     semantic names, opcodes, message shapes
    xrefs/                     handlers, senders, constructors, xrefs
    analyses/                  focused investigations
    reports/                   maps and unresolved work
.github/ISSUE_TEMPLATE/        structured evidence submissions
```

## Core workflow

```text
runtime observation
→ registry lookup
→ obfuscated type
→ metadata parameter/method lookup
→ handler/sender xrefs
→ protobuf parser shape
→ minimal runtime validation
→ confirmed semantic mapping
```

For registry reconstruction itself, independent evidence paths are kept separate until the final gate:

```text
MHY metadata → metadata usage → runtime type identity ┐
                                                     ├→ usage-backed native registry
native compact table → CmdId/flag/type-slot         ┘

independent direct-slot native registry ─────────────┐
                                                     ├→ row-by-row comparison
usage-backed native registry ────────────────────────┘

comparison + Req/Rsp direction audit + AstaPS controls
→ canonical static registry projection
```

A target count is never used to pad or trim generated output. Historical counts are regression evidence only.

## Highest-value artifacts

The long-term priority order is:

1. `registry/registry.csv`: current client registration map.
2. `metadata/types.csv`, `methods.csv`, `fields.csv`, `type-methods.json`, `method-pointers.csv`.
3. `proto/message-shapes.json`: parser-derived protobuf shapes.
4. `xrefs/message-handlers.csv` and `message-senders.csv`.
5. `analyses/<topic>/`: evidence, candidates, rejected paths and current state.

The committed 7.1 registry is currently a **partial seed** reconstructed from preserved audit evidence. Historical analysis recovered 4,896 unique CmdIds and matched all 1,540 then-known AstaPS opcodes. The repository now contains the generators, independent layout probes, raw exporters, cross-path comparison, direction audit and publication gates needed to regenerate the full dataset, but the full exact-sample output is not claimed until that pipeline is actually run and reviewed.

## Evidence boundaries

Use `CONFIRMED`, `HIGH_CONFIDENCE`, `CANDIDATE`, `REJECTED`, and `UNRESOLVED`. More specific machine-readable provenance states (`runtime-verified`, `static-verified`, `historical-only`, etc.) may be used where useful.

Historical numeric CmdId equality is never enough to establish a current mapping. Candidate graphs and layout probes never overwrite canonical registry data. `registry_flag` direction semantics stay provisional until independent Req/Rsp controls validate them. Semantic protobuf names remain a separate evidence layer even after numeric registry membership is statically closed.

## Current target

Initial target: **Genshin Impact 7.1.0 Global / Windows x64**.

Current focused investigations include fresh-account born flow, `CmdId 186 (0xBA)`, and `UnlockTransPointRsp`.

Server integration and runtime probes live in [RinoPaw/AstaPS](https://github.com/RinoPaw/AstaPS).
