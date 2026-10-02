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

For the pinned 7.1 client, the maintained data path is deliberately split by responsibility:

```text
regenerate
  -> exact-sample metadata, runtime types and GetCmdId evidence
  -> optional registry/research probes are best-effort
publish artifacts
  -> validate and publish canonical metadata + reusable intermediates
canonical registry
  -> independently published from verified slot/xref identity evidence
```

Entry points:

```text
scripts/regenerate-7.1.{sh,ps1}
scripts/publish-artifacts-7.1.{sh,ps1}
genshinre.registryxrefpublish
```

The older `close-registry-7.1.*` / `publish-registry-7.1.*` native-layout path remains research tooling and historical evidence. It is not the current canonical registry publication path.

See `docs/getting-started.md` for the maintained workflow.

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

A target count is never used to pad or trim generated output. Historical counts are regression evidence only.

## Current 7.1 artifact status

The canonical 7.1 registry is published and statically closed at **4,896 unique CmdIds**, with a strict one-to-one mapping between CmdId, IL2CPP type definition and registry slot. Its canonical files are `registry/registry.csv` and `registry/registry.summary.json`. Direction and semantic identity are separate evidence layers and remain unresolved for most rows.

The canonical metadata index set is also published: `types.csv`, `methods.csv`, `fields.csv`, `type-methods.json`, `method-pointers.csv` and `runtime-types.csv`. Exact-sample regeneration reproduces **88,904 types, 440,172 fields and 733,442 methods / method pointers** and validates those counts before publication.

The repository therefore treats registry identity and metadata recovery as available infrastructure for focused investigations. New investigations should begin from the canonical artifacts before adding executable-specific probes.

## Highest-value artifacts

The long-term priority order is:

1. `registry/registry.csv`: current client registration map.
2. `metadata/types.csv`, `methods.csv`, `fields.csv`, `type-methods.json`, `method-pointers.csv`.
3. `proto/message-shapes.json`: parser-derived protobuf shapes.
4. `xrefs/message-handlers.csv` and `message-senders.csv`.
5. `analyses/<topic>/`: evidence, candidates, rejected paths and current state.

The highest-value maintenance work is now to expand reusable semantic/xref tooling, keep published artifacts internally consistent, and retire one-off research scaffolding once its method has been generalized.

## Evidence boundaries

Use `CONFIRMED`, `HIGH_CONFIDENCE`, `CANDIDATE`, `REJECTED`, and `UNRESOLVED`. More specific machine-readable provenance states (`runtime-verified`, `static-verified`, `historical-only`, etc.) may be used where useful.

Historical numeric CmdId equality is never enough to establish a current mapping. Candidate graphs and layout probes never overwrite canonical registry data. `registry_flag` direction semantics stay provisional until independent Req/Rsp controls validate them. Semantic protobuf names remain a separate evidence layer even after numeric registry membership is statically closed.

## Maintenance boundary

Repository maintenance and protocol investigations are tracked separately. Maintainers keep schemas, tooling, documentation, generated-artifact contracts, tests and CI coherent. Focused reverse-engineering work belongs under `versions/<target>/analyses/` or an issue and should be promoted into canonical artifacts only after its stated evidence gate is satisfied.

Heavy reverse-engineering jobs should remain opt-in or narrowly path-triggered. Normal CI is for fast validation and regression tests; it should not repeatedly download or analyze full game samples.

## Current target

Initial target: **Genshin Impact 7.1.0 Global / Windows x64**.

Active protocol investigations are listed in `versions/7.1.0-global/windows-x64/reports/unresolved.md`. Their presence does not make them maintainer-owned work.

Server integration and runtime probes live in [RinoPaw/AstaPS](https://github.com/RinoPaw/AstaPS).
