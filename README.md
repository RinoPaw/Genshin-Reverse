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
genshinre protocol-query versions/7.1.0-global/windows-x64 --cmd-id 186
genshinre validate versions/7.1.0-global/windows-x64 --allow-partial
```

The maintained 7.1 path accepts only the pinned exact client sample. A sample/hash mismatch is a hard error. Target-specific counts, hashes, RVAs and preserved anchors are defined by the exact `NativeProfile`; see `docs/native-profiles.md` for the fail-closed version bring-up policy.

Maintained entry points:

```text
scripts/regenerate-7.1.{sh,ps1}
scripts/publish-artifacts-7.1.{sh,ps1}
genshinre.registryxrefpublish
genshinre protocol-query <version-dir> --cmd-id <id>
genshinre pointer-xrefs <GenshinImpact.exe> <start-rva> <end-rva> [--output pointer-xrefs.json]
genshinre scene-handler-slots <exe> <methods.csv> <registry.csv> <owner-type> <slot-start> <slot-end>
genshinre correlate-capture <capture.ndjson> --request-cmd <id> --candidate-cmd <id> [...]
python -m genshinre.packetframe (--file <decrypted-frames.bin> | --hex <hex>) [--watch-cmd <id>]...
```

`protocol-query` joins canonical registry identity, declared methods/fields, inbound method-signature references, handlers/senders/constructors, scene-handler dispatch evidence, runtime observations, message shapes and focused analysis records. It is an evidence aggregator and does not infer a semantic name on its own.

`pointer-xrefs` scans file-backed aligned qword holders whose values point into the half-open RVA range `[start-rva, end-rva)`, then joins simple RIP-relative code references to those holders. Use `rip-xrefs` when the code directly references the target RVA itself.

`correlate-capture` provides reusable request/response correlation for decrypted NDJSON packet captures. Version-specific collectors may keep build-bound hook addresses under `tools/runtime/`, while correlation policy stays in the package.

`genshinre.packetframe` parses already-decrypted game frame buffers with the same standard-library implementation on every target. It does not perform transport decryption or semantic packet promotion.

See `docs/getting-started.md` for the maintained workflow and `docs/native-profiles.md` for exact-target bring-up rules.

## Layout

```text
docs/                         methods, case studies, artifact contract
genshinre/                    standard-library CLI/package
schemas/                      canonical artifact schemas
tools/                        focused research helpers
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

## 7.1 progression research home

The maintained research home is **this repository's `main` branch**:
[`versions/7.1.0-global/analyses/progression/`](versions/7.1.0-global/analyses/progression/).
Keep reproducible source-bound observations and collectors here. Use
[`RinoPaw/AstaPS-Resource`](https://github.com/RinoPaw/AstaPS-Resource)
for the version-pinned ExcelBin and reward/drop source data, and
[`RinoPaw/AstaPS`](https://github.com/RinoPaw/AstaPS)
for server consumers and runtime behavior. The three repositories have different
roles; a resource snapshot is not proof that either the client or server applies
its rules in that form.

The [progression research index](versions/7.1.0-global/analyses/progression/README.md) organizes data under character/, weapon/, artifact/, world/, economy/ and rules/.

## Core workflow

```text
runtime observation
→ registry lookup
→ obfuscated type
→ metadata methods/fields + inbound signature references
→ handler/sender/dispatch evidence
→ protobuf parser shape
→ minimal runtime validation
→ confirmed semantic mapping
```

## Current 7.1 artifact status

The canonical 7.1 registry is published and statically closed at **4,896 unique CmdIds**, with a strict one-to-one mapping between CmdId, IL2CPP type definition and registry slot. Its canonical files are `registry/registry.csv` and `registry/registry.summary.json`. Direction and semantic identity are separate evidence layers and remain unresolved for most rows.

The canonical metadata index set is also published: `types.csv`, `methods.csv`, `fields.csv`, `type-methods.json`, `method-pointers.csv` and `runtime-types.csv`. Exact-sample regeneration reproduces **88,904 types, 440,172 fields and 733,442 methods / method pointers** and validates those counts before publication.

The repository treats registry identity and metadata recovery as available infrastructure for focused investigations. New investigations should begin from the canonical artifacts before adding executable-specific probes.

## Highest-value artifacts

1. `registry/registry.csv`: current client registration map.
2. `metadata/types.csv`, `methods.csv`, `fields.csv`, `type-methods.json`, `method-pointers.csv`.
3. `proto/message-shapes.json`: parser-derived protobuf shapes.
4. `xrefs/message-handlers.csv` and `message-senders.csv`.
5. `analyses/scene-handler-dispatch/`: reusable exact-sample scene handler slot relations.
6. `analyses/<topic>/`: evidence, candidates, rejected paths and current state.

## Evidence boundaries

Use `CONFIRMED`, `HIGH_CONFIDENCE`, `CANDIDATE`, `REJECTED`, and `UNRESOLVED`. Historical information may be cited as evidence, but historical numeric equality or old-format compatibility is never accepted as a current mapping or current data path.

Exploratory probes never overwrite canonical registry data. Semantic protobuf names remain a separate evidence layer even after numeric registry membership is statically closed. Signature references, dispatch-table membership, local ordering and runtime timing are relationship evidence; promotion requires the evidence gate stated by the focused investigation.

## Maintenance boundary

Repository maintenance and protocol investigations are tracked separately. Maintainers keep schemas, tooling, documentation, generated-artifact contracts, tests and CI coherent. Focused reverse-engineering work belongs under `versions/<target>/analyses/` or an issue and should be promoted into canonical artifacts only after its stated evidence gate is satisfied.

The maintainer-curated delegated investigation queue is `docs/research-queue.md`. It records current priorities, researcher handoff requirements, AstaPS intake rules and promotion gates. External projects and newly discovered techniques are triaged in `docs/external-intelligence.md`; that file is a navigation/method log, not canonical evidence.

Heavy reverse-engineering jobs remain opt-in or narrowly path-triggered. Normal CI is for fast validation and regression tests. Canonical 7.1 generation has one write-capable workflow; packet-specific Actions are retired after their useful logic or evidence becomes durable.

## Current target

Initial target: **Genshin Impact 7.1.0 Global / Windows x64**.

Active protocol investigations are listed in `versions/7.1.0-global/windows-x64/reports/unresolved.md`. Their presence does not make them maintainer-owned work.

Server integration and runtime probes live in [RinoPaw/AstaPS](https://github.com/RinoPaw/AstaPS).

## License

The repository-authored code, documentation, schemas, and other original material are licensed under the Apache License 2.0; see `LICENSE`.

This license does not grant rights to proprietary game binaries, extracted third-party assets, trademarks, or other material owned by their respective rights holders. Raw proprietary game files are intentionally excluded from the repository.
