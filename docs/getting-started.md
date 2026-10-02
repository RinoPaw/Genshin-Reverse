# Getting started

The base toolkit is intentionally standard-library only. Python 3.11+ is enough for querying, decoding the pinned 7.1 sample, and validating committed artifacts.

```bash
git clone https://github.com/RinoPaw/Genshin-Reverse.git
cd Genshin-Reverse
python -m venv .venv
# activate the venv for your shell
python -m pip install -e .
```

## Maintained 7.1 data flow

The maintained workflow uses the pinned exact client sample and the current artifact schemas:

```text
exact 7.1 samples
→ regenerate canonical metadata/runtime/GetCmdId evidence
→ run current registry/xref research probes when applicable
→ publish validated metadata and reusable intermediates
→ validate the canonical registry and protocol evidence
```

The committed canonical registry is already closed at 4,896 identities and is represented by:

```text
versions/7.1.0-global/windows-x64/registry/registry.csv
versions/7.1.0-global/windows-x64/registry/registry.summary.json
```

General artifact publication validates these files when publishing the current 7.1 dataset. Alternate native-layout publication and generic registry compatibility paths have been retired.

## 1. Regenerate the pinned 7.1 client data

Raw game files stay outside Git. Put your matching samples wherever convenient; the native decoder checks both SHA-256 values before decoding. Expected sample identities are recorded in `versions/7.1.0-global/windows-x64/hashes.json`.

For automated or repeatable sample acquisition, use `scripts/fetch-7.1-samples.sh` or `scripts/fetch-7.1-samples.ps1`; those entry points pin the maintained Sophon manifest and expected sample hashes.

Windows PowerShell:

```powershell
./scripts/regenerate-7.1.ps1 `
  -Exe 'D:\path\to\GenshinImpact.exe' `
  -Metadata 'D:\path\to\global-metadata.dat' `
  -AstaPS 'D:\path\to\AstaPS'
```

Linux/macOS/WSL:

```bash
./scripts/regenerate-7.1.sh \
  --exe /path/to/GenshinImpact.exe \
  --metadata /path/to/global-metadata.dat \
  --astaps /path/to/AstaPS
```

The required core stages are:

1. exact sample fingerprints;
2. native 7.1 MHY metadata indexes;
3. metadata anchor verification;
4. runtime IL2CPP type index;
5. conservative constant-return `GetCmdId` candidates.

These stages must succeed. The generated canonical metadata tables reproduce:

- 88,904 type definitions;
- 440,172 fields;
- 733,442 methods;
- 733,442 method-pointer rows.

The same regeneration command may also produce metadata-usage joins, registry candidate graphs, AstaPS control-set diagnostics and convergence reports. Those stages are current research intermediates. If a research stage does not close, its output stays unresolved; regeneration does not switch to a second compatibility implementation.

The scripts write generated work under ignored `work/7.1.0-global/windows-x64/`.

## 2. Publish validated generated artifacts

PowerShell:

```powershell
./scripts/publish-artifacts-7.1.ps1
```

POSIX shell:

```bash
./scripts/publish-artifacts-7.1.sh
```

Publication verifies exact sample hashes, metadata counts, CSV row counts, the complete method-pointer table, runtime-type anchors and the full GetCmdId input coverage before copying canonical metadata into the version directory. The current manifest contract is `manifest_version: 2`.

Published metadata includes:

```text
metadata/types.csv
metadata/fields.csv
metadata/methods.csv
metadata/method-pointers.csv
metadata/type-methods.json
metadata/runtime-types.csv
```

If current registry or xref intermediates were generated, the publisher may preserve them too. They remain evidence datasets and do not replace the canonical registry.

## 3. Canonical registry identity

The current 7.1 canonical registry was published from verified constructor/type slots and dominant declaring-type xrefs. Its summary requires:

- exactly 4,896 rows;
- 4,896 unique CmdIds;
- a strict registry-slot / type-definition / CmdId bijection;
- exact-sample identity evidence.

The current canonical publisher is `genshinre.registryxrefpublish`. See `registry/README.md` and the relevant xref tooling when maintaining that publication path.

## Automated exact-sample regeneration

`.github/workflows/generate-7.1-data.yml` is the maintained heavy workflow. It is narrowly triggered and uses a pinned Sophon manifest plus expected SHA-256 hashes so a moving launcher/live-version endpoint cannot silently select another game version. Stale runs in the same heavy-generation concurrency group are cancelled when a newer relevant change arrives.

Normal `ci.yml` never downloads the full client. It runs unit tests, version validation, the wire/protocol-query smoke tests and cheap shell/PowerShell syntax checks. Validator-only changes stay on this fast path and do not trigger exact-sample regeneration.

## Inspect an unknown runtime packet

Start with the wire payload when one is available:

```bash
genshinre wire 7202d027
```

For the current 7.1 `CmdId 186` observation this reports field 14, wire type 2, two payload bytes and the possible packed-varint interpretation `[5072]`. The packed interpretation is only a structural candidate until the current client type/parser identity is recovered.

Then join the published evidence around the packet identity:

```bash
genshinre protocol-query \
  versions/7.1.0-global/windows-x64 \
  --cmd-id 186
```

`protocol-query` joins the canonical registry row with metadata fields/methods, handler/sender/constructor xrefs, runtime observation summaries, evidence-gated known opcodes and committed message shapes. It is an evidence aggregator only; it does not infer a semantic packet name or promote confidence.

The same command can start from `--type`, `--type-definition-index` or registry `--index` when a CmdId is not the first known identity.

## Convert a server trace into reusable data

```bash
genshinre import-trace born-full.log work/born-trace.csv --source born-quest351-probe
```

The importer recognizes `RECV/SEND cmdId=... name=... len=... payload=...` lines and records direction, offset and payload in a per-packet trace CSV. Version-level semantic summaries live separately in `cmdids/observations.csv`.

## Query the client registry

```bash
genshinre query-registry \
  versions/7.1.0-global/windows-x64/registry/registry.csv \
  --cmd-id 26105
```

The committed 7.1 registry is the current complete static identity dataset. Direction and semantic names are separate evidence layers and may remain unresolved even when the numeric/type identity is closed.

## Build an independent control set

```bash
genshinre import-opcodes-java \
  ../AstaPS/src/main/java/emu/grasscutter/net/packet/PacketOpcodes.java \
  work/control-set.csv
```

When published by the maintained 7.1 generation path this becomes `registry/control-set.csv`. It is a broad comparison/control surface imported from AstaPS; evidence-gated target-client semantic mappings live in `proto/known-opcodes.csv`.

## Query metadata by handler parameter type

```bash
genshinre query-methods \
  versions/7.1.0-global/windows-x64/metadata/methods.csv \
  --parameter-type ONKOPMILDMF
```

The common traversal is `CmdId -> obfuscated type -> typeDefinitionIndex -> methods/fields -> handler/sender/parser/xrefs`.

## Fingerprint local samples

```bash
genshinre fingerprint inputs/GenshinImpact.exe inputs/global-metadata.dat
```

Copy only hashes and reproducible derived artifacts into the matching version directory.

## Start a new client version

```bash
genshinre scaffold --version 7.2.0 --region global --platform windows-x64
```

## Validate before committing

```bash
genshinre validate versions/7.1.0-global/windows-x64 --allow-partial
```

The maintained validator composes registry/proto/analysis checks with manifest-v2, CmdId-observation and message-xref contracts. `--allow-partial` permits intentionally unresolved research layers; it does not waive errors in artifacts that claim to be published.
