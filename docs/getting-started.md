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

The maintained workflow separates stable exact-sample datasets from exploratory registry research:

```text
exact 7.1 samples
→ regenerate canonical metadata/runtime/GetCmdId evidence
→ run optional registry/research probes when they are applicable
→ publish validated metadata and reusable intermediates
→ preserve the independently published canonical registry
```

The committed canonical registry is already closed at 4,896 identities and is represented by:

```text
versions/7.1.0-global/windows-x64/registry/registry.csv
versions/7.1.0-global/windows-x64/registry/registry.summary.json
```

General artifact publication validates and preserves these files. It does not re-close or overwrite the canonical registry through an alternate recovery path.

## 1. Regenerate the preserved 7.1 client data

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

The same regeneration command may also produce metadata-usage joins, registry candidate graphs, layout probes, AstaPS control-set diagnostics and convergence reports. Those stages are best-effort research intermediates. Failure of an experimental registry heuristic does not invalidate a successfully decoded exact-sample metadata dataset.

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

Publication verifies exact sample hashes, metadata counts, CSV row counts, the complete method-pointer table, runtime-type anchors and the full GetCmdId input coverage before copying canonical metadata into the version directory.

Published metadata includes:

```text
metadata/types.csv
metadata/fields.csv
metadata/methods.csv
metadata/method-pointers.csv
metadata/type-methods.json
metadata/runtime-types.csv
```

If optional registry or xref intermediates were generated, the publisher may preserve them too. They remain evidence datasets and do not replace the canonical registry.

## 3. Canonical registry identity

The current 7.1 canonical registry was published from verified constructor/type slots and dominant declaring-type xrefs. Its summary requires:

- exactly 4,896 rows;
- 4,896 unique CmdIds;
- a strict registry-slot / type-definition / CmdId bijection;
- exact-sample identity evidence.

The current canonical publisher is `genshinre.registryxrefpublish`. See `registry/README.md` and the relevant xref tooling when maintaining that publication path.

The older `scripts/close-registry-7.1.*` and `scripts/publish-registry-7.1.*` commands preserve an earlier native-layout recovery method. They are useful for reproducing or comparing historical structural evidence, but they are not the maintained general publication path and must not overwrite the current xref-published canonical registry.

## Automated exact-sample regeneration

`.github/workflows/generate-7.1-data.yml` is the maintained heavy workflow. It is narrowly triggered and uses a pinned Sophon manifest plus expected SHA-256 hashes so a moving launcher/live-version endpoint cannot silently select another game version. Stale runs in the same heavy-generation concurrency group are cancelled when a newer relevant change arrives.

Normal `ci.yml` never downloads the full client. It runs unit tests, version validation, the wire smoke test and cheap shell/PowerShell syntax checks.

## Inspect an unknown runtime packet

```bash
genshinre wire 7202d027
```

For the current 7.1 `CmdId 186` observation this reports field 14, wire type 2, two payload bytes and the possible packed-varint interpretation `[5072]`. The packed interpretation is only a structural candidate until the current client type/parser identity is recovered.

## Convert a server trace into reusable data

```bash
genshinre import-trace born-full.log work/born-observations.csv --source born-quest351-probe
```

The importer recognizes `RECV/SEND cmdId=... name=... len=... payload=...` lines and records direction, offset and payload in CSV.

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

For generic imported registries, `genshinre normalize-registry` remains available. It normalizes data; it does not prove that a direction map, type identity or protocol membership is correct.

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

The validator checks artifact shape, publication manifests and high-value dataset consistency. `--allow-partial` permits intentionally unresolved research layers; it does not waive errors in artifacts that claim to be published.
