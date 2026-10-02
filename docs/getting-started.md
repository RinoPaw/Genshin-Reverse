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

The maintained path is exact-sample and fail-closed:

```text
exact 7.1 samples
→ regenerate canonical metadata/runtime/GetCmdId evidence
→ publish validated canonical artifacts
→ validate registry/protocol evidence
```

The committed canonical registry is already closed at 4,896 identities:

```text
versions/7.1.0-global/windows-x64/registry/registry.csv
versions/7.1.0-global/windows-x64/registry/registry.summary.json
```

Publication requires those canonical registry artifacts to exist and pass the current schema/bijection checks. Alternate registry recovery and compatibility publication paths are retired.

## 1. Regenerate the pinned 7.1 client data

Raw game files stay outside Git. The native decoder checks both SHA-256 values before decoding. Expected sample identities are recorded in `versions/7.1.0-global/windows-x64/hashes.json`.

For repeatable sample acquisition, use `scripts/fetch-7.1-samples.sh` or `scripts/fetch-7.1-samples.ps1`; both pin the maintained Sophon manifest and expected hashes.

Windows PowerShell:

```powershell
./scripts/regenerate-7.1.ps1 `
  -Exe 'D:\path\to\GenshinImpact.exe' `
  -Metadata 'D:\path\to\global-metadata.dat'
```

Linux/macOS/WSL:

```bash
./scripts/regenerate-7.1.sh \
  --exe /path/to/GenshinImpact.exe \
  --metadata /path/to/global-metadata.dat
```

The five maintained stages are mandatory:

1. exact sample fingerprints;
2. native 7.1 MHY metadata indexes;
3. metadata anchor verification;
4. runtime IL2CPP type index;
5. conservative constant-return `GetCmdId` candidates.

Any failure stops regeneration. The generated canonical metadata tables reproduce:

- 88,904 type definitions;
- 440,172 fields;
- 733,442 methods;
- 733,442 method-pointer rows.

Exploratory usage recovery, registry graphs, control-set comparisons and protocol-specific probes are separate research commands/workflows. They are run explicitly when a research task needs them and do not participate in canonical regeneration.

Generated work is written under ignored `work/7.1.0-global/windows-x64/`.

## 2. Publish validated generated artifacts

PowerShell:

```powershell
./scripts/publish-artifacts-7.1.ps1
```

POSIX shell:

```bash
./scripts/publish-artifacts-7.1.sh
```

Publication verifies exact sample hashes, metadata counts, CSV row counts, the complete method-pointer table, runtime-type anchors, full GetCmdId input coverage and the current canonical registry before writing the version tree. The manifest contract is `manifest_version: 2`.

Published metadata includes:

```text
metadata/types.csv
metadata/fields.csv
metadata/methods.csv
metadata/method-pointers.csv
metadata/type-methods.json
metadata/runtime-types.csv
```

## 3. Canonical registry identity

The 7.1 canonical registry was published from verified constructor/type slots and dominant declaring-type xrefs. Its summary requires:

- exactly 4,896 rows;
- 4,896 unique CmdIds;
- the exact canonical CSV header;
- a strict registry-slot / type-definition / CmdId bijection;
- exact-sample identity evidence.

The current canonical publisher is `genshinre.registryxrefpublish`. See `registry/README.md` and the current xref tooling when maintaining that publication path.

## Automated exact-sample regeneration

`.github/workflows/generate-7.1-data.yml` is the maintained heavy workflow. It is narrowly triggered and uses the pinned Sophon manifest plus expected SHA-256 hashes. It does not clone AstaPS or run exploratory research stages.

Normal `ci.yml` never downloads the full client. It runs unit tests, version validation, wire/protocol-query smoke tests and cheap shell/PowerShell syntax checks. Validator-only changes stay on the fast path.

## Inspect an unknown runtime packet

Start with the wire payload when one is available:

```bash
genshinre wire 7202d027
```

Then join the published evidence around the packet identity:

```bash
genshinre protocol-query \
  versions/7.1.0-global/windows-x64 \
  --cmd-id 186
```

`protocol-query` joins the canonical registry row with metadata fields/methods, handler/sender/constructor xrefs, runtime observation summaries, evidence-gated known opcodes and committed message shapes. It aggregates evidence only; it does not assign semantic names or promote confidence.

The same command can start from `--type`, `--type-definition-index` or registry `--index`.

## Convert a server trace into reusable data

```bash
genshinre import-trace born-full.log work/born-trace.csv --source born-quest351-probe
```

The importer records packet direction, offset and payload in a trace CSV. Version-level semantic summaries live separately in `cmdids/observations.csv`.

## Query the client registry

```bash
genshinre query-registry \
  versions/7.1.0-global/windows-x64/registry/registry.csv \
  --cmd-id 26105
```

## Build a research control set explicitly

When a comparison with AstaPS is useful, run it as a research action rather than as part of canonical regeneration:

```bash
genshinre import-opcodes-java \
  ../AstaPS/src/main/java/emu/grasscutter/net/packet/PacketOpcodes.java \
  work/control-set.csv
```

This is comparison evidence. Evidence-gated target-client semantic mappings live in `proto/known-opcodes.csv`.

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

## Start a new client version

```bash
genshinre scaffold --version 7.2.0 --region global --platform windows-x64
```

## Validate before committing

```bash
genshinre validate versions/7.1.0-global/windows-x64 --allow-partial
```

`--allow-partial` permits unresolved research layers in a scaffold/investigation. It never waives errors in artifacts that claim to be published.
