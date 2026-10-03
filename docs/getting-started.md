# Getting started

The base toolkit is intentionally standard-library only. Python 3.11+ is enough for querying, decoding the pinned 7.1 sample, correlating already-decrypted captures, and validating committed artifacts.

```bash
git clone https://github.com/RinoPaw/Genshin-Reverse.git
cd Genshin-Reverse
python -m venv .venv
# activate the venv for your shell
python -m pip install -e .
```

## Maintained 7.1 data flow

The maintained target path is exact-sample and fail-closed:

```text
exact 7.1 samples
→ regenerate metadata/runtime/GetCmdId evidence
→ recover verified registry type slots
→ recover dominant slot xrefs
→ publish the strict 4,896-row canonical registry
→ publish validated metadata/GetCmdId artifacts
→ query canonical evidence
→ run focused investigations
→ promote semantics only after the case evidence gate is satisfied
```

The committed canonical registry is:

```text
versions/7.1.0-global/windows-x64/registry/registry.csv
versions/7.1.0-global/windows-x64/registry/registry.summary.json
```

Alternate registry publication paths and pre-closure candidate-graph layers are retired.

## Local metadata regeneration

Raw game files stay outside Git. Expected sample identities are recorded in `versions/7.1.0-global/windows-x64/hashes.json`; the exact native target contract lives in `genshinre.nativeprofile`.

For repeatable sample acquisition, use `scripts/fetch-7.1-samples.sh` or `scripts/fetch-7.1-samples.ps1`. Sample acquisition requires the optional `zstandard` package.

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

The local regeneration script produces the exact-sample metadata/runtime/GetCmdId work set:

1. exact sample fingerprints;
2. native 7.1 MHY metadata indexes;
3. metadata anchor verification;
4. runtime IL2CPP type index;
5. conservative constant-return GetCmdId candidates.

Generated work is written under ignored `work/7.1.0-global/windows-x64/`.

## Local publication

PowerShell:

```powershell
./scripts/publish-artifacts-7.1.ps1
```

POSIX shell:

```bash
./scripts/publish-artifacts-7.1.sh
```

Publication validates metadata counts, runtime anchors, full GetCmdId input coverage and the current canonical registry before writing the version tree.

For registry-specific debugging, the maintained package modules are:

```text
genshinre.registryslots
genshinre.registryslotxref
genshinre.registryxrefpublish
```

The repository does not keep separate Actions shells for those stages.

## Automated exact-sample regeneration

`.github/workflows/generate-7.1-data.yml` is the single write-capable canonical 7.1 workflow. It performs the full ordered chain from sample fetch through metadata generation, registry reconstruction, publication, validation and one final commit.

Normal `ci.yml` never downloads the full client. It runs unit tests, version validation, wire/protocol-query smoke tests and cheap shell/PowerShell syntax checks.

`disassemble-7.1-rva.yml` is the only retained generic opt-in exact-sample research workflow. Packet-specific workflow shells are retired once their evidence is durable.

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

`protocol-query` joins the canonical registry row with declared metadata fields/methods, inbound method-signature references, handler/sender/constructor xrefs, scene-handler dispatch evidence, runtime observations, evidence-gated known opcodes, committed message shapes and focused analysis records. It aggregates evidence only; it does not assign semantic names or promote confidence.

The same command can start from `--type`, `--type-definition-index` or registry `--index`.

## Follow inbound signature references

```bash
genshinre query-methods \
  versions/7.1.0-global/windows-x64/metadata/methods.csv \
  --parameter-type ONKOPMILDMF
```

Signature membership is relationship evidence. It can locate consumers and handlers, but does not establish a semantic protobuf name by itself.

## Reproduce scene-handler slot relations

```bash
genshinre scene-handler-slots \
  /path/to/GenshinImpact.exe \
  versions/7.1.0-global/windows-x64/metadata/methods.csv \
  versions/7.1.0-global/windows-x64/registry/registry.csv \
  KLLNGCPBLMM \
  0x4B1A90 \
  0x4B3AB8 \
  --output work/scene-handler-slots.json
```

Committed current-client evidence lives under `versions/7.1.0-global/windows-x64/analyses/scene-handler-dispatch/`.

## Correlate a decrypted runtime transaction

```bash
genshinre correlate-capture capture.ndjson \
  --request-cmd 9369 \
  --candidate-cmd 36641 \
  --candidate-cmd 20290 \
  --sequence-field 3 \
  --output capture.analysis.json
```

Build-specific capture hooks stay in focused runtime tools. Correlation policy stays in reusable package code.

## Convert a server trace into reusable data

```bash
genshinre import-trace born-full.log work/born-trace.csv --source born-quest351-probe
```

## Query the client registry

```bash
genshinre query-registry \
  versions/7.1.0-global/windows-x64/registry/registry.csv \
  --cmd-id 26105
```

## Build a research control set explicitly

```bash
genshinre import-opcodes-java \
  ../AstaPS/src/main/java/emu/grasscutter/net/packet/PacketOpcodes.java \
  work/control-set.csv
```

This is comparison evidence. Evidence-gated target-client semantic mappings live in `proto/known-opcodes.csv`.

## Common traversal

```text
CmdId
→ obfuscated type
→ typeDefinitionIndex
→ methods / fields
→ inbound signature references
→ handler / sender / dispatch evidence
→ parser / wire shape
→ runtime transaction evidence
→ semantic promotion
```

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
