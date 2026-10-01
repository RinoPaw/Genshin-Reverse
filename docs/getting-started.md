# Getting started

The base toolkit is intentionally standard-library only. Python 3.11+ is enough for querying, decoding the pinned 7.1 sample, and validating committed artifacts.

```bash
git clone https://github.com/RinoPaw/Genshin-Reverse.git
cd Genshin-Reverse
python -m venv .venv
# activate the venv for your shell
python -m pip install -e .
```

## Rebuild the preserved 7.1 client indexes

Raw game files stay outside Git. Put your own matching samples wherever convenient; the native decoder checks both SHA-256 values before decoding.

Expected sample identities are recorded in `versions/7.1.0-global/windows-x64/hashes.json`.

Windows PowerShell:

```powershell
./scripts/regenerate-7.1.ps1 `
  -Exe 'D:\path\to\GenshinImpact.exe' `
  -Metadata 'D:\path\to\global-metadata.dat' `
  -AstaPS 'D:\path\to\AstaPS'
```

Linux/macOS/WSL with locally accessible sample files:

```bash
./scripts/regenerate-7.1.sh \
  --exe /path/to/GenshinImpact.exe \
  --metadata /path/to/global-metadata.dat \
  --astaps /path/to/AstaPS
```

The scripts write only under ignored `work/7.1.0-global/windows-x64/`. They perform this pipeline in order:

1. fingerprint the executable and metadata;
2. run the exact-sample native MHY metadata decoder;
3. require `anchors-native.json` to pass;
4. scan metadata method RVAs for conservative constant-return CmdId candidates;
5. optionally extract a numeric AstaPS opcode control set.

A successful run produces full type/field/method/method-pointer indexes plus `getcmdid-candidates.csv`. The candidate file is an intermediate discovery asset and must not be copied wholesale into canonical `registry.csv`: small constant-return functions exist outside the protocol layer. Continue with `docs/methods/registry-recovery.md` for the registration-table stage.

The current native decoder intentionally leaves method `parameter_types` and `return_type` empty because the historical parameter-record formula has not yet been independently restored. `anchors-native.json` validates only layers that the native decoder actually recovers. `anchors.json` is the stronger check for extractors that also recover parameter types.

## Inspect an unknown runtime packet

```bash
genshinre wire 7202d027
```

For the current 7.1 observation this reports field 14, wire type 2, two payload bytes and the possible packed-varint interpretation `[5072]`.

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

The committed 7.1 registry is currently a small seed reconstructed from preserved audit evidence. `summary.json` records that it is partial. The historical full dataset had 4,896 unique CmdIds and must be regenerated before completeness is claimed.

## Build and verify a registry

Normalize raw recovery output:

```bash
genshinre normalize-registry work/registry-raw.csv \
  versions/7.1.0-global/windows-x64/registry \
  --direction-map 0=S2C,1=C2S \
  --provenance versions/7.1.0-global/windows-x64/hashes.json
```

Build an independent numeric control set from AstaPS:

```bash
genshinre import-opcodes-java ../AstaPS/src/main/java/emu/grasscutter/net/proto/PacketOpcodes.java work/known-opcodes.csv
```

Then require every known CmdId to exist in the recovered client registry:

```bash
genshinre crosscheck-registry \
  versions/7.1.0-global/windows-x64/registry/registry.csv \
  work/known-opcodes.csv \
  --output work/registry-crosscheck.json
```

The old 7.1 recovery passed this style of check for all 1,540 known AstaPS opcode values. A newly regenerated 4,896-entry registry should meet the same bar before publication.

## Query metadata by handler parameter type

When an extractor provides method parameter types:

```bash
genshinre query-methods versions/7.1.0-global/windows-x64/metadata/methods.csv --parameter-type ONKOPMILDMF

genshinre build-type-methods \
  versions/7.1.0-global/windows-x64/metadata/methods.csv \
  versions/7.1.0-global/windows-x64/metadata/type-methods.json
```

This supports the common path `CmdId -> obfuscated type -> methods whose parameters reference that type`.

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

Remove `--allow-partial` once all canonical high-value artifacts for a version are present.
