# Getting started

The base toolkit is intentionally standard-library only. Python 3.11+ is enough for querying and validating committed artifacts.

```bash
git clone https://github.com/RinoPaw/Genshin-Reverse.git
cd Genshin-Reverse
python -m venv .venv
# activate the venv for your shell
python -m pip install -e .
```

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

Once `metadata/methods.csv` exists:

```bash
genshinre query-methods versions/7.1.0-global/windows-x64/metadata/methods.csv --parameter-type ONKOPMILDMF

genshinre build-type-methods \
  versions/7.1.0-global/windows-x64/metadata/methods.csv \
  versions/7.1.0-global/windows-x64/metadata/type-methods.json
```

This supports the common path `CmdId -> obfuscated type -> methods whose parameters reference that type`.

## Fingerprint local samples

Raw game files stay outside Git:

```text
inputs/
  GenshinImpact.exe
  global-metadata.dat
```

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
