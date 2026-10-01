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

## Query the client registry

```bash
genshinre query-registry \
  versions/7.1.0-global/windows-x64/registry/registry.csv \
  --cmd-id 26105
```

The committed 7.1 registry is currently a small seed reconstructed from preserved audit evidence. `summary.json` records that it is partial. The historical full dataset had 4,896 unique CmdIds and must be regenerated before completeness is claimed.

## Normalize recovered registry output

A recovery script may emit different column names or raw direction flags. Normalize it before committing:

```bash
genshinre normalize-registry work/registry-raw.csv \
  versions/7.1.0-global/windows-x64/registry \
  --direction-map 0=S2C,1=C2S \
  --provenance versions/7.1.0-global/windows-x64/hashes.json
```

This writes sorted `registry.csv`, `registry.json`, and `summary.json`, rejects duplicate CmdIds and validates addresses/status values.

## Fingerprint local samples

Raw game files stay outside Git:

```text
inputs/
  GenshinImpact.exe
  global-metadata.dat
```

Then run:

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
