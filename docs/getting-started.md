# Getting started

The base toolkit is intentionally standard-library only. Python 3.11+ is enough for querying, decoding the pinned 7.1 sample, and validating committed artifacts.

```bash
git clone https://github.com/RinoPaw/Genshin-Reverse.git
cd Genshin-Reverse
python -m venv .venv
# activate the venv for your shell
python -m pip install -e .
```

## Three registry stages

The 7.1 registry workflow has three explicit stages:

```text
regenerate  -> discovery and independent evidence artifacts
close       -> require two native recovery paths to agree across all 4,896 rows
publish     -> require direction/control/type gates and project stable canonical fields
```

Do not skip stages by copying a candidate CSV into `versions/.../registry/registry.csv`.

## 1. Regenerate the preserved 7.1 client evidence

Raw game files stay outside Git. Put your own matching samples wherever convenient; the native decoder checks both SHA-256 values before decoding. Expected sample identities are recorded in `versions/7.1.0-global/windows-x64/hashes.json`.

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

The scripts write only under ignored `work/7.1.0-global/windows-x64/`. The current pipeline produces these evidence layers:

1. exact sample fingerprints;
2. native 7.1 MHY metadata indexes and anchor verification;
3. runtime IL2CPP type index;
4. conservative constant-return `GetCmdId` candidates;
5. `0x00523400` metadata-usage initializer call-site audit;
6. metadata-registration structural probe;
7. anchored metadata usage-destination -> static-slot recovery;
8. metadata usage -> runtime/typeDefinition identity join;
9. broad registry candidate graph;
10. one-to-one strict static candidate subset;
11. preserved type-slot xref probes;
12. direct-slot native compact-registry layout probe;
13. usage-backed native compact-registry layout probe;
14. optional current AstaPS numeric control set;
15. broad and strict control-set diagnostics;
16. human-readable convergence report.

Read these first after a run:

```text
registry-candidate-report.md
registry-layout-probe.json
registry-usage-layout-probe.json
registry-candidate-graph.diagnostic.json
registry-static-candidates.diagnostic.json
```

Candidate graph output is discovery data. A small constant-return method, a historical numeric equality, or a candidate layout does not establish canonical protocol identity.

## 2. Close the native registry structure

After regeneration, run strict closure:

PowerShell:

```powershell
./scripts/close-registry-7.1.ps1 `
  -Exe 'D:\path\to\GenshinImpact.exe' `
  -RequireDirectionPerfect
```

POSIX shell:

```bash
./scripts/close-registry-7.1.sh \
  --exe /path/to/GenshinImpact.exe \
  --require-direction-perfect
```

The closure command intentionally fails unless the following evidence closes:

1. the direct-slot native layout exports 4,896 unique CmdIds;
2. the usage-backed native layout exports 4,896 unique CmdIds;
3. the two independent exports agree row-by-row on CmdId, registry flag and type slot across all 4,896 rows;
4. if `known-opcodes.csv` is available, registry-flag semantics are audited against independent `Req`/`Rsp` controls;
5. `--require-direction-perfect` / `-RequireDirectionPerfect` makes that direction audit a hard gate.

The raw outputs stay build-specific evidence:

```text
registry-native-direct.csv
registry-native-direct.summary.json
registry-native-usage.csv
registry-native-usage.summary.json
registry-native-compare.json
registry-direction-audit.json
```

The direction audit treats `Req` as a C2S control and `Rsp` as an S2C control and also checks matched Req/Rsp pairs. `Notify` names are deliberately excluded from this semantic direction control because notifications can be bidirectional in this protocol family. Any mismatch must be investigated before global flag semantics are published.

## 3. Publish canonical registry artifacts

Only after strict closure succeeds should stable fields be projected into canonical artifacts.

PowerShell:

```powershell
./scripts/publish-registry-7.1.ps1
```

POSIX shell:

```bash
./scripts/publish-registry-7.1.sh
```

By default publication writes to:

```text
work/7.1.0-global/windows-x64/canonical-registry/
```

This avoids silently overwriting committed version data. Review the generated `summary.json`, unresolved semantic-name count and provenance before committing it to:

```text
versions/7.1.0-global/windows-x64/registry/
```

The publisher independently rechecks:

- exact 4,896-row population and unique CmdIds;
- full independent native-path agreement;
- strongly validated direction mapping;
- current AstaPS control-set coverage;
- unique type identity for every row;
- direct type-slot membership in the independently recovered usage-slot evidence;
- ambiguity in `GetCmdId` RVA candidates;
- exact sample hashes from `hashes.json`.

If any publication gate fails, fix or document the underlying recovery evidence. Do not pad, trim, rename or manually patch rows to match historical counts.

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

Until the exact-sample closure/publication workflow has been completed and reviewed, the committed 7.1 registry remains a partial seed reconstructed from preserved audit evidence. Historical analysis recovered 4,896 unique CmdIds; that number is a regression reference and is never used to fabricate generated rows.

## Build an independent control set

```bash
genshinre import-opcodes-java \
  ../AstaPS/src/main/java/emu/grasscutter/net/proto/PacketOpcodes.java \
  work/known-opcodes.csv
```

For generic imported registries, `genshinre normalize-registry` remains available. It does not prove that a direction map, type identity or protocol membership is correct. The pinned 7.1 workflow uses the stronger regenerate -> close -> publish path above.

## Query metadata by handler parameter type

When an extractor provides method parameter types:

```bash
genshinre query-methods \
  versions/7.1.0-global/windows-x64/metadata/methods.csv \
  --parameter-type ONKOPMILDMF

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

Remove `--allow-partial` only after the canonical high-value artifacts required by the artifact contract are present and their provenance gates have passed.
