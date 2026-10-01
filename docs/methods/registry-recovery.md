# Registry recovery pipeline

The 7.1 protocol registry is recovered in explicit evidence layers. Every intermediate table remains inspectable so a plausible false positive cannot silently become a canonical CmdId mapping.

## Stage 0 — exact sample and metadata

Fingerprint the samples, decode metadata indexes, and require the pinned 7.1 anchors to pass first. See `metadata-extraction.md` and `native-metadata-71.md`.

The preserved Global/Windows x64 sample is bound to the SHA-256 values in `versions/7.1.0-global/windows-x64/hashes.json`.

## Stage 1 — constant-return `GetCmdId` candidates

With a complete `metadata/methods.csv` containing method RVAs:

```bash
genshinre scan-constant-cmdids \
  inputs/GenshinImpact.exe \
  work/7.1.0-global/windows-x64/metadata/methods.csv \
  work/7.1.0-global/windows-x64/getcmdid-candidates.csv
```

The scanner maps metadata method RVAs into the PE and recognizes a deliberately narrow constant-return body such as:

```text
mov eax, IMM32
ret
```

Optional ENDBR64 and small NOP padding are accepted. The output is candidate data because ordinary client methods can also return small constants.

Preserved controls include:

```text
HJDNCHODGOL @ 0x10587260 -> 26105
DMMJNICDOHM @ 0x0C87EA60 -> 9369
```

Failure of these controls indicates a sample, metadata, RVA, or decoder problem and stops the stronger joins from being trusted.

## Stage 2a — metadata-usage call-site audit

`0x00523400` is the confirmed IL2CPP metadata-usage initializer. `genshinre.usage` scans direct callers and recovers the immediate usage destination plus nearby store site and static slot where the pattern is visible.

The preserved `UnlockTransPointReq` row gives the strongest call-site anchor:

```text
usage_destination = 37523
store_rva         = 0x07F852AB
type_slot_rva     = 0x057E6498
```

`metadata-usage-sites.csv` is audit evidence. It is intentionally kept separate from the full destination table because call-site recovery and registration-table recovery are independent observations.

## Stage 2b — metadata-registration destination table

`genshinre.metareg` first probes count/pointer structures around the known runtime type array without assigning semantic names from layout alone.

`genshinre.metausage` then looks for a candidate pointer table whose entry `37523` resolves exactly to the preserved static slot `0x057E6498`. The anchor must be unique before the table is exported as:

```text
metadata-usage-slots.csv
usage_destination -> type_slot_rva
```

This table reconstructs the destination-to-static-slot layer. It does not identify the message type by itself.

## Stage 2c — usage source and runtime type identity

`genshinre.typearray` exports the IL2CPP runtime type array into a queryable index.

`genshinre.usagesource` inspects data references used by the metadata-usage initializer and tests build-relevant source representations against the preserved mapping:

```text
usage 37523 -> runtime type index 405772
```

`genshinre.usagejoin` combines the selected usage-source representation with the anchored destination table and runtime type index. The preserved end-to-end control is:

```text
37523
-> type slot 0x057E6498
-> runtime type index 405772
-> kind 0x12 / class
-> typeDefinition 84249
-> DMMJNICDOHM
```

The resulting `metadata-usage-types.csv` is a machine-queryable bridge from metadata usage identity to decoded client type identity.

## Stage 2d — registry candidate graph

`genshinre.registrygraph` joins `metadata-usage-types.csv` with the Stage-1 `GetCmdId` candidates by typeDefinition identity, retaining genuine ambiguity instead of collapsing it.

It outputs:

```text
registry-candidate-graph.csv
registry-candidate-graph.summary.json
```

Important preserved anchors are checked explicitly:

- `9369 -> DMMJNICDOHM`, typeDefinition `84249`, usage `37523`, slot `0x057E6498`, GetCmdId `0x0C87EA60`;
- `26105 -> HJDNCHODGOL`, GetCmdId `0x10587260`;
- `22899 -> ONKOPMILDMF`, typeDefinition `87483`, slot `0x057F6F60`.

The earlier successful audit recovered **4,896 unique CmdIds**. Natural convergence toward that scale is a regression signal. Generation code never trims, pads, or otherwise forces the result to 4,896.

The candidate graph is still intermediate evidence. Constant-return non-protocol methods can survive this layer, and a protobuf type may participate in more than one metadata usage.

## Stage 2e — convergence diagnostics and report

With an AstaPS checkout, create an independent numeric control set:

```bash
genshinre import-opcodes-java \
  ../AstaPS/src/main/java/emu/grasscutter/net/proto/PacketOpcodes.java \
  work/7.1.0-global/windows-x64/known-opcodes.csv
```

`genshinre.graphdiag` produces machine-readable coverage and delta information. The preserved earlier recovery covered all **1,540** then-known AstaPS numeric opcode values.

`genshinre.registryreport` produces `registry-candidate-report.md` for human review. It highlights:

- graph row count and unique CmdId count;
- one-to-one joins;
- usage ambiguity;
- duplicate CmdIds;
- types associated with multiple candidate CmdIds;
- AstaPS control-set gaps when available;
- focused rows for `186`, `9369`, `22899`, and `26105`;
- preserved anchor status.

A missing `186` row is itself useful evidence: it shows which recovery layer still excludes the observed packet before anyone starts another full EXE analysis.

## Stage 3 — canonical registration identity and direction

Promotion into canonical `registry/registry.csv` requires independent closure of protocol registration membership. The richer historical raw rows included `registry_flag`, metadata usage destination, static slot, store RVA, runtime type index, typeDefinition and type name.

Two preserved direction controls currently support:

```text
9369  registry_flag=1  C2S
22899 registry_flag=0  S2C
```

These controls are insufficient to globally assign flag semantics without regenerating more of the original registration structure. Direction remains evidence-backed per row until that layer is closed.

Once membership is closed, emit raw build-specific evidence first, then project stable fields into canonical `registry.csv` through `normalize-registry`.

## Stage 4 — semantic naming

Numeric CmdId plus obfuscated type identity still does not establish a semantic protobuf name for unknown rows. Semantic naming should use parser shape, handler/sender xrefs, UI/gameplay call paths, runtime observations, or another independent current-version source.

Historical numeric equality remains `historical-only` evidence. Rejected candidates are retained with the reason they failed.

## One-command regeneration

The supported entry points are:

```bash
scripts/regenerate-7.1.sh \
  --exe inputs/GenshinImpact.exe \
  --metadata inputs/global-metadata.dat \
  --astaps ../AstaPS
```

or on Windows:

```powershell
.\scripts\regenerate-7.1.ps1 `
  -Exe .\inputs\GenshinImpact.exe `
  -Metadata .\inputs\global-metadata.dat `
  -AstaPS ..\AstaPS
```

Read `registry-candidate-report.md` first after a run, then inspect the machine-readable summaries for the layer that still carries uncertainty.
