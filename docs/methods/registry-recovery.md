# Registry recovery pipeline

The 7.1 protocol registry is recovered in explicit evidence layers. Every intermediate table remains inspectable so a plausible false positive cannot silently become a canonical CmdId mapping.

The current canonical 7.1 identity registry is already closed at 4,896 rows / 4,896 unique CmdIds and is published by `genshinre.registryxrefpublish`. The usage/native-layout stages below remain valuable as independent recovery and regression evidence; they do not own current canonical publication.

## Stage 0 — exact sample and metadata

Fingerprint the samples, decode metadata indexes, and require the pinned 7.1 anchors to pass first. See `metadata-extraction.md` and `native-metadata-71.md`.

The preserved Global/Windows x64 sample is bound to the SHA-256 values in `versions/7.1.0-global/windows-x64/hashes.json`.

Maintained automation obtains this exact sample through `scripts/fetch-7.1-samples.sh` or `.ps1` and the pinned Sophon manifest.

## Stage 1 — constant-return `GetCmdId` candidates

With a complete `metadata/methods.csv` containing method RVAs:

```bash
genshinre scan-constant-cmdids \
  inputs/GenshinImpact.exe \
  work/7.1.0-global/windows-x64/metadata/methods.csv \
  work/7.1.0-global/windows-x64/getcmdid-candidates.csv
```

The scanner maps metadata method RVAs into the PE and recognizes deliberately narrow constant-return bodies. Current 7.1 controls include 16-bit AX immediate-return stubs in addition to ordinary EAX forms.

The output is candidate data because ordinary client methods can also return small constants.

Preserved controls include:

```text
HJDNCHODGOL @ 0x10587260 -> 26105
DMMJNICDOHM @ 0x0C87EA60 -> 9369
```

Failure of these controls indicates a sample, metadata, RVA, or decoder problem and stops stronger joins from being trusted.

## Stage 2a — metadata-usage call-site audit

`0x00523400` is the confirmed IL2CPP metadata-usage initializer. `genshinre.usage` scans direct callers and recovers the immediate usage destination plus nearby store site and static slot where the pattern is visible.

The preserved `UnlockTransPointReq` row gives the strongest call-site anchor:

```text
usage_destination = 37523
store_rva         = 0x07F852AB
type_slot_rva     = 0x057E6498
```

`metadata-usage-sites.csv` is audit evidence. It stays separate from the destination table because call-site recovery and registration-table recovery are independent observations.

## Stage 2b — metadata-registration destination table

`genshinre.metareg` probes count/pointer structures around the runtime type array without assigning semantic names from layout alone.

`genshinre.metausage` searches for a candidate pointer table whose entry `37523` resolves exactly to the preserved static slot `0x057E6498`. The anchor must be unique before the table is accepted.

Some exact-sample runs do not close this heuristic. Maintained regeneration treats this as an optional research stage and may fall back to `genshinre.usageslots` using direct initializer call-site evidence. A failure here does not invalidate already verified metadata/runtime/GetCmdId core artifacts.

The resulting intermediate shape is:

```text
metadata-usage-slots.csv
usage_destination -> type_slot_rva
```

## Stage 2c — usage source and runtime type identity

`genshinre.typearray` exports the IL2CPP runtime type array into a queryable index.

`genshinre.usagesource` and `genshinre.usagejoin` test source representations and join usage slots to runtime type identities. The preserved end-to-end control is:

```text
37523
-> type slot 0x057E6498
-> runtime type index 405772
-> kind 0x12 / class
-> typeDefinition 84249
-> DMMJNICDOHM
```

`metadata-usage-types.csv` is a research bridge from metadata usage identity to decoded client type identity. Its availability depends on the optional usage recovery closing without ambiguity.

## Stage 2d — registry candidate graphs

There are two intentionally separate candidate-graph namespaces.

`genshinre.getcmdidgraph` uses only the verified GetCmdId method identity plus machine-code stub shape. It publishes:

```text
registry/getcmdid-candidate-graph.csv
registry/getcmdid-candidate-graph.summary.json
```

`genshinre.registrygraph` joins `metadata-usage-types.csv` with GetCmdId candidates by typeDefinition identity and publishes the usage-backed research graph when that optional path closes:

```text
registry-candidate-graph.csv
registry-candidate-graph.summary.json
```

Preserved anchors include:

- `9369 -> DMMJNICDOHM`, typeDefinition `84249`, usage `37523`, slot `0x057E6498`, GetCmdId `0x0C87EA60`;
- `26105 -> HJDNCHODGOL`, GetCmdId `0x10587260`;
- `22899 -> ONKOPMILDMF`, typeDefinition `87483`, slot `0x057F6F60`.

Candidate graphs remain discovery evidence. Constant-return non-protocol methods and genuine usage ambiguity can survive these layers.

## Stage 2e — independent control-set diagnostics

With an AstaPS checkout, create a broad numeric/semantic comparison surface:

```bash
genshinre import-opcodes-java \
  ../AstaPS/src/main/java/emu/grasscutter/net/packet/PacketOpcodes.java \
  work/7.1.0-global/windows-x64/control-set.csv
```

Maintained regeneration publishes this as:

```text
versions/7.1.0-global/windows-x64/registry/control-set.csv
```

This control set is external/server-derived comparison evidence. Target-client semantic names that pass the repository evidence gate live separately in `proto/known-opcodes.csv`.

`genshinre.graphdiag` and `genshinre.registryreport` use the control set to report coverage, deltas, duplicate identities, ambiguity and focused rows without promoting names into canonical target-client semantics.

## Stage 3 — current canonical registration identity

Current 7.1 canonical identity is built from verified registry type slots plus dominant declaring-type code xrefs. The maintained publisher is:

```text
genshinre.registryxrefpublish
```

Its publication gate requires:

- exactly 4,896 registry rows;
- 4,896 unique CmdIds;
- strict registry-slot / type-definition / CmdId bijection;
- preserved control anchors;
- exact current artifact inputs.

The published pair is:

```text
registry/registry.csv
registry/registry.summary.json
```

Direction and semantic names are independent evidence layers. A closed numeric/type identity can therefore carry blank or unresolved semantic fields.

`genshinre normalize-registry` is a generic interchange normalizer for external or historical registry-like CSV files. Its output explicitly records `canonical_publication=false`; it is not the current canonical publication mechanism.

## Historical native-layout structural closure

The direct-slot and usage-backed native-layout paths are retained as independent historical reproduction evidence. Their maintained wrappers are:

```text
scripts/close-registry-7.1.sh / .ps1
scripts/publish-registry-7.1.sh / .ps1
```

They require natural 4,896-row closure and row-by-row agreement between the independent native paths. Their default projection output stays under `work/.../historical-native-registry` so it cannot silently overwrite the xref-published canonical registry.

See `native-registry-layout-71.md` for the structural method.

## Stage 4 — semantic naming

Numeric CmdId plus obfuscated client type identity does not establish a semantic protobuf name for an unknown row. Semantic naming should use parser shape, handler/sender xrefs, UI/gameplay call paths, runtime observations, or another independent current-version source.

Historical numeric equality remains `historical-only` evidence. Rejected candidates are retained with the reason they failed.

## Maintained regeneration

Linux/macOS/WSL:

```bash
scripts/regenerate-7.1.sh \
  --exe inputs/GenshinImpact.exe \
  --metadata inputs/global-metadata.dat \
  --astaps ../AstaPS
```

Windows:

```powershell
.\scripts\regenerate-7.1.ps1 `
  -Exe .\inputs\GenshinImpact.exe `
  -Metadata .\inputs\global-metadata.dat `
  -AstaPS ..\AstaPS
```

The exact-sample metadata/runtime/GetCmdId stages are required. Usage/native registry heuristics are best-effort research stages and report unresolved results without suppressing valid core artifacts.
