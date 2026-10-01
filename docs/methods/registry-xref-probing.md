# Registry type-slot xref probing

The lost 7.1 `decode_registry.py` preserved more than CmdId/type pairs. Historical rows also contained a metadata-usage destination, a type-cache slot RVA, and the native store site that initialized that slot. Those columns give concrete anchors for reconstructing the registration-table extractor.

The strongest preserved row is `UnlockTransPointReq = 9369`:

```text
index=2232
registry_flag=1
type_slot_rva=0x057E6498
usage_destination=37523
store_rva=0x07F852AB
type_index=405772
type_kind=18
type_definition_index=84249
type_name=DMMJNICDOHM
```

## Stage 2a — recover metadata-usage initializer stores

The preserved born-protocol audit identified RVA `0x00523400` as the 7.1 IL2CPP metadata-usage initializer. It also preserved three useful aggregate anchors from the previous full scan:

```text
direct calls to 0x00523400:        430749
calls with direct mov ecx, IMM:     430737
unique immediate usage IDs:         311716
```

`genshinre.usage` reconstructs the local evidence chain around those calls. It scans executable PE sections for a direct `call rel32` to `0x00523400`, searches backward for a conservative immediate load into ECX/RCX, then searches forward for a simple RIP-relative write to a static slot.

```bash
python -m genshinre.usage \
  inputs/GenshinImpact.exe \
  work/metadata-usage-sites.csv \
  --summary work/metadata-usage-sites.summary.json
```

The important row shape is:

```text
usage_destination -> mov_rva -> call_rva -> store_rva -> type_slot_rva
```

For the exact preserved 7.1 sample, the strongest hard anchor is:

```text
37523 -> ... -> 0x07F852AB -> 0x057E6498
```

Use `--require-9369-anchor` when you want the command to fail closed if that exact triplet is not recovered. Use `--all-calls` only for auditing the complete direct-call population; the default CSV keeps rows where both an immediate usage ID and a RIP-relative store were recovered.

The output remains **candidate evidence**. The scanner recognizes only a deliberately narrow set of x86-64 forms. A mismatch can mean the reconstruction is wrong, the sample is wrong, or the compiler used an instruction form outside the current decoder. Do not force the historical counts into generated data.

## Stage 2b — probe known type slots

Use the generic scanner:

```bash
genshinre rip-xrefs inputs/GenshinImpact.exe 0x057E6498 0x057F6F60 --output work/type-slot-xrefs.json
```

Or run the fixed 7.1 probe set:

```bash
genshinre probe-registry-71 inputs/GenshinImpact.exe work/registry-probe-71.json
```

The fixed probe includes:

- `0x057E6498` — type slot for `9369 / DMMJNICDOHM`; historical store site `0x07F852AB`;
- `0x057F6F60` — type slot for `22899 / ONKOPMILDMF`;
- `0x057DE810` — non-protocol Traveler selection-page type slot used as a control.

The xref scanner recognizes a deliberately small set of x86-64 RIP-relative `mov`/`lea` forms. Its output is discovery evidence, not a disassembly. Missing xrefs can mean the client uses an instruction form outside the scanner's current subset.

Inspect any interesting site with:

```bash
genshinre inspect-rva inputs/GenshinImpact.exe 0x07F852AB --before 64 --after 128
```

## Next reconstruction boundary

Stage 2a gives a reproducible `usage_destination -> type_slot_rva` relation. The next missing relation is the one that turns a usage destination into the resolved IL2CPP type index/type definition, followed by the client protocol registration structure that binds `CmdId + registry_flag + type_slot`.

Keep these layers separate in intermediate artifacts. A type-slot mapping can be statically correct even while the surrounding protocol identity remains unresolved. The final regenerated registry still has to reproduce or explain the preserved 4,896 unique CmdIds and pass the independent AstaPS control-set cross-check before it becomes canonical.
