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

The scanner recognizes a deliberately small set of x86-64 RIP-relative `mov`/`lea` forms. Its output is discovery evidence, not a disassembly. Missing xrefs can mean the client uses an instruction form outside the scanner's current subset.

Inspect any interesting site with:

```bash
genshinre inspect-rva inputs/GenshinImpact.exe 0x07F852AB --before 64 --after 128
```

The next reconstruction step is to compare the instruction/data flow around the known 9369 store site with the xrefs found for other registered protobuf type slots. Repeated structure can then be promoted into a dedicated registration enumerator and checked against the preserved 4,896-entry/full-control-set invariants.
