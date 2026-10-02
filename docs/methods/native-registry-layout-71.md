# Native 7.1 protocol registry layout recovery

This method recovers the compact client protocol-registration structure that produced the historical 4,896-row audit. It remains valuable as independent structural reproduction evidence. Current canonical 7.1 identity publication is already closed through `genshinre.registryxrefpublish`; the native-layout path does not overwrite that dataset.

## Preserved indexed anchors

The historical 7.1 raw registry retained enough information to constrain a native table layout:

```text
9369 / UnlockTransPointReq / DMMJNICDOHM
row index          2232
registry_flag      1
usage_destination  37523
type_slot_rva      0x057E6498
```

A preserved born-flow note describes `22899 / ONKOPMILDMF` as the **3118th item**. Because that wording may be one-based, both row indices are tested:

```text
22899 / DoSetPlayerBornDataNotify / ONKOPMILDMF
row index candidate  3118 or 3117
registry_flag        0
type_slot_rva        0x057F6F60
```

These two rows also preserve opposite request/notification directions. They are local direction controls for the recovered flag field; broader direction claims require independent control coverage.

## Hypothesis A — direct type-slot field

`genshinre.registrylayout` tests a compact fixed-stride structure where the CmdId column is accompanied by a flag field and an expanded type-slot address.

It searches the exact 7.1 PE for layouts where the row spacing implied by index 2232 and index 3118/3117 places both known CmdIds correctly. Candidate rows are tested for:

- a common fixed stride;
- a common CmdId column;
- a common field containing both preserved type-slot values as RVA32, RVA64, or VA64;
- a common flag field containing `1` for 9369 and `0` for 22899;
- protocol-range CmdId values and column uniqueness across the preserved 4,896-row scale.

Run:

```bash
python -m genshinre.registrylayout \
  inputs/GenshinImpact.exe \
  work/7.1.0-global/windows-x64/registry-layout-probe.json
```

A 32-bit CmdId interpretation is preferred only as a deterministic tie-breaker when a 16-bit prefix produces the same structural evidence. The preference does not increase the evidence score.

## Hypothesis B — metadata usage-destination field

`genshinre.registryusagelayout` tests a second model where the compact registry row carries the metadata usage destination and relies on the IL2CPP metadata-usage layer to obtain the static type slot.

This is motivated by the preserved 9369 raw row:

```text
usage_destination = 37523
type_slot_rva     = 0x057E6498
```

and by the independently reconstructed metadata-usage layer.

The probe resolves both anchor types through `metadata-usage-types.csv`, then searches for a common fixed-stride row layout containing:

- 9369 at row index 2232;
- 22899 at row index 3118 or 3117;
- their independently resolved usage destinations at the same relative field offset;
- `registry_flag` values 1 and 0 at the same relative field offset.

The candidate is scored across all 4,896 rows using CmdId range/uniqueness, metadata-usage resolution and binary-flag consistency.

Run:

```bash
python -m genshinre.registryusagelayout \
  inputs/GenshinImpact.exe \
  work/7.1.0-global/windows-x64/metadata-usage-types.csv \
  work/7.1.0-global/windows-x64/registry-usage-layout-probe.json
```

The usage-backed path depends on optional metadata-usage recovery. An unresolved usage heuristic is reported as research debt and does not invalidate the exact-sample metadata/runtime/GetCmdId core datasets.

## Historical structural closure gate

The retained wrappers make the historical reproduction explicit:

```bash
scripts/close-registry-7.1.sh \
  --exe inputs/GenshinImpact.exe \
  --require-direction-perfect
```

The closure requires both independent native paths to produce natural 4,896-row / 4,896-unique-CmdId results and then requires row-by-row agreement with `genshinre.registrycompare`.

When `control-set.csv` is available, `genshinre.directionaudit` can additionally compare the recovered flag behavior with the independent AstaPS-derived control surface. The control set is comparison evidence; confirmed target-client semantic names remain in `proto/known-opcodes.csv`.

The historical projection wrapper writes to `work/.../historical-native-registry` by default. It deliberately stays outside the current canonical version path.

## Relationship to current canonical registry

Current canonical 7.1 identity is published from verified registry type slots and dominant declaring-type xrefs:

```text
registry/type-cache-xrefs.csv
registry/registry-type-slots.csv
        ↓
genshinre.registryxrefpublish
        ↓
registry/registry.csv
registry/registry.summary.json
```

The publication gate requires exactly 4,896 rows, 4,896 unique CmdIds and a strict slot/type/CmdId bijection.

Native-layout artifacts remain an independent way to reproduce historical structural evidence and catch contradictions. Agreement strengthens confidence; disagreement is a reason to investigate inputs or assumptions rather than overwrite the canonical registry.

## Related research artifacts

Depending on which optional stages close, a regeneration work directory may contain:

```text
metadata-usage-sites.csv          call-site audit evidence
metadata-usage-slots.csv          usage destination -> static slot
metadata-usage-types.csv          usage destination -> runtime/typeDefinition identity
getcmdid-candidates.csv           conservative constant-return candidates
registry-candidate-graph.csv      optional usage-backed discovery graph
registry-static-candidates.csv    optional one-to-one structural subset
registry-layout-probe.json        direct-slot native layout hypothesis
registry-usage-layout-probe.json  usage-backed native layout hypothesis
registry-native-direct.csv        direct native raw rows
registry-native-usage.csv         usage-backed native raw rows
registry-native-compare.json      row-by-row path comparison
registry-direction-audit.json     optional control-set direction audit
```

The native probes are intentionally independent from the xref canonical publisher. Their primary maintenance value is reproducibility, regression detection and cross-checking structural claims.
