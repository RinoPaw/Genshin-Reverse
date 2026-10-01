# Native 7.1 protocol registry layout recovery

This stage attempts to recover the compact client protocol-registration structure that produced the earlier successful 4,896-row audit. It deliberately runs multiple structural hypotheses in parallel and does not promote a plausible match directly into canonical `registry.csv`.

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

The two direction controls currently support `flag 1 = C2S` and `flag 0 = S2C` for these rows. Global flag semantics remain provisional until a recovered table independently explains the full population.

## Hypothesis A — direct type-slot field

`genshinre.registrylayout` assumes a compact fixed-stride structure where the CmdId column is accompanied by a flag field and an expanded type-slot address.

It searches the exact 7.1 PE for layouts where the row spacing implied by index 2232 and index 3118/3117 places both known CmdIds correctly. Candidate rows are then tested for:

- a common fixed stride;
- a common CmdId column;
- a common field containing both preserved type-slot values as RVA32, RVA64, or VA64;
- a common flag field containing `1` for 9369 and `0` for 22899;
- protocol-range CmdId values and column uniqueness across the preserved 4,896-row scale.

Run:

```bash
python -m genshinre.registrylayout \
  inputs/GenshinImpact.exe \
  work/7.1.0-global/windows-x64/registry-layout-71.json
```

A 32-bit CmdId interpretation is preferred only as a deterministic tie-breaker when a 16-bit prefix produces the same structural evidence. The preference does not increase the evidence score.

## Hypothesis B — metadata usage-destination field

`genshinre.registryusagelayout` tests a second layout model: the compact registry row may carry the metadata usage destination and rely on the IL2CPP metadata-usage layer to obtain the static type slot.

This is motivated by the preserved 9369 raw row, which contains both:

```text
usage_destination = 37523
type_slot_rva     = 0x057E6498
```

and by the independently reconstructed `metadata-usage-slots.csv` table.

The probe first resolves both anchor types through `metadata-usage-types.csv`, then searches for a common fixed-stride row layout containing:

- 9369 at row index 2232;
- 22899 at row index 3118 or 3117;
- their independently resolved usage destinations at the same relative field offset;
- `registry_flag` values 1 and 0 at the same relative field offset.

The candidate is scored across all 4,896 rows using:

- CmdId protocol-range fraction;
- CmdId uniqueness;
- metadata usage-destination resolution fraction;
- binary flag fraction.

Run:

```bash
python -m genshinre.registryusagelayout \
  inputs/GenshinImpact.exe \
  work/7.1.0-global/windows-x64/metadata-usage-types.csv \
  work/7.1.0-global/windows-x64/registry-usage-layout-71.json
```

## Acceptance boundary

A layout becomes strong evidence only when one structure naturally satisfies the preserved constraints. At minimum, a publishable regenerated raw registry should explain:

1. the exact 4,896-row population without padding or trimming;
2. 4,896 unique protocol CmdIds, or a documented reason for any discrepancy;
3. both indexed anchors and their static type identities;
4. a stable flag column whose interpretation is independently consistent with known C2S and S2C messages;
5. metadata usage/type linkage that reproduces the 9369 raw row;
6. complete coverage of the current independent AstaPS control set, with any mismatch investigated;
7. exact sample SHA-256 provenance and generator revision.

Even after this structural closure, unknown semantic protobuf names still require parser/handler/sender/runtime evidence. The native table establishes protocol membership, numeric identity, client type identity, and potentially direction; it does not invent semantic names.

## Relationship to other artifacts

Use these artifacts together:

```text
metadata-usage-sites.csv       call-site audit evidence
metadata-usage-slots.csv       usage destination -> static slot
metadata-usage-types.csv       usage destination -> runtime/typeDefinition identity
getcmdid-candidates.csv        conservative constant-return candidates
registry-candidate-graph.csv   joined discovery graph
registry-static-candidates.csv one-to-one structural subset
registry-layout-71.json        direct-slot native layout hypothesis
registry-usage-layout-71.json  usage-backed native layout hypothesis
```

The layout probes are intentionally independent from the candidate graph. Agreement between them is much stronger than either path alone and is the intended route to regenerating the old raw registry without silently reusing its conclusions.
