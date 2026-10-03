# Registry slot xref recovery

The current 7.1 canonical registry is already closed at 4,896 identities. This document describes the two reusable evidence layers that established and can reproduce the slot side of that closure.

## Verified constructor slots

`registry/registry-type-slots.csv` records the exact 4,896 registry constructor/type slots. Two preserved controls are:

```text
UnlockTransPointReq / 9369
index=2232
type_slot_rva=0x057E6498
type_definition_index=84249
type_name=DMMJNICDOHM

DoSetPlayerBornDataNotify / 22899
index=3118
type_slot_rva=0x057F6F60
type_definition_index=87483
type_name=ONKOPMILDMF
```

These slots are exact-sample evidence. They are independent of semantic packet names and historical opcode equality.

## Candidate type to registry slot relation

`genshinre.registryslotxref` scans methods declared on current GetCmdId candidate types for RIP-relative references to the verified constructor slots.

```bash
python -m genshinre.registryslotxref \
  inputs/GenshinImpact.exe \
  versions/7.1.0-global/windows-x64/metadata/methods.csv \
  versions/7.1.0-global/windows-x64/registry/getcmdid-candidates.csv \
  versions/7.1.0-global/windows-x64/registry/registry-type-slots.csv \
  work/registry-slot-xrefs.csv \
  --summary work/registry-slot-xrefs.summary.json
```

The scanner retains every referenced verified slot and ranks multiple relations by instruction count and distinct declaring-method count. It does not guess when no slot is referenced.

For the pinned 7.1 sample the primary relation closes all 4,896 protocol identities, with 4,891 unique single-slot references and a unique dominant slot for all 4,896 types. The preserved 9369 and 22899 controls must resolve to their exact slots.

`registry-slot-xrefs.csv` is supporting evidence for `genshinre.registryxrefpublish`. The publisher independently requires:

- exactly 4,896 verified constructor slots;
- exactly one primary xref identity per selected type;
- unique CmdIds and type definitions;
- every verified slot selected exactly once;
- exact preserved control matches.

Only after those gates pass can the relationship be published as `registry/registry.csv`.

## Generic inspection tools

For a small set of slots, use the generic scanner:

```bash
genshinre rip-xrefs inputs/GenshinImpact.exe 0x057E6498 0x057F6F60 --output work/slot-xrefs.json
```

Inspect a specific native site with:

```bash
genshinre inspect-rva inputs/GenshinImpact.exe 0x07F852AB --before 64 --after 128
```

These commands are discovery aids. Canonical identity still comes from the publication gate over the complete exact-sample evidence set.

The former metadata-usage convergence route and `type-cache` naming were retired after full registry closure. Git history preserves those experiments; they are not maintained current data paths.
