# Metadata indexes

Machine-queryable indexes derived from the matching 7.1 metadata/IL2CPP sample belong here.

Canonical targets:

- `types.csv`
- `methods.csv`
- `fields.csv`
- `type-methods.json`
- `method-pointers.csv`
- `runtime-types.csv`

## Publication state

The canonical 7.1 metadata index set is published:

- `types.csv`
- `methods.csv`
- `fields.csv`
- `type-methods.json`
- `method-pointers.csv`
- `runtime-types.csv`

The early hand-recovered seed files were retired after the exact-sample native decoder and validated canonical indexes became available. Git history preserves those seed snapshots for provenance; they are not part of the current metadata contract.

The decoder and publication path are bound to the exact 7.1 sample hashes. The regenerated exact-sample counts are:

- 88,904 type definitions
- 440,172 fields
- 733,442 methods
- 733,442 method-pointer rows
- 683,574 runtime `Il2CppType` entries

The runtime type array starts at RVA `0x2E1EA20` and its verified half-open boundary is RVA `0x388CD80`. All indexes `0..683573` pass the exact-sample structural gate; index `683574` is the first boundary record and fails that gate. The compact published `runtime-types.csv` contains 228,519 named class/valuetype rows derived from that exact table.

These counts are regression evidence. They are not used to pad or trim generated output. Publication validates the exact sample hashes, native decoder counts, runtime type boundary, CSV row counts and the complete method-pointer table before copying canonical metadata artifacts into this version directory.

Canonical published CSVs are compact query indexes. Full decoder provenance columns remain in the regeneration work output and short-lived Actions artifact rather than being duplicated into Git.

Use the streaming query commands instead of loading or grepping the large canonical CSVs by hand:

```bash
genshinre query-methods methods.csv --type NLOMEGMJDGJ
genshinre query-methods methods.csv --type-definition-index 61556
genshinre query-methods methods.csv --parameter-type ONKOPMILDMF

genshinre query-fields fields.csv --type NLOMEGMJDGJ
genshinre query-fields fields.csv --type-definition-index 61556
genshinre query-fields fields.csv --field-type-index 476942
```

Text filters can be combined with exact numeric type/type-field indexes. `query-methods` and `query-fields` stream the CSV input so a focused lookup does not materialize the complete 7.1 table in memory.

The key traversal is `CmdId -> obfuscated type -> typeDefinitionIndex -> methods/fields -> handler/sender/parser/xrefs`.

New canonical indexes should be generated through reusable tooling with sample provenance and validation rather than committed as hand-selected subsets.
