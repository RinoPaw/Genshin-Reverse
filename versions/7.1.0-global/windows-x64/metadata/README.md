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

Historical hand-recovered evidence remains under `historical-seed/` and must not be treated as a complete client index.

The decoder and publication path are bound to the exact 7.1 sample hashes. The regenerated exact-sample counts are:

- 88,904 type definitions
- 440,172 fields
- 733,442 methods
- 733,442 method-pointer rows

These counts are regression evidence. They are not used to pad or trim generated output. Publication validates the exact sample hashes, native decoder counts, CSV row counts and the complete method-pointer table before copying canonical metadata artifacts into this version directory.

Common query:

```bash
genshinre query-methods methods.csv --parameter-type ONKOPMILDMF
```

The key traversal is `CmdId -> obfuscated type -> typeDefinitionIndex -> methods/fields -> handler/sender/parser/xrefs`.

New canonical indexes should be generated through reusable tooling with sample provenance and validation rather than committed as hand-selected subsets.
