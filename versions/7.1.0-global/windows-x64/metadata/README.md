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

Currently published canonical artifacts:

- `types.csv`
- `methods.csv`
- `type-methods.json`
- `runtime-types.csv`

Still pending canonical publication:

- `fields.csv`
- `method-pointers.csv`

Historical hand-recovered evidence remains under `historical-seed/` and must not be treated as a complete client index.

The decoder and publication path are bound to the exact 7.1 sample hashes. Preserved reference counts are:

- 88,904 type definitions
- 440,172 fields
- 733,442 methods

These counts are regression evidence. They are not used to pad or trim generated output. A canonical artifact should be published only after exact-sample provenance and the relevant runtime-type / metadata-usage / GetCmdId / registry anchors pass.

Common query:

```bash
genshinre query-methods methods.csv --parameter-type ONKOPMILDMF
```

The key traversal is `CmdId -> obfuscated type -> typeDefinitionIndex -> methods/fields -> handler/sender/parser/xrefs`.

If a focused investigation needs an index that is still missing here, generate it through reusable tooling and preserve the generator/provenance rather than committing a hand-selected subset under a canonical filename.
