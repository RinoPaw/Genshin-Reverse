# Metadata indexes

Machine-queryable indexes derived from the matching 7.1 metadata/IL2CPP sample belong here.

Canonical generated targets:

- `types.csv`
- `methods.csv`
- `fields.csv`
- `type-methods.json`
- `method-pointers.csv`
- `runtime-types.csv`

The canonical generated files are intentionally absent until the native 7.1 decoder runs against the exact sample and reproduces the preserved counts and anchors. Small audit seeds must not occupy these filenames because absence from a seed cannot be interpreted as absence from the client.

Historical hand-recovered evidence is kept under `historical-seed/`.

The native decoder is gated on the exact 7.1 sample hashes and the preserved counts:

- 88,904 type definitions
- 440,172 fields
- 733,442 methods

Generated artifacts are published into this directory only after those counts match and the runtime-type / metadata-usage / GetCmdId / registry-graph anchors pass.

Common query after publication:

```bash
genshinre query-methods methods.csv --parameter-type ONKOPMILDMF
```

The key traversal is `CmdId -> obfuscated type -> typeDefinitionIndex -> methods/fields -> handler/sender/parser/xrefs`.
