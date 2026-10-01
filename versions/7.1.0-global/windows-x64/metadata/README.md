# Metadata indexes

Machine-queryable indexes derived from the matching 7.1 metadata/IL2CPP sample belong here.

Canonical targets:

- `types.csv`
- `methods.csv`
- `fields.csv`
- `type-methods.json`
- `method-pointers.csv`

The current committed files are **partial seeds** reconstructed from preserved client-audit evidence. They exist so current investigations can already perform stable graph lookups while the full metadata decoder is regenerated.

Preserved earlier analysis reported 88,904 decoded IL2CPP type names, 440,172 field names, and 733,442 method names. A regenerated complete index should reproduce/justify its own counts and sample hashes before replacing the seed.

Common query:

```bash
genshinre query-methods methods.csv --parameter-type ONKOPMILDMF
```

The key traversal is `CmdId -> obfuscated type -> typeDefinitionIndex -> methods/fields -> handler/sender/parser/xrefs`.
