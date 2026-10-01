# Metadata indexes

Machine-queryable indexes derived from the matching 7.1 metadata/IL2CPP sample belong here.

Preferred outputs:

- `types.csv`
- `methods.csv`
- `fields.csv`
- `type-methods.json`
- `method-pointers.csv`

The key use case is fast graph traversal: CmdId -> obfuscated type -> typeDefinitionIndex -> methods/fields -> handler/sender/parser/xrefs.

Preserve raw indexes and RVAs alongside semantic annotations so later naming corrections do not invalidate the underlying identity.
