# Artifact contract

Every generated dataset should answer four questions without relying on someone's memory:

1. Which exact client sample produced this?
2. Which tool and revision produced it?
3. What transformation was performed?
4. How strong is the semantic conclusion?

## Provenance manifest

A version/platform directory should contain `hashes.json` and generated datasets should carry either embedded provenance fields or a sibling manifest. Recommended fields:

```json
{
  "game_version": "7.1.0",
  "region": "global",
  "platform": "windows-x64",
  "exe_sha256": "...",
  "metadata_sha256": "...",
  "generated_by": "tools/decode_registry.py",
  "tool_commit": "...",
  "command": "python tools/decode_registry.py ..."
}
```

## Stable identities

Obfuscated IL2CPP type names are valid stable node identities when they are bound to the same sample. Preserve `typeDefinitionIndex`, method indexes, RVAs and type-cache RVAs whenever available. Semantic names may be added in separate columns so later corrections do not destroy the original identity.

## Addresses

Prefer RVA as the portable stored address. If VA is also useful, record image base and both values explicitly. Never mix RVA and VA in one column.

## Evidence

Machine-readable mappings should include a `status` or `confidence` field. For protocol mappings, a strong final row usually contains:

- static evidence (`GetCmdId`, parser shape, handler/sender relationship);
- matching runtime behavior or packet observation;
- sample hashes.

Cross-project mappings are supporting evidence. Older-version numeric matches are historical clues.

## Keep computation-friendly data

A report is allowed to summarize a result, but the underlying CSV/JSON should remain available whenever practical. Examples: registry, metadata indexes, parser shapes, handler/sender xrefs, candidate lists and rejected-candidate tables.
