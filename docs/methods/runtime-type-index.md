# 7.1 IL2CPP runtime type index

The historical full registry rows retained both a metadata type definition and an IL2CPP runtime `type_index`. Keeping those two identities separate is useful because client metadata-usage and registration code often refer to the runtime type table first.

The strongest preserved example is `UnlockTransPointReq = 9369`:

```text
type_index=405772
type_kind=18 (0x12, class)
type_definition_index=84249
type_name=DMMJNICDOHM
```

`genshinre.typearray` exports a queryable reverse index from the 7.1 executable's runtime type array:

```bash
python -m genshinre.typearray \
  inputs/GenshinImpact.exe \
  work/7.1.0-global/windows-x64/metadata/types.csv \
  work/7.1.0-global/windows-x64/metadata/runtime-types.csv \
  --summary work/7.1.0-global/windows-x64/metadata/runtime-types.summary.json
```

The default output keeps class/valuetype entries whose `data` resolves to a decoded metadata type definition. Use `--all-kinds` only when auditing the raw table.

The extractor is pinned to the preserved 7.1 executable hash by default. Its hard regression anchor is:

```text
405772 -> kind 0x12 -> typeDefinition 84249 -> DMMJNICDOHM
```

Pass `--require-anchor` when you want a fail-closed check for that identity.

## Scan boundary

The current tool intentionally does not claim that it has recovered the authoritative runtime `typesCount`. It scans at most one million entries, bounded by the containing PE section, and records that boundary in the summary. This is enough to test the preserved 405772 anchor and build a useful reverse type-definition index while the exact metadata-registration structure is still being reconstructed.

The summary also records qwords around the pointer source RVA. Those values are useful when deriving the actual `Il2CppMetadataRegistration` layout for this protected build. Once an authoritative count is independently recovered, the scanner should switch from a bounded research scan to that exact count.

## How it fits registry recovery

This stage gives:

```text
runtime type_index -> kind -> typeDefinition -> obfuscated type name
```

The metadata-usage scanner gives:

```text
usage_destination -> call/store evidence -> type-slot RVA
```

The remaining join is to establish how the 7.1 initializer maps `usage_destination` to the runtime `type_index`, then recover the protocol registration structure binding `CmdId + registry_flag + type-slot`. Keep all intermediate relations in separate machine-readable artifacts so each layer can be independently checked.
