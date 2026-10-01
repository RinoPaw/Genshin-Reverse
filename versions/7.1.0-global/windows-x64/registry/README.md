# Registry artifacts

This directory should contain the recovered client message registry for the exact sample in `../hashes.json`.

Primary targets:

- `registry.csv`
- `registry.json`
- `summary.json`

Canonical columns for `registry.csv`:

```text
cmd_id,type_name,type_definition_index,type_cache_rva,direction,get_cmd_id_rva,status
```

The registry is intended to be the fastest first lookup for a new unknown CmdId. Keep original obfuscated type identity even after a semantic name is recovered.
