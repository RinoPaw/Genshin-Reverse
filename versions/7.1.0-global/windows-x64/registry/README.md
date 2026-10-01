# Registry artifacts

This directory contains the client CmdId -> IL2CPP message identity dataset for the exact sample in `../hashes.json`.

Canonical files:

- `registry.csv`: primary query surface
- `registry.json`: JSON equivalent for scripts
- `summary.json`: completeness and generation statistics

Canonical columns:

```text
cmd_id,type_name,type_definition_index,type_cache_rva,direction,get_cmd_id_rva,semantic_name,status,evidence,notes
```

The currently committed 7.1 registry is deliberately marked **partial**. Two rows were reconstructed from preserved audit evidence. Earlier analysis had recovered 4,896 unique CmdIds and cross-checked all 1,540 known AstaPS opcodes, but that original generated dataset was not preserved in an accessible repository.

Never silently present the seed as the full registry. Regenerated full output should replace these files only after sample hashes and control-set checks match.

Normalize recovered raw output with:

```bash
genshinre normalize-registry work/registry-raw.csv . \
  --direction-map 0=S2C,1=C2S \
  --provenance ../hashes.json
```
