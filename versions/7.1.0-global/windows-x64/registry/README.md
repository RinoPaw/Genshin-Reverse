# Registry artifacts

This directory contains protocol-registry artifacts for the exact 7.1 sample in `../hashes.json`.

Canonical filenames are reserved for the complete, publication-gated 7.1 dataset:

- `registry.csv`: complete primary query surface
- `registry.json`: complete JSON equivalent
- `summary.json`: completeness and generation statistics

They are intentionally absent until the native registry recovery closes and the publication gates pass. A small historical seed must never occupy these canonical filenames.

Preserved historical evidence remains in:

- `historical-recovery-samples.csv`
- `historical-recovery-schema.md`

Canonical columns:

```text
cmd_id,type_name,type_definition_index,type_cache_rva,direction,get_cmd_id_rva,semantic_name,status,evidence,notes
```

The earlier 7.1 analysis recovered 4,896 unique CmdIds and cross-checked all 1,540 then-known AstaPS numeric opcodes. The regenerated canonical files may be published only after the current native direct-slot and usage-backed recovery paths agree row-for-row, direction controls pass, and the current AstaPS control set is covered.

Use `scripts/publish-registry-7.1.ps1` or `scripts/publish-registry-7.1.sh` after strict closure. The publisher rejects incomplete or ambiguous input.
