# Registry artifacts

This directory contains protocol-registry artifacts for the exact 7.1 sample in `../hashes.json`.

## Canonical identity registry

The current publication-gated 7.1 identity dataset is present:

- `registry.csv`: complete 4,896-row primary query surface
- `registry.summary.json`: closure statistics, control anchors and publication status

The canonical registry was closed from verified constructor/type slots plus dominant declaring-type code xrefs. The summary requires a strict one-to-one registry-slot / type-definition / CmdId mapping across all 4,896 rows.

Direction and semantic names are independent evidence layers. Blank or unresolved values do not invalidate the closed numeric/type identity registry.

Current canonical columns:

```text
index,cmd_id,type_name,type_definition_index,direction,direction_status,semantic_name,type_slot_rva,get_cmd_id_rva,get_cmd_id_method,load_rva,store_rva,xref_count,xref_method_count,status,evidence
```

`registry.json` and `summary.json` belong to an older native-layout publication path and are not canonical filenames for the current xref-published dataset. Do not regenerate or overwrite the current registry through that legacy contract.

## Supporting evidence

Preserved historical evidence remains in:

- `historical-recovery-samples.csv`
- `historical-recovery-schema.md`

Registry candidate graphs, metadata-usage joins, layout probes and similar files are research intermediates. They may be useful evidence, but they do not replace `registry.csv` unless a publication gate explicitly promotes a new complete identity dataset.

The current canonical publisher is `genshinre.registryxrefpublish`. General metadata/artifact publication validates and preserves the canonical registry in place; it does not attempt to re-close the registry through experimental heuristics.
