# Dataset schemas

These are the canonical published column sets for the highest-value datasets. Decoder work files may carry additional provenance columns. Avoid renaming/removing published identity columns without a migration note.

## registry/registry.csv

```text
index,cmd_id,type_name,type_definition_index,direction,direction_status,semantic_name,type_slot_rva,get_cmd_id_rva,get_cmd_id_method,load_rva,store_rva,xref_count,xref_method_count,status,evidence
```

`registry/registry.summary.json` is the companion publication record. For the current 7.1 canonical identity registry it records the complete 4,896-row / 4,896-unique-CmdId closure and the strict registry-slot / type-definition / CmdId bijection gate.

`schemas/registry.schema.json` describes the logical row shape. CSV values are serialized as text on disk; tools may normalize numeric columns when loading them.

## registry/control-set.csv

Broad comparison/control data imported from the current AstaPS `PacketOpcodes.java`. It is not an evidence-gated target-client semantic mapping. Confirmed 7.1 semantic mappings live separately in `proto/known-opcodes.csv`.

## metadata/types.csv

```text
type_definition_index,namespace,type_name,parent_type,field_start,field_count,method_start,method_count,name_token,record_file_offset
```

## metadata/methods.csv

```text
method_index,type_definition_index,type_name,method_name,rva,return_type,parameter_types,parameter_start,parameter_count,name_token
```

`parameter_types` uses JSON array syntax inside CSV. Full native decoder work output also retains `parameter_type_indices`, `record_file_offset`, `status` and `evidence`; the Git-published canonical CSV is the compact query projection above.

`genshinre query-methods` also accepts pipe-separated legacy `parameter_types` values when reading older external inputs.

## metadata/fields.csv

```text
field_index,type_definition_index,type_name,field_name,field_type,field_type_index,name_token,offset,record_file_offset
```

## metadata/method-pointers.csv

```text
method_index,rva,va
```

## metadata/type-methods.json

Compact lookup index with two maps:

```text
by_type_name -> [method_index, ...]
by_type_definition_index -> [method_index, ...]
```

It deliberately does not duplicate complete method rows.

## xrefs/message-handlers.csv

```text
cmd_id,type_name,direction,handler_type,handler_method,handler_rva,status
```

## xrefs/message-senders.csv

```text
cmd_id,type_name,sender_type,sender_method,sender_rva,context,status
```

## runtime observations

```text
timestamp,offset_ms,direction,cmd_id,name,length,payload_hex,source
```

## proto/message-shapes.json

Key by semantic name when confirmed and by stable obfuscated/unknown identity while unresolved. Each message may include `cmd_id`, parser-derived field numbers, wire types, likely semantic types and evidence/provenance.

## analyses/<topic>/evidence.json

Focused investigations may add a machine-readable evidence index alongside their narrative README. Use `analysis-evidence.schema.json`; keep investigation `state` separate from claim-level evidence `status`. See `docs/analysis-contract.md` for promotion and provenance rules.
