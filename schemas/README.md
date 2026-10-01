# Dataset schemas

These are the canonical column sets for the highest-value datasets. Extra columns are welcome; avoid renaming/removing core identity columns without a migration note.

## registry/registry.csv

```text
cmd_id,type_name,type_definition_index,type_cache_rva,direction,get_cmd_id_rva,semantic_name,status,evidence,notes
```

`registry/summary.json` must state whether a dataset is partial. A full registry should also record independent control-set crosscheck counts.

## metadata/types.csv

```text
type_definition_index,namespace,type_name,parent_type,field_start,field_count,method_start,method_count,type_cache_rva
```

## metadata/methods.csv

```text
method_index,type_definition_index,type_name,method_name,rva,return_type,parameter_types
```

`parameter_types` uses JSON array syntax inside CSV when possible. `genshinre query-methods` also accepts pipe-separated legacy values.

## metadata/fields.csv

```text
field_index,type_definition_index,type_name,field_name,field_type,offset
```

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
