# Dataset schemas

These are the canonical column sets for the highest-value datasets. Extra columns are welcome; avoid renaming/removing core identity columns without a migration note.

## registry/registry.csv

```text
cmd_id,type_name,type_definition_index,type_cache_rva,direction,get_cmd_id_rva,status
```

## metadata/types.csv

```text
type_definition_index,namespace,type_name,parent_type,field_start,field_count,method_start,method_count,type_cache_rva
```

## metadata/methods.csv

```text
method_index,type_definition_index,type_name,method_name,rva,return_type,parameter_types
```

`parameter_types` should use JSON array syntax inside CSV when more than one parameter is present.

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

## proto/message-shapes.json

Key by original obfuscated type identity when possible. Each message may include `cmd_id`, recovered parser fields, wire types, likely semantic types and evidence/provenance.
