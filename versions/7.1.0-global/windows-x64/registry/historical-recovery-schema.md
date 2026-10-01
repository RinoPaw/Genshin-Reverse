# Preserved 7.1 registry recovery schema

This file preserves the richer row layout used by the earlier successful 7.1 client registry recovery. The original `decode_registry.py` and full 4,896-row output were not retained in an accessible repository, so this is recovery evidence for reconstructing the generator.

The historical CSV header was:

```text
index,cmd_id,cmd_hex,known_names,registry_flag,type_slot_rva,usage_destination,store_rva,type_index,type_kind,type_data,type_definition_index,type_name,name_token,field_start
```

A preserved row for the current 7.1 `UnlockTransPointReq = 9369` was:

```text
2232,9369,0x2499,,1,0x57e6498,37523,0x7f852ab,405772,18,84249,84249,DMMJNICDOHM,0xb8aeaf6,417613
```

Independent follow-up metadata work confirmed typeDefinition `84249` is `DMMJNICDOHM`, with two fields beginning at field index `417613` and eight methods beginning at method index `696275`.

Another preserved registry result is:

```text
22899 -> ONKOPMILDMF
TypeDefIndex: 87483
Type-cache slot RVA: 0x057F6F60
registry flag: 0
```

The client receive/handler chain identifies that row as server-to-client traffic. The 9369 row has flag `1` and is a confirmed client-to-server request. These controls support the historical interpretation `0 = S2C`, `1 = C2S`; a regenerated table must revalidate the flag semantics before publishing them as a general rule.

## Column interpretation

Some meanings are directly established by the preserved artifacts, while implementation details of the lost decoder are still being reconstructed:

- `index`: row/order index in the recovered registration dataset.
- `cmd_id` / `cmd_hex`: registered numeric CmdId.
- `known_names`: optional semantic names from an independent known-opcode set.
- `registry_flag`: client registration-direction/category flag; controls above support `0=S2C`, `1=C2S` for this sample.
- `type_slot_rva`: IL2CPP type-cache/metadata-usage destination slot RVA associated with the registered message type.
- `usage_destination`: metadata-usage destination index associated with that slot.
- `store_rva`: native RVA of the initialization/store site that writes the resolved type into the destination slot.
- `type_index`: IL2CPP type-table index resolved from the usage destination.
- `type_kind`: IL2CPP type kind; the 9369 row records decimal 18 (`0x12`, class).
- `type_data`: type payload/index; for the 9369 class this is `84249`.
- `type_definition_index`: resolved metadata type-definition index.
- `type_name`: decoded obfuscated client type name.
- `name_token`: metadata token/offset used by the build-specific metadata decoder to recover the type name.
- `field_start`: first metadata field index for the type definition.

## Reconstruction target

The regenerated decoder should preserve these rich recovery columns in a raw/intermediate dataset, then project stable identity fields into canonical `registry.csv`. This keeps details such as metadata-usage destinations and store sites available for auditing without forcing build-specific columns into the cross-version canonical schema.

Historical validation for the lost full output:

- 4,896 unique CmdIds.
- all 1,540 then-known AstaPS numeric opcodes were present.
- `26105 -> HJDNCHODGOL`, whose GetCmdId method at RVA `0x10587260` returns `0x65F9`.

These figures are regression anchors. They must be reproduced or explained, never hard-coded as expected output.
