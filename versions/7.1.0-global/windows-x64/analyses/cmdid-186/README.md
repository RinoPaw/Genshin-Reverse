# CmdId 186

Status: **UNRESOLVED**

## Runtime observation

```text
CmdId:   186 / 0xBA
Direction: client -> server
Payload: 72 02 d0 27
Context: fresh-account born / intro login trace
```

Wire-level protobuf reading:

```text
0x72 -> field 14, wire type 2
0x02 -> length 2
body -> d0 27
```

If the body is interpreted as packed varints, it is `[5072]`. That is a structural hypothesis only; field 14 may be bytes or a nested message.

## Historical warning

Some old Genshin versions used numeric CmdId 186 for `PlayerPropChangeNotify`. CmdIds were remapped in later clients, so the old equality is `historical-only` and must not be copied into the 7.1 mapping.

## Recovery plan

1. Resolve `0xBA` in the 7.1 client registry / `GetCmdId` implementations.
2. Bind the registered type to `typeDefinitionIndex`, type-cache RVA and methods.
3. Locate parser and recover field 14 structure.
4. Locate sender/call context and compare it with the runtime intro/login timing.
5. Publish the mapping only when static identity and runtime context agree.

Expected sample hashes are in `../../hashes.json`.
