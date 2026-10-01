# UnlockTransPoint protocol recovery

Status: **UNRESOLVED**

## Confirmed anchor

```text
UnlockTransPointReq
7.1 CmdId: 9369
known request fields: scene_id = 12, point_id = 1
```

`UnlockTransPointRsp` remains unresolved for the current 7.1 client. A local/generated `retcode = field 6` shape is only a clue until current-client parser/static evidence confirms it.

## Historical clue

An older mapping recorded `UnlockTransPointRsp = 1776` for 7.0. Treat the numeric value as historical-only.

## Recovery path

1. Resolve CmdId 9369 in `registry.csv` to its obfuscated request type.
2. Use metadata/sender xrefs to locate the request call site and surrounding interaction state.
3. Identify the client success consumer that clears the unlock interaction or updates map-point state.
4. Trace that consumer back to a network handler and packet type.
5. Recover that type's `GetCmdId` and protobuf parser shape.
6. Validate the candidate with the smallest possible runtime response.
7. Record both accepted and rejected candidates here.

## Desired reusable outputs

- request registry row;
- request sender xref;
- response candidate list;
- response handler/type relation;
- parser/message shape;
- final CmdId mapping with runtime evidence.
