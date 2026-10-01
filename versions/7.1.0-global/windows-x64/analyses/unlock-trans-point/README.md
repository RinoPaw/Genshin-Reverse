# UnlockTransPoint protocol recovery

Status: **UNRESOLVED**

## Confirmed anchor

```text
UnlockTransPointReq
7.1 CmdId: 9369
known request fields: scene_id = 12, point_id = 1
```

AstaPS `play/rino` registers `HandlerUnlockTransPointReq` on CmdId `9369`. The handler resolves the scene point and performs the server-side unlock through `TransPointUnlockHelper.unlock(...)`.

`UnlockTransPointRsp` remains unresolved for the current 7.1 client. `PacketOpcodes.UnlockTransPointRsp` is still `0`. A local/generated `retcode = field 6` shape is only a clue until current-client parser/static evidence confirms it.

## Current AstaPS workaround

After a successful unlock, the handler sends `GetScenePointRsp` so the client refreshes the scene-point list, then constructs `PacketUnlockTransPointRsp` using the unresolved opcode.

This is useful as a temporary gameplay workaround, but it does not identify the real 7.1 response. Runtime validation of a future candidate should initially remove or suppress the extra `GetScenePointRsp` refresh so the visible result can be attributed to the recovered response itself.

## Historical clue

An older mapping recorded `UnlockTransPointRsp = 1776` for 7.0. Treat the numeric value as historical-only. It is tracked in `candidates.csv` and must not be promoted without current-client evidence.

## Repository dependency exposed by this task

`tools/query_registry.py` is already present, but the canonical 7.1 `registry/registry.csv` is not yet checked in. A previous static-analysis pass recovered 4,896 unique client CmdIds and cross-checked 1,540 then-known AstaPS opcodes successfully.

Backfilling that registry is currently the highest-value dependency for this investigation. Once it exists, the first query is simply:

```text
9369 -> obfuscated request type
```

That type provides a stable starting node for sender, manager, handler and parser xrefs.

## Recovery path

1. Resolve CmdId 9369 in `registry.csv` to its obfuscated request type.
2. Use metadata/sender xrefs to locate the request call site and surrounding interaction state.
3. Identify the client success consumer that clears the unlock interaction or updates map-point state.
4. Trace that consumer back to a network handler and packet type.
5. Recover that type's `GetCmdId` and protobuf parser shape.
6. Validate the candidate with the smallest possible runtime response. If success is represented only by default `retcode = 0`, try an empty payload first.
7. Record both accepted and rejected candidates in `candidates.csv`.
8. Promote the mapping only after static identity and runtime behavior agree.

## Runtime validation target

For a fresh locked waypoint, a successful mapping should produce this minimal sequence:

```text
client sends 9369
server changes unlock state once
server sends recovered UnlockTransPointRsp
client finishes the interaction without timeout/retry
client shows the waypoint unlocked
```

If the confirmed Rsp still requires a separate point-state notification or scene-point refresh, record that as a distinct lifecycle requirement rather than folding it into the response mapping.

## Desired reusable outputs

- request registry row;
- request sender xref;
- response candidate list;
- response handler/type relation;
- parser/message shape;
- final CmdId mapping with runtime evidence.

The target sample identity is recorded in `../../hashes.json`.
