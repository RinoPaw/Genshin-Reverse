# UnlockTransPoint protocol recovery

Status: **UNRESOLVED** for the response; request side is **CONFIRMED**.

## Confirmed request anchor

```text
UnlockTransPointReq
7.1 CmdId:              9369 / 0x2499
client type:            DMMJNICDOHM
typeDefinition:         84249
type slot RVA:          0x057E6498
usage destination:      37523
registry store RVA:     0x07F852AB
field start/count:      417613 / 2
GetCmdId:               DMMJNICDOHM.AEGNNPENLNM @ 0x0C87EA60
parser-like method:     DMMJNICDOHM.IENGFLPCLNM @ 0x0C87E6A0
constructor:            DMMJNICDOHM..ctor @ 0x0C87E8F0
```

The public 7.1 dumped proto independently agrees with the recovered type:

```proto
// CmdId: 9369
message DMMJNICDOHM {
    uint32 NEAFKBADNDA = 12;
    uint32 GKPKNPFEPBF = 1;
}
```

AstaPS interprets those fields as `scene_id = 12` and `point_id = 1`. The preserved registry row has flag `1`; together with the 22899 receive-side control this supports `1 = C2S` for this sample.

The canonical request row is now stored in `../../registry/registry.csv`.

## Unresolved response

`UnlockTransPointRsp` remains unresolved for the current 7.1 client. AstaPS `play/rino` still has `UnlockTransPointRsp = 0`.

The local/generated response proto says `int32 retcode = 6`. Current-client evidence has not yet proved that field number, so it remains a structural clue.

## Current AstaPS workaround

After a successful unlock, `HandlerUnlockTransPointReq` sends `GetScenePointRsp` so the client refreshes the scene-point list, then constructs `PacketUnlockTransPointRsp` using the unresolved opcode.

Runtime validation of a future response candidate must initially suppress the extra `GetScenePointRsp` refresh. That isolates whether the recovered response itself completes the interaction and whether an additional point-state packet is genuinely required.

## Historical clue

Genshin 7.0 mapped:

```text
UnlockTransPointRsp = 1776
obfuscated type = CPKAHGFBBIH
shape = int32 retcode field 6
```

The number `1776` is historical-only. It must not be copied into the 7.1 table.

## 7.1 structural search

The 7.1 dump uses the common obfuscated retcode field name `BLPJNJBFDJJ` on many responses. Use the repository shape filter to reproduce the old `find_retcode6_candidates.py` style search:

```bash
python -m genshinre.proto_shape \
  path/to/7.1.0/Obfuscated.proto \
  --field-type int32 \
  --field-number 6 \
  --field-name BLPJNJBFDJJ \
  --single-field \
  --translations path/to/7.1.0/nameTranslation.txt \
  --output work/unlock-trans-point-retcode6.json
```

This is candidate generation only. Every candidate still needs receive-direction evidence plus a handler/state-machine relationship or equivalent static proof.

## External type-slot xref checkpoint

A 7.1 executable scan traced RIP-relative references to the request slot, the scene-point notify control, the born-point control pair, and every current single-field response candidate. The workflow artifact is from run `36869811621`, artifact `11166782212`, digest `sha256:0f7fb2f4629499127cd2edfb403837a8a8f683cc86a930c915e07d2e28c2563f`.

The registry identity for CmdId `9369` is still `DMMJNICDOHM`. The external owner type `KLLNGCPBLMM` seen in the xref artifact is the declaring type of a method that references the `DMMJNICDOHM` type slot; it is not the message type. This resolves the apparent `DMMJNICDOHM` / `KLLNGCPBLMM` conflict.

Control observations from that scan:

```text
26105 external owner types: EDKMMIPJHJA
4385  external owner types: none
9369  external owner types: KLLNGCPBLMM
25567 external owner types: NHFPOGNBPPE
```

The born request/response control pair had no shared external owner type, and `9369` shared no external owner type with the scene-point notify control. None of the current single-field response candidates shared an external owner type with `9369`; all `shared_count` values were zero. The simple "same controller type references both request and response slots" heuristic therefore produced no response identity and should not be treated as positive evidence for any candidate.

## Recovery path

1. Generate the exact single-field `int32 field #6` candidate set from the 7.1 proto dump.
2. Remove candidates already translated or mapped to unrelated current messages.
3. Resolve remaining types through the client registry / metadata indexes.
4. Locate S2C handlers and identify the one tied to teleport-point interaction state.
5. Confirm its `GetCmdId()` and parser field number directly in the 7.1 executable.
6. Validate the smallest possible response at runtime, preferably empty payload for `retcode = 0`.
7. Record rejected candidates and their rejection evidence in `candidates.csv`.
8. Promote the mapping only after static identity and runtime behavior agree.

## Runtime validation target

For a fresh locked waypoint:

```text
client sends 9369
server changes unlock state once
server sends recovered UnlockTransPointRsp
client finishes the interaction without timeout/retry
client shows the waypoint unlocked
```

If a confirmed Rsp still requires a separate point-state Notify or scene-point refresh, record that as a distinct lifecycle requirement.

## Desired reusable outputs

- full 7.1 registry row for the response;
- response handler/type relation;
- parser/message shape;
- accepted/rejected candidate table;
- runtime trace proving interaction completion.

The target sample identity is recorded in `../../hashes.json`.
