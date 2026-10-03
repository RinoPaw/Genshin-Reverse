# UnlockTransPoint protocol recovery

Status: request side **CONFIRMED**; live waypoint unlock behavior is **CLOSED/VALIDATED** with the corrected `ScenePointUnlockNotify`; exact `UnlockTransPointRsp` identity remains an **UNRESOLVED STATIC TIE** and further response research is **PAUSED** because it has no observed gameplay value for the current AstaPS path. See `WORK_PROGRESS_2026-10-03.md` for the handoff checkpoint.

Pinned official global 7.1 sample:

```text
GenshinImpact.exe    08a3086d5f3fe695f01dab61efa42e442006b18e5e475b2520df356f6a073b7d
global-metadata.dat 05ae04d7a91b91cc880217a56b0b01f3e67f845b06e894216654ec5d160e0da0
```

## Confirmed request anchor

```text
UnlockTransPointReq
7.1 CmdId:              9369 / 0x2499
client type:            DMMJNICDOHM
typeDefinition:         84249
type slot RVA:          0x057E6498
registry store RVA:     0x07F852AB
field start/count:      417613 / 2
GetCmdId:               DMMJNICDOHM.AEGNNPENLNM @ 0x0C87EA60
parser-like method:     DMMJNICDOHM.IENGFLPCLNM @ 0x0C87E6A0
constructor:            DMMJNICDOHM..ctor @ 0x0C87E8F0
sender:                 KLLNGCPBLMM.OIFANGMCKNJ @ 0x0F0452B0
```

Recovered current wire shape:

```proto
// CmdId: 9369
message DMMJNICDOHM {
    uint32 NEAFKBADNDA = 12; // scene_id
    uint32 GKPKNPFEPBF = 1;  // point_id
}
```

## Response candidate state

Historical 7.0 control:

```text
UnlockTransPointRsp
CmdId      1776
client type CPKAHGFBBIH
wire shape int32 retcode = 6
handler    KGCKOFPFBLA.NDKDCLAKKIG @ 0x0B6F18D0
```

The old numeric CmdId is historical evidence only.

Current 7.1 candidate reduction:

```text
40 one-field int32-field-6 shapes
        |
        | protected handler-parameter recovery
        v
36641 / 20290 / 2666
        |
        | historical handler-class controls
        v
36641 / 20290
```

Surviving current identities:

```text
candidate A
  CmdId        36641
  type         NCBEHBOCBJJ
  typeDef      70557
  registry idx 4878
  type slot    0x57F9080
  GetCmdId     0x13BEF180
  handler      KLLNGCPBLMM.GDILHLIGMPI @ 0xF045790
  method idx   615758

candidate B
  CmdId        20290
  type         MAFFAFNMEBM
  typeDef      76295
  registry idx 2466
  type slot    0x57F63D0
  GetCmdId     0x114767D0
  handler      KLLNGCPBLMM.OAEILOAJOML @ 0xF0462A0
  method idx   615762
```

Both parse the expected `int32 retcode = 6` shape. Both are consumed by the same generic 112-byte scene ACK-handler template. Neither currently has a unique static semantic binding to `UnlockTransPointRsp`.

Do not describe `36641` as preferred. The earlier local-neighborhood preference was invalidated by later controls.

Runtime controls on the corrected live notification path produced the same successful physical activation, immediate map usability, and teleport behavior with candidate `36641`, candidate `20290`, and with no `UnlockTransPointRsp` sent at all. Visible private-server behavior therefore provides no promotion evidence and the response identity is not required by the current gameplay implementation.

## Current lifecycle controls

```text
ScenePointUnlockNotify
  CmdId        25567
  type         DBNMIKBJIPE
  handler      KLLNGCPBLMM.IPADDHFIGMF @ 0xF05F0F0
  method idx   615937

GetSceneAreaRsp
  CmdId        23366
  type         DKJCMHENKAI
  handler      KLLNGCPBLMM.GCDHLNLACDK @ 0xF046780
```

The large distance from the candidate ACKs to the confirmed current `ScenePointUnlockNotify` handler is one of the controls proving that the compact 7.0 lifecycle neighborhood did not survive owner-method reordering.

`ScenePointUnlockNotify` is a confirmed official client message, not an AstaPS workaround. The exact current 7.1 field semantics recovered from the client are:

```text
field 2   scene_id
field 4   locked_point_list
field 6   hide_point_list
field 8   unhide_point_list
field 15  point_list
```

A normal unlock should send `scene_id + point_list`. The old AstaPS path also populated generated field 4, whose stale generated name suggested unhide but whose official current meaning is `locked_point_list`; that contradictory unlock+lock update was the cause of the live gray/unusable map waypoint behavior.

## Static boundary

The following paths have already been tested and must not be reused as promotion evidence without a changed premise:

- ACK body/native equality: unrelated responses share the same tiny retcode template;
- local current owner distance and 7.0 -> 7.1 owner-order interpolation: method order is heavily rearranged and mixes protocol families;
- `0x4B2Axx` slot proximity: these are per-method ILFix/hotfix storage, advancing by exactly eight bytes with method index;
- direct handler pointers and decoded signature consumers: each candidate exposes only its own scene handler, matching known controls;
- generic submit fan-out: `EDKMMIPJHJA.DMLCLHCBOBJ @ 0x7246860` has about 491 callers;
- hidden submit `MethodInfo` / rgctx: the native calling convention does not carry a response type at the unlock submit edge;
- registry or TypeDefinition order interpolation: unstable against controls;
- semantic message-name strings: absent from the exact current EXE and metadata in ASCII/UTF-16;
- standard generated protobuf descriptor Base64: absent even for confirmed `ScenePointUnlockNotify` and `GetSceneAreaRsp` controls;
- same-version public server forks: useful controls, but the unlock pair remains unresolved there too;
- forcing either candidate on a private server and judging visible success: both handlers accept the same empty-success shape and simply return.

Detailed chronology and the 🕳️ list are in `RESEARCH_LOG.md`. The compact static boundary is in `STATIC_BOUNDARY_2026-10-02.md`.

## Maintained runtime capture path

The current-client framing/XOR boundaries were recovered from the pinned 7.1 executable itself. They are not copied from an older version.

```text
S2C post-XOR plaintext boundary   RVA 0xA01846A
C2S pre-XOR plaintext boundary    RVA 0xA01A0EF
```

Recovery evidence is preserved in `RUNTIME_CAPTURE_RECOVERY_2026-10-02.md`.

The Frida collector is:

```text
tools/runtime/capture_game_packets_71.js
tools/runtime/capture_game_packets_71.py
```

It validates the `0x4567 ... 0x89AB` game-packet framing, records surrounding packet headers, and preserves full frames for:

```text
9369   confirmed UnlockTransPointReq
36641  candidate A
20290  candidate B
25567  confirmed ScenePointUnlockNotify
```

Typical capture command:

```bash
python -m pip install frida
python tools/runtime/capture_game_packets_71.py \
  --output work/unlock-trans-point-71.ndjson
```

Use a genuine known-correct current-7.1 unlock flow. A private server that has been manually forced to send one candidate cannot establish semantic identity.

The capture path is retained for future use, but active response-identity research is paused. Resume only if a gameplay dependency appears, a genuine official-current capture becomes available incidentally, or new static evidence creates a unique semantic binding.

## Automatic transaction correlation

After capture, run:

```bash
python tools/runtime/analyze_unlock_trans_point_capture_71.py \
  work/unlock-trans-point-71.ndjson \
  --json work/unlock-trans-point-71-analysis.json
```

The analyzer:

1. verifies that the capture's ready event uses the maintained current-client S2C/C2S hook RVAs;
2. finds each `C2S 9369` request;
3. decodes PacketHead protobuf field 3 (`client_sequence_id`, independently retained by same-version 7.1 protocol controls);
4. inspects the narrow following S2C window for `36641`, `20290`, and `25567`;
5. marks a transaction `promotable` only when exactly one response candidate shares the request `client_sequence_id`.

If both candidates appear, no candidate matches the sequence, or PacketHead field 3 is unavailable, preserve the full capture and review the surrounding traffic rather than promoting a mapping from proximity alone.

## Promotion rule

A response mapping can be promoted when a known-correct 7.1 transaction establishes:

```text
C2S  9369   UnlockTransPointReq     seq = N
S2C  X      candidate response      seq = N
```

with exactly one of:

```text
X = 36641
X = 20290
```

`ScenePointUnlockNotify / 25567` may appear in the same lifecycle, but it does not replace the request/response sequence correlation.

Until that observation or another independent semantic binding exists, keep both candidates unresolved and do not assign `PacketOpcodes.UnlockTransPointRsp` in AstaPS.

## AstaPS integration rule

Current validated gameplay path:

```text
receive UnlockTransPointReq(sceneId, pointId)
    -> if newly unlocked:
         update player state
         grant reward / trigger unlock events
         send ScenePointUnlockNotify(sceneId, pointId)
         persist
```

Do not proactively send a full `GetScenePointRsp` after each unlock; that was a refresh workaround and is no longer required after correcting the live notification fields. Keep normal request-driven `GetScenePointReq/GetScenePointRsp` support for full scene-point state synchronization.

Do not send either unconfirmed `UnlockTransPointRsp` candidate merely to complete the apparent Req/Rsp pair. Runtime controls show no observed gameplay dependency on that response in the tested ordinary waypoint flow.

## Primary references

```text
WORK_PROGRESS_2026-10-03.md
RESEARCH_LOG.md
STATIC_BOUNDARY_2026-10-02.md
RUNTIME_PROBE.md
RUNTIME_CAPTURE_RECOVERY_2026-10-02.md
docs/case-studies/unlock-trans-point-7.1.md
```

The target sample identity is recorded in `../../hashes.json`.
