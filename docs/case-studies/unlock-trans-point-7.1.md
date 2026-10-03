# Genshin 7.1 unlock-trans-point case study

This case study records the current Genshin 7.1 teleport-point unlock result used by AstaPS. The ordinary waypoint gameplay path is closed and validated. Exact `UnlockTransPointRsp` semantic identity remains unresolved between two current-client types, and active response research is paused because the tested gameplay path does not depend on that ACK.

The detailed chronology and raw case evidence live under:

```text
versions/7.1.0-global/windows-x64/analyses/unlock-trans-point/
```

The current handoff checkpoint is `WORK_PROGRESS_2026-10-03.md`.

## Current status

| Message | 7.1 CmdId | Status | Current role |
| --- | ---: | --- | --- |
| `UnlockTransPointReq` | 9369 | CONFIRMED | C2S waypoint activation request |
| `ScenePointUnlockNotify` | 25567 | CONFIRMED | S2C live point-state update |
| `GetScenePointReq` | 1649 | confirmed integration control | C2S full scene-point state request |
| `GetScenePointRsp` | 26 | confirmed integration control | S2C full scene-point state response |
| `SceneTransToPointReq` | 1252 | confirmed integration control | C2S use of an unlocked waypoint |
| `SceneTransToPointRsp` | 23515 | confirmed integration control | S2C teleport request response |
| `UnlockTransPointRsp` | `36641` or `20290` | UNRESOLVED / PAUSED | no observed dependency in tested ordinary waypoint flow |

## Validated ordinary waypoint lifecycle

The smallest current-client path validated in AstaPS is:

```text
C -> S  UnlockTransPointReq        CmdId 9369
        scene_id = field 12
        point_id = field 1

S       update unlocked point state
        grant configured unlock reward
        trigger quest/script unlock events
        persist player

S -> C  ScenePointUnlockNotify     CmdId 25567
        scene_id = field 2
        point_list = field 15
```

The server does not need to proactively send a full `GetScenePointRsp` after each ordinary unlock. Full scene-point synchronization remains available through the normal request-driven `GetScenePointReq/GetScenePointRsp` path.

The server also does not send either unresolved `UnlockTransPointRsp` candidate in the maintained gameplay path.

## UnlockTransPointReq

Current 7.1 static identity:

```text
CmdId                 9369 / 0x2499
client type            DMMJNICDOHM
typeDefinition         84249
type slot RVA          0x057E6498
metadata usage         37523
registry store RVA     0x07F852AB
field start / count    417613 / 2
GetCmdId               DMMJNICDOHM.AEGNNPENLNM @ 0x0C87EA60
parser-like method     DMMJNICDOHM.IENGFLPCLNM @ 0x0C87E6A0
constructor            DMMJNICDOHM..ctor @ 0x0C87E8F0
```

Recovered wire shape:

```proto
// CmdId: 9369
message DMMJNICDOHM {
    uint32 NEAFKBADNDA = 12; // scene_id
    uint32 GKPKNPFEPBF = 1;  // point_id
}
```

The registry/type identity is exact-sample current-7.1 evidence. The semantic field interpretation agrees with the live server/client transaction used by AstaPS.

## ScenePointUnlockNotify

Current 7.1 identity:

```text
CmdId                 25567
client type            DBNMIKBJIPE
typeDefinition         66061
GetCmdId               0x1252BA60
```

The current official client closes the field semantics as:

```text
field 2   scene_id
field 4   locked_point_list
field 6   hide_point_list
field 8   unhide_point_list
field 15  point_list
```

A normal waypoint unlock sends `scene_id + point_list`.

The earlier AstaPS implementation also populated generated field 4 with the newly unlocked point because the generated field name suggested an unhide list. On the exact 7.1 client field 4 is `locked_point_list`, so that packet simultaneously announced the point as unlocked and locked. The result matched the observed bug: the physical waypoint activated and rewards were granted while the map waypoint remained gray/unusable.

Removing that contradictory field and sending only `scene_id + point_list` fixed immediate map usability and teleport behavior without an unlock-time full-state refresh.

A useful cross-version control remains:

```text
7.0 PANBIAIAIDH / ScenePointUnlockNotify / CmdId 7929
    -> strong native handler match
7.1 DBNMIKBJIPE / ScenePointUnlockNotify / CmdId 25567
```

This supports semantic transfer for a distinctive large handler. It does not make neighboring scene-controller method positions stable across versions.

## UnlockTransPointRsp static tie

Historical 7.0 control:

```text
CmdId                 1776
client type            CPKAHGFBBIH
wire shape             int32 retcode = 6
known handler RVA      0x0B6F18D0
```

The old numeric CmdId is historical evidence only.

The current investigation started from 40 current-7.1 protocol types matching a one-field `int32 field 6` response. Protected method-parameter recovery reduced the set to `36641`, `20290`, and `2666`; native comparison against the known 7.0 response handler removed `2666`.

Current surviving identities:

```text
36641
  type                    NCBEHBOCBJJ
  typeDefinition          70557
  registry index          4878
  type slot RVA           0x57F9080
  GetCmdId RVA            0x13BEF180
  handler                 KLLNGCPBLMM.GDILHLIGMPI @ 0xF045790
  method index            615758
  wire shape              int32 field 6

20290
  type                    MAFFAFNMEBM
  typeDefinition          76295
  registry index          2466
  type slot RVA           0x57F63D0
  GetCmdId RVA            0x114767D0
  handler                 KLLNGCPBLMM.OAEILOAJOML @ 0xF0462A0
  method index            615762
  wire shape              int32 field 6
```

Both numeric/type identities are already closed by the canonical 4,896-row registry. The unresolved layer is the semantic assignment of `UnlockTransPointRsp`.

Do not describe `36641` as preferred. The earlier preference came mainly from local method proximity and was invalidated by later controls.

## Why the two ACK handlers do not distinguish semantics

Both candidate handlers are 112-byte generic scene ACK handlers. Their normal path is effectively:

```text
response == null -> common null/error path
retcode != 0     -> common error handling
retcode == 0     -> ret
```

The indirect branch at the beginning of each handler belongs to ILFix/hotfix method replacement. The `0x4B2Axx` values are per-method implementation slots, including ordinary helper methods. They are unrelated to protocol type identity and do not form a request/response binding.

Historical controls show the same compact ACK template on unrelated response semantics such as `PersonalSceneJumpRsp`, `PlayerQuitDungeonRsp`, and `DungeonDieOptionRsp`. Native-template equality therefore classifies handler shape only.

## Signature-reference boundary

A full scan of the current decoded `metadata/methods.csv` found the same relationship shape for both candidates:

```text
NCBEHBOCBJJ / 36641
  self reference          CopyFrom
  external reference      KLLNGCPBLMM.GDILHLIGMPI @ 0xF045790

MAFFAFNMEBM / 20290
  self reference          CopyFrom
  external reference      KLLNGCPBLMM.OAEILOAJOML @ 0xF0462A0
```

No second decoded consumer, return-type use, response factory, or callback distinguishes the pair. The reusable `query_method_references` layer and `protocol-query` now expose this kind of evidence without a packet-specific workflow.

## Request sender and RPC submit boundary

The current 7.1 unlock sender is:

```text
KLLNGCPBLMM.OIFANGMCKNJ @ 0x0F0452B0
```

Its submit edge is:

```text
0xF045405  mov rcx, [rax + 0xA110]
0xF045415  mov rdx, rdi        ; DMMJNICDOHM request
0xF045418  xor r8d, r8d        ; second explicit argument = 0
0xF04541B  call 0x07246860     ; EDKMMIPJHJA.DMLCLHCBOBJ
```

Metadata reports two parameters for `DMLCLHCBOBJ`. The call site exposes no trustworthy response type or callback argument. Expanding the generic submitter caller graph also fails as a semantic discriminator because the method is broadly shared.

A strong native match independently connects the current request sender to the historical 7.0 unlock sender:

```text
7.1  KLLNGCPBLMM.OIFANGMCKNJ @ 0x0F0452B0
7.0  KGCKOFPFBLA.ECEGLMADOOM @ 0x0B6EA6B0

native body size         0x390 / 912 bytes in both builds
mnemonic similarity      97.27%
token similarity         81.39%
```

That result confirms the request-side method identity. It does not transfer response position because scene-controller owner order changed substantially between 7.0 and 7.1.

## Runtime ACK/no-ACK control

All controls below used the corrected `ScenePointUnlockNotify` and omitted the old proactive `GetScenePointRsp` refresh:

```text
send candidate 36641  -> physical activation OK
                       -> map icon immediately usable OK
                       -> teleport from map OK

send candidate 20290  -> physical activation OK
                       -> map icon immediately usable OK
                       -> teleport from map OK

send no response ACK  -> physical activation OK
                       -> map icon immediately usable OK
                       -> teleport from map OK
```

The no-response control occurred when the server completed state mutation and sent the corrected notification, then failed while constructing an invalid response probe. Since the visible unlock/map/teleport behavior still completed, the tested ordinary waypoint path has no observed dependency on `UnlockTransPointRsp`.

This control cannot identify the semantic CmdId. It establishes that AstaPS does not need to guess one for the current gameplay path.

## Related scene-point lifecycle

Full state synchronization:

```text
C -> S  GetScenePointReq        CmdId 1649
S -> C  GetScenePointRsp        CmdId 26
```

Using an unlocked waypoint:

```text
C -> S  SceneTransToPointReq    CmdId 1252
        scene_id = field 4
        point_id = field 10

S -> C  SceneTransToPointRsp    CmdId 23515
        scene_id = field 7
        retcode = field 12
        point_id = field 15
```

A scene-changing teleport then enters the ordinary scene-entry lifecycle (`PlayerEnterSceneNotify`, EnterSceneReady, SceneInitFinish, EnterSceneDone, PostEnterScene, plus client-requested state refreshes).

`GadgetInteractReq/GadgetInteractRsp` remains a generic gadget-interaction path and is not currently required by the validated ordinary waypoint-unlock chain. Statue/worktop/talk behavior should be treated as separate investigations when needed.

## Rejected recovery paths

The following paths were tested and should not be reused as positive evidence without a changed premise:

- request/response shared-owner inference from external type-slot xrefs;
- direct contiguous native CmdId/flag-array assumptions;
- protected metadata-usage shortcuts without a unique semantic anchor;
- direct handler function-pointer xrefs without a semantic edge;
- generic RPC-submit caller expansion;
- scanning `0x4B2Axx` as protocol-registration storage;
- treating the scene static constructor as a simple response-registration list;
- ACK native identity/template equality;
- fixed or monotonic 7.0 -> 7.1 scene-owner order;
- local handler adjacency as RPC-family evidence;
- ILFix indirect branches as gameplay callbacks;
- forcing a candidate on a private server and judging visible client behavior;
- payload-only runtime capture for a success ACK whose protobuf body may be empty.

The chronological record in `RESEARCH_LOG.md` and `STATIC_BOUNDARY_2026-10-02.md` preserves the discarded hypotheses and their evidence.

## Maintained promotion gate if research resumes

Response-identity research is paused. Resume it only when one of these changes the premise:

1. a gameplay feature actually requires the response;
2. a genuine known-correct current-7.1 capture becomes available incidentally;
3. new static evidence creates a unique semantic binding.

For a runtime capture, the maintained decisive relation is:

```text
C2S  9369  sequence=N
S2C  X     sequence=N
```

where exactly one of:

```text
X = 36641
X = 20290
```

matches the request transaction. The generic correlator is available as:

```bash
python -m genshinre.capture capture.ndjson \
  --request-cmd 9369 \
  --candidate-cmd 36641 \
  --candidate-cmd 20290 \
  --sequence-field 3 \
  --json capture.analysis.json
```

A single unrelated occurrence in a timing window is insufficient. Preserve direction, packet-head sequence data, the complete bounded event window, exact client identity, and the decrypted frame evidence.

Until that evidence exists, keep the semantic tie unresolved and leave `PacketOpcodes.UnlockTransPointRsp` unassigned in AstaPS.
