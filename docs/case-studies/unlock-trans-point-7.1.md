# Genshin 7.1 unlock-trans-point case study

This case study preserves the current recovery state for the teleport-point unlock flow used by AstaPS. The response CmdId remains unresolved until a current-7.1 semantic observation closes the final two-way split.

## Current status

| Message | 7.1 CmdId | Status | Structure / note |
| --- | ---: | --- | --- |
| `UnlockTransPointReq` | 9369 | confirmed | two `uint32` fields; scene id / point id |
| `ScenePointUnlockNotify` | 25567 | confirmed | current parser reads fields 2, 4, 6, 8, 15 |
| `GetSceneAreaRsp` | 23366 | confirmed control | current scene-handler control |
| `UnlockTransPointRsp` | `36641` or `20290` | unresolved static tie | both parse the expected single `int32` field 6 shape |

The response search began with 40 current-7.1 protocol types matching a one-field `int32 field 6` response. Protected method-parameter recovery reduced the set to `36641`, `20290`, and `2666`; native comparison against the known 7.0 response handler removed `2666`.

Earlier work tentatively preferred `36641` because it sits closer to the confirmed unlock sender. Continued validation removed the independent value of that preference: scene-owner ordering is heavily rearranged across 7.0 -> 7.1, nearby current handlers mix protocol families, and the apparent `0x4B2Axx` delegate slots are per-method ILFix/hotfix storage. Treat `36641` and `20290` as a semantic tie until a new evidence class identifies one of them.

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

## ScenePointUnlockNotify

Current 7.1 identity:

```text
CmdId                 25567
client type            DBNMIKBJIPE
typeDefinition         66061
GetCmdId               0x1252BA60
```

The parser accepts fields 2, 4, 6, 8 and 15. AstaPS currently maps field 2 to `scene_id`, field 4 to `unhide_point_list`, field 6 to `hide_point_list`, field 15 to `point_list`; field 8 remains semantically unresolved.

A useful cross-version control also closes cleanly:

```text
7.0 PANBIAIAIDH / ScenePointUnlockNotify / CmdId 7929
    -> strong native handler match
7.1 DBNMIKBJIPE / ScenePointUnlockNotify / CmdId 25567
```

This demonstrates that distinctive large handlers can transfer semantic identity across versions. It does not make neighboring method positions stable.

## UnlockTransPointRsp search

Historical 7.0 control:

```text
CmdId                 1776
client type            CPKAHGFBBIH
wire shape             int32 retcode = 6
known handler RVA      0x0B6F18D0
```

The 7.0 CmdId is historical evidence only.

Expected 7.1 semantic shape:

```proto
message UnlockTransPointRsp {
    int32 retcode = 6;
}
```

A successful `retcode = 0` response normally has an empty protobuf body. Runtime validation therefore needs the packet header/CmdId; payload-only capture cannot distinguish the remaining candidates.

### Candidate reduction

```text
40 parser-shape candidates
    |
    | protected parameter-type recovery
    v
36641 / 20290 / 2666
    |
    | known 7.0 handler structural comparison
    v
36641 / 20290
```

Current canonical identities:

```text
36641
  type                    NCBEHBOCBJJ
  typeDefinition          70557
  registry index          4878
  type slot RVA           0x57F9080
  GetCmdId RVA            0x13BEF180
  handler                 KLLNGCPBLMM.GDILHLIGMPI @ 0xF045790
  method index            615758

20290
  type                    MAFFAFNMEBM
  typeDefinition          76295
  registry index          2466
  type slot RVA           0x57F63D0
  GetCmdId RVA            0x114767D0
  handler                 KLLNGCPBLMM.OAEILOAJOML @ 0xF0462A0
  method index            615762
```

Both numeric/type identities are already closed by the canonical 4,896-row registry. The open layer is semantic naming only.

## Why ACK native code cannot decide the pair

Both candidate handlers are 112-byte generic ACK handlers. Their normal path is effectively:

```text
response == null -> common null/error path
retcode != 0     -> common error handling
retcode == 0     -> ret
```

The indirect branch at the beginning of each handler belongs to ILFix/hotfix method replacement. It dereferences `[root + 0x24F40]` and the per-method `0x4B2Axx` slot only when the hotfix flag is active. It is not a success callback or request/response binding.

Historical controls show how broad this template family is. The same small ACK shape occurs for unrelated 7.0 messages including:

```text
UnlockTransPointRsp   = 1776
PersonalSceneJumpRsp  = 1717
PlayerQuitDungeonRsp  = 20709
DungeonDieOptionRsp   = 9878
```

Machine-code equality therefore classifies ACK shape and cannot transfer semantic identity.

## Protected 7.1 parameter metadata recovery

This investigation recovered a reusable decoder for protected method-parameter type records.

Method parameter range skeleton:

```text
count = ((method[0x18] + 0xE1) & 0xff) ^ key8
start = (method[0x04] + 0xF0A05526) ^ key32
parameter_index = start + ordinal
```

Parameter records use an 8-byte stride. The type-index decode is:

```text
value   = (index * 0xA291 + 0x48B5FFB1) & MASK64
value  ^= 0x19E1D47A
product = (value * 0x56E732D7) & MASK64
key     = ((product >> 0x15) + 0x7B48E804) & MASK32

type_index = record.word0 ^ key ^ 0x31BF59F3
```

Independent handler controls resolved exactly, so this decoder remains useful beyond the teleport-point case.

## Current-client RPC lifecycle anchors

The 7.1 unlock sender is:

```text
KLLNGCPBLMM.OIFANGMCKNJ @ 0x0F0452B0
```

The submit call is:

```text
0xF045405  mov rcx, [rax + 0xA110]
0xF045415  mov rdx, rdi        ; freshly built DMMJNICDOHM request
0xF045418  xor r8d, r8d        ; second explicit argument = 0
0xF04541B  call 0x07246860     ; EDKMMIPJHJA.DMLCLHCBOBJ
```

Metadata reports `DMLCLHCBOBJ` with parameter count 2. The call site exposes no trustworthy response type, callback or generic response `MethodInfo`. The generic submitter has 491 direct callers, so expanding its ordinary caller graph does not provide a semantic request/response edge.

## Full decoded-signature reference check

A targeted scan of the current checked-in `metadata/methods.csv` was preserved by Actions run `37004973598`, artifact `unlock-rsp-external-refs-71` (`11224837704`).

Results:

```text
NCBEHBOCBJJ / 36641
  total decoded signature references     2
  self reference                         CopyFrom
  external references                    1
  only external target                   KLLNGCPBLMM.GDILHLIGMPI @ 0xF045790

MAFFAFNMEBM / 20290
  total decoded signature references     2
  self reference                         CopyFrom
  external references                    1
  only external target                   KLLNGCPBLMM.OAEILOAJOML @ 0xF0462A0
```

Controls behave the same way: `ScenePointUnlockNotify / 25567` and `GetSceneAreaRsp / 23366` each expose their protocol class self-reference plus exactly one scene handler. The two response candidates therefore have no second decoded consumer, return-type use, factory or callback that can currently supply semantic identity.

## Cross-version sender evidence

A 7.0 scene-controller method is a strong native match for the 7.1 unlock sender:

```text
7.1  KLLNGCPBLMM.OIFANGMCKNJ @ 0x0F0452B0
7.0  KGCKOFPFBLA.ECEGLMADOOM @ 0x0B6EA6B0

size                     0x390 / 912 bytes in both builds
mnemonic similarity      97.27%
token similarity         81.39%
```

This strongly identifies the request sender. It does not locate the response by method position.

A monotonic owner-order hypothesis was explicitly tested and rejected. Distinctive methods from one small historical scene-controller window map to widely separated current owner positions. The controller has been substantially reordered between 7.0 and 7.1.

## Current scene-method neighborhood

Relevant 7.1 owner band:

```text
0xF0452B0  OIFANGMCKNJ      UnlockTransPointReq sender
0xF045640  CHOHMONDPNJ      helper
0xF045710  HBLEMPNBAAO      helper
0xF045720  CJJIJIHCAHM      CmdId 26552 ACK handler
0xF045790  GDILHLIGMPI      CmdId 36641 ACK handler
0xF045800  GJHPOFKNMEB      helper/other
...
0xF0460C0  HMICLHMGNCB      BFGEIFDEOKH handler
0xF0462A0  OAEILOAJOML      CmdId 20290 ACK handler
0xF046310  LHDHFIHDFNM      helper/other
0xF046780  GCDHLNLACDK      GetSceneAreaRsp / 23366 handler
```

Earlier neighborhood scoring was `36641 = 0.4076`, `20290 = 0.3223`. Continued validation showed that this ranking is not an independent semantic signal. Nearby current methods can quickly cross protocol domains; for example the same owner soon reaches a message independently named `DungeonEntryInfoRsp / 9782`. Local adjacency is therefore retained as descriptive layout evidence only.

## Correction: `0x4B2Axx` is hotfix method storage

The local methods contain an exact +8 slot progression with method index:

```text
615754 OIFANGMCKNJ     -> 0x4B2A70
615755 CHOHMONDPNJ     -> 0x4B2A78
615756 HBLEMPNBAAO     -> 0x4B2A80
615757 CJJIJIHCAHM     -> 0x4B2A88
615758 GDILHLIGMPI     -> 0x4B2A90
615759 GJHPOFKNMEB     -> 0x4B2A98
615760 OEHHCMEMGNA     -> 0x4B2AA0
615761 HMICLHMGNCB     -> 0x4B2AA8
615762 OAEILOAJOML     -> 0x4B2AB0
615763 LHDHFIHDFNM     -> 0x4B2AB8
615764 GCDHLNLACDK     -> 0x4B2AC0
```

These are per-method ILFix/hotfix implementation slots, including ordinary helper methods. Slot distance simply restates method order and contributes no protocol identity evidence. The real protocol type slots are canonical registry values such as `0x57F9080` and `0x57F63D0`.

## Rejected recovery paths / 🕳️

- request/response shared-owner inference from external type-slot xrefs: fails on known control pairs;
- direct contiguous native CmdId/flag-array assumptions: expected simple layout is not present;
- protected metadata-usage shortcuts: no unique response semantic anchor;
- direct handler function-pointer xrefs: no useful semantic edge;
- generic RPC-submit caller expansion: 491 callers and no response argument at the unlock site;
- scanning `0x4B2Axx` for protocol-registration writes: wrong abstraction, those are hotfix method slots;
- treating the scene static constructor as a simple handler-registration list: does not expose the pair;
- ACK native identity: identical templates serve unrelated response semantics;
- fixed or monotonic 7.0 -> 7.1 scene-owner order: invalid under substantial method reordering;
- local handler adjacency as RPC-family evidence: current owner mixes protocol domains;
- ILFix indirect branch as business callback: hotfix trampoline only, while normal success returns directly;
- forcing either candidate from a private server and judging visible client behavior: both success handlers accept the same shape and return;
- payload-only runtime capture: a successful response can have a zero-length protobuf body.

The detailed chronological record lives in `versions/7.1.0-global/windows-x64/analyses/unlock-trans-point/RESEARCH_LOG.md`. The continuation boundary is recorded in `STATIC_BOUNDARY_2026-10-02.md`.

## External-project cross-checks

Grasscutter-style servers support the expected lifecycle: receive the unlock request, update/persist point state, send `ScenePointUnlockNotify` for a newly unlocked point, then send `UnlockTransPointRsp`.

A same-version public fork, `capyb2222/LunaGC_7.1.0`, independently agrees on current controls including `ScenePointUnlockNotify = 25567` and `GetSceneAreaRsp = 23366`. It has the expected `UnlockTransPointRsp { int32 retcode = 6; }` schema, but its opcode table leaves the unlock request/response pair unresolved. Current public 7.1 forks therefore provide schema and control evidence, not an independent answer for `36641` versus `20290`.

## AstaPS integration state

Do not assign `PacketOpcodes.UnlockTransPointRsp` yet. The response identity remains a two-way semantic-recovery problem.

Once confirmed, the intended lifecycle is:

```text
receive UnlockTransPointReq(sceneId, pointId)
    -> if newly unlocked:
         update player state
         persist
         send ScenePointUnlockNotify(sceneId, pointId)
    -> send UnlockTransPointRsp(retcode = 0)
```

Current gameplay refresh/fallback behavior in AstaPS should remain until runtime evidence proves it redundant.

## Next decisive step: decrypted packet header observation

Static analysis has reached an information boundary for the two candidate ACK classes. The next maintained evidence step is documented in:

```text
versions/7.1.0-global/windows-x64/analyses/unlock-trans-point/RUNTIME_PROBE.md
```

`tools/parse_decrypted_game_packet.py` parses one or more already-XOR-decrypted game packet frames. The verified framing exposes CmdId as a big-endian `uint16` at offset `+0x02`, between head magic `0x4567` and the packet-head/body lengths.

The decisive experiment is a genuine known-correct 7.1 unlock transaction:

```text
C2S  9369   UnlockTransPointReq
S2C  36641  ?
```

or:

```text
C2S  9369   UnlockTransPointReq
S2C  20290  ?
```

Preserve direction and surrounding traffic. If exactly one candidate appears in the real unlock transaction, the mapping can be promoted. If both appear, recover packet-head sequence correlation before promotion.

Until that observation or another independent semantic binding is available, record `36641` and `20290` as an unresolved static tie and confirm neither.
