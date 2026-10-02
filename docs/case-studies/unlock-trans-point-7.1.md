# Genshin 7.1 unlock-trans-point case study

This case study preserves the current static-recovery state for the teleport-point unlock flow used by AstaPS. The response CmdId is intentionally unresolved until a current-client semantic binding closes the final two-way split.

## Current status

| Message | 7.1 CmdId | Status | Structure / note |
| --- | ---: | --- | --- |
| `UnlockTransPointReq` | 9369 | confirmed | two `uint32` fields; scene id / point id |
| `ScenePointUnlockNotify` | 25567 | confirmed | current parser reads fields 2, 4, 6, 8, 15 |
| `GetSceneAreaRsp` | 23366 | confirmed control | nearby current scene-handler control |
| `UnlockTransPointRsp` | `36641` or `20290` | unresolved | both parse the expected single `int32` field 6 shape |

The response search began with 40 current-7.1 protocol types matching a one-field `int32 field 6` response. Protected method-parameter recovery reduced the set to `36641`, `20290`, and `2666`; native comparison against the known 7.0 response handler removed `2666`.

`36641` remains the preferred candidate because of its local method neighborhood around the confirmed unlock sender. It is not confirmed. A previous piece of apparent support based on `0x4B2Axx` “delegate-slot proximity” has been withdrawn after those offsets were proved to be ordinary per-method ILFix/hotfix storage.

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
    | known 7.0 handler native comparison
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

20290
  type                    MAFFAFNMEBM
  typeDefinition          76295
  registry index          2466
  type slot RVA           0x57F63D0
  GetCmdId RVA            0x114767D0
  handler                 KLLNGCPBLMM.OAEILOAJOML @ 0xF0462A0
```

Both numeric/type identities are already closed by the canonical 4,896-row registry. The open question is semantic naming: which one is `UnlockTransPointRsp`.

Both candidate handlers are 112-byte generic scene ACK handlers. They read retcode, route non-zero values to common error handling, and return immediately on success. Multiple unrelated ACK handlers compile to the same template, so machine-code identity is not a semantic discriminator.

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

Independent handler controls resolved exactly, so this decoder is useful beyond the teleport-point case.

## Current-client RPC lifecycle anchors

The 7.1 unlock sender is:

```text
KLLNGCPBLMM.OIFANGMCKNJ @ 0x0F0452B0
    call @ 0x0F04541B
        -> EDKMMIPJHJA.DMLCLHCBOBJ @ 0x07246860
```

At the call site the freshly constructed request object is passed as `rdx`, with `r8 = 0`. No obvious response type or callback pointer is carried by the submit call. The generic submitter has 491 direct callers, so expanding its ordinary caller graph does not provide a request/response identity edge.

## Cross-version sender evidence

A 7.0 scene-controller method is a strong native match for the 7.1 unlock sender:

```text
7.1  KLLNGCPBLMM.OIFANGMCKNJ @ 0x0F0452B0
7.0  KGCKOFPFBLA.ECEGLMADOOM @ 0x0B6EA6B0

size                     0x390 / 912 bytes in both builds
mnemonic similarity      97.27%
token similarity         81.39%
```

This strongly identifies the sender. It does not locate the response by fixed method distance because scene-owner layout drifts and the ACK template is duplicated.

## Local scene-method evidence

Relevant current 7.1 owner band:

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

A native-neighborhood comparison scores `36641 = 0.4076` and `20290 = 0.3223`. This is supporting evidence only because duplicate ACK templates make historical alignment non-bijective.

## Correction: `0x4B2Axx` is not protocol registration

The local methods also contain accesses such as:

```text
OIFANGMCKNJ    method_index 615754 -> 0x4B2A70
CHOHMONDPNJ    method_index 615755 -> 0x4B2A78
HBLEMPNBAAO    method_index 615756 -> 0x4B2A80
CJJIJIHCAHM    method_index 615757 -> 0x4B2A88
GDILHLIGMPI    method_index 615758 -> 0x4B2A90
GJHPOFKNMEB    method_index 615759 -> 0x4B2A98
OEHHCMEMGNA    method_index 615760 -> 0x4B2AA0
HMICLHMGNCB    method_index 615761 -> 0x4B2AA8
OAEILOAJOML    method_index 615762 -> 0x4B2AB0
LHDHFIHDFNM    method_index 615763 -> 0x4B2AB8
GCDHLNLACDK    method_index 615764 -> 0x4B2AC0
```

The exact +8 progression through ordinary helper methods proves these are per-method ILFix/hotfix implementation slots reached through `[root + 0x24F40]`. They are not protocol delegate slots or CmdId registration entries.

Therefore:

- `0x4B2A90` being nearer to the sender than `0x4B2AB0` has no independent evidentiary value;
- read-only xrefs to these slots do not reveal protocol registration;
- the real protocol type slots are the canonical registry values such as `0x57F9080` and `0x57F63D0`.

This correction removes the prior “delegate-slot proximity” argument for `36641`.

## Heuristics deliberately excluded from confirmation

- global registry-order interpolation: unstable across versions;
- TypeDefinition-order interpolation: unstable against known controls;
- fixed 7.0 -> 7.1 scene-owner method distance: invalid under layout drift;
- duplicated 112-byte ACK native identity: classifies shape, not semantics;
- `0x4B2Axx` hotfix-slot distance: simply restates method order.

## Rejected recovery paths / 🕳️

- request/response shared-owner inference from external type-slot xrefs: fails on known control pairs;
- direct contiguous native CmdId/flag-array assumption: layout not present;
- protected metadata-usage shortcut: no unique response semantic anchor;
- direct handler function-pointer xrefs: no useful semantic edge;
- generic RPC-submit caller expansion: 491 callers and no response argument at the unlock site;
- scanning `0x4B2Axx` for protocol-registration writes: wrong abstraction, those are hotfix method slots;
- treating the scene static constructor as a simple handler-registration list: does not expose the pair;
- payload-only runtime capture: success response can be zero-length.

The detailed chronological record and recovered Actions artifacts are preserved in `versions/7.1.0-global/windows-x64/analyses/unlock-trans-point/RESEARCH_LOG.md`.

## External-project cross-checks

Grasscutter-style servers support the expected lifecycle: receive the unlock request, update/persist point state, send `ScenePointUnlockNotify` for the newly unlocked point, then send `UnlockTransPointRsp`.

A same-version public fork, `capyb2222/LunaGC_7.1.0`, independently agrees on current controls including `ScenePointUnlockNotify = 25567` and `GetSceneAreaRsp = 23366`. It has the expected `UnlockTransPointRsp { int32 retcode = 6; }` schema, but its opcode table still uses unresolved placeholders:

```text
UnlockTransPointReq = -119
UnlockTransPointRsp = -120
```

`invoker-bot/LunaGC` carries the same unresolved pair. Thus public 7.1 forks currently provide semantic/schema controls, not an independent answer for `36641` versus `20290`.

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

The current gameplay refresh/fallback behavior in AstaPS should remain until runtime evidence proves it redundant.

## Next decisive step

The next work should introduce a new semantic evidence class rather than another ranking heuristic:

1. map richer neighboring current scene messages such as the `BFGEIFDEOKH` parameter around the `20290` handler; use independently named schemas/controls to determine whether that local cluster belongs to another RPC family;
2. search protobuf reflection/descriptor or semantic registration data for a direct obfuscated-type -> message-name edge;
3. use the canonical registry type slots and business consumers, not the `0x4B2Axx` hotfix slots;
4. if static recovery remains ambiguous, observe the raw response CmdId/header in a minimal runtime probe.

Until one of these closes the pair, record `36641` as preferred and `20290` as the surviving alternate, with neither marked confirmed.