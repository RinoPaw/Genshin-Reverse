# Genshin 7.1 unlock-trans-point case study

This case study preserves the current static-recovery state for the teleport-point unlock flow used by AstaPS. The response CmdId is intentionally left unresolved until the final binding can be closed from current-client evidence.

## Current status

| Message | 7.1 CmdId | Status | Structure / note |
| --- | ---: | --- | --- |
| `UnlockTransPointReq` | 9369 | confirmed | two `uint32` fields; AstaPS maps scene id and point id |
| `ScenePointUnlockNotify` | 25567 | confirmed | current client parser reads fields 2, 4, 6, 8, 15 |
| `UnlockTransPointRsp` | `36641` or `20290` | unresolved | both remaining candidates parse the expected single `int32` field 6 response shape |

The response search started with 40 current-7.1 protocol types whose parser shape matched a one-field `int32 field 6` message. Recovering protected method-parameter metadata reduced the set to three real scene-handler candidates: `36641`, `20290`, and `2666`. Native comparison against the known 7.0 `UnlockTransPointRsp` handler then removed `2666`, leaving the current two-way split.

`36641` is presently the stronger candidate, but it is not promoted to confirmed. Independent neighborhood and local scene-handler/delegate evidence both lean toward it, while weaker ordering heuristics disagree and are therefore excluded from the final decision.

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
    uint32 NEAFKBADNDA = 12; // AstaPS: scene_id
    uint32 GKPKNPFEPBF = 1;  // AstaPS: point_id
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

The current client parser explicitly accepts:

```text
field 2   varint scalar
field 4   repeated uint32, unpacked or packed
field 6   repeated uint32, unpacked or packed
field 8   repeated uint32, unpacked or packed
field 15  repeated uint32, unpacked or packed
```

Equivalent protobuf shape:

```proto
message DBNMIKBJIPE {
    uint32 field_2 = 2;
    repeated uint32 field_4 = 4;
    repeated uint32 field_6 = 6;
    repeated uint32 field_8 = 8;
    repeated uint32 field_15 = 15;
}
```

AstaPS's generated 7.1 class already maps these wire fields as:

```text
field 2   scene_id
field 4   unhide_point_list
field 6   hide_point_list
field 8   HBKHEKLMEKN (semantic name still unknown)
field 15  point_list
```

The current unlock sender that writes `scene_id`, `unhide_point_list`, and `point_list` is wire-compatible with the 7.1 client parser. A separate `PacketScenePointUnlockNotify.lock()` implementation appears to write `hide_point_list` twice and not populate field 8; this should remain a deferred cleanup until field 8 semantics are independently recovered.

## UnlockTransPointRsp search

Historical 7.0 control:

```text
CmdId                 1776
client type            CPKAHGFBBIH
wire shape             int32 retcode = 6
known handler RVA      0x0B6F18D0
```

The 7.0 CmdId is historical evidence only and must not be copied into the 7.1 protocol table.

Expected semantic shape in 7.1:

```proto
message UnlockTransPointRsp {
    int32 retcode = 6;
}
```

A successful response with `retcode = 0` normally serializes to an empty protobuf body, so runtime capture alone does not expose the response type.

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

The 7.1 response handlers for `36641` and `20290` are both 112-byte scene-controller handlers with the same template-like behavior as the known 7.0 response handler: obtain the response object, read retcode, route non-zero retcodes to common error handling, return on success, and dispatch through a static delegate. Because this ack-handler pattern is compiler/template generated, machine-code identity by itself cannot distinguish the two remaining candidates.

Candidate `2666` has a different 80-byte special-handler structure and is rejected.

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

The decoder was validated against independent known handlers:

```text
parameter 243673 -> runtime type 248305 -> DoSetPlayerBornDataNotify
parameter 243763 -> runtime type 248269 -> PlayerNicknameNotify
parameter 243933 -> runtime type 248313 -> SetPlayerNameRsp
```

All three controls resolved exactly, making this decoder reusable beyond the teleport-point case.

## Current-client RPC lifecycle anchors

The 7.1 unlock owner / sender path currently includes:

```text
KLLNGCPBLMM.OIFANGMCKNJ @ 0x0F0452B0
    direct call @ 0x0F04541B
        -> EDKMMIPJHJA.DMLCLHCBOBJ @ 0x07246860
```

`EDKMMIPJHJA.DMLCLHCBOBJ` is also reached from the confirmed born request sender `EDKMMIPJHJA.NPKEIOHEPPD @ 0x0725CEF0`, which makes it a useful generic RPC-submit control. At the unlock call site, the submit arguments do not directly contain an obvious response-type or response-handler pointer; response dispatch appears to be resolved through the global protocol-handler registration layer.

## Cross-version sender evidence

A 7.0 scene-controller method was found as a very strong native match for the 7.1 unlock sender:

```text
7.1  KLLNGCPBLMM.OIFANGMCKNJ @ 0x0F0452B0
7.0  KGCKOFPFBLA.ECEGLMADOOM @ 0x0B6EA6B0

size                     0x390 / 912 bytes in both builds
mnemonic similarity      97.27%
token similarity         81.39%
```

The 7.0 method consumes a unique business-object type `CEDKGNBPJBL`, whose recovered public shape includes two `uint32` properties and one `int32` property. It has only one external consumer in the 7.0 dump, the matched scene-controller method above. This supports the cross-version sender identification but does not directly identify the response CmdId.

## Delegate-slot / local scene evidence

The known 7.0 response handler dispatches through static delegate slot `0x36E970`. In the corresponding 7.1 scene-handler region, the two remaining response candidates occupy nearby slots:

```text
0x4B2A90  -> candidate 36641
0x4B2AB0  -> candidate 20290
```

Both are genuine one-parameter scene protocol handlers in the same local dispatch region. A native-neighborhood comparison currently scores:

```text
36641   0.4076
20290   0.3223
```

This is independent supporting evidence for `36641`, not a confirmation criterion on its own.

## Heuristics deliberately excluded from confirmation

Several ordering-based models were evaluated and retained only as heuristics:

- global registry-order interpolation weakly favored `20290`, but the overall cross-version correlation was poor;
- TypeDefinition-order comparison weakly favored `36641`, but the known-control mapping was unstable;
- a direct 7.0 TypeDef-index to 7.1 TypeDef-index control produced correlation around `-0.405`, with only 18 of 55 known pairwise orders preserved.

Because the controls are unstable, these results must not be used to choose the final response CmdId.

## Rejected recovery paths

The following approaches were tested and rejected or downgraded:

- request/response shared-owner inference from external type-slot xrefs: failed even on the known `SetPlayerBornDataReq/Rsp` control pair;
- direct contiguous native CmdId/flag-array recovery: expected array layout was not present;
- protected metadata-usage table anchor recovery: no unique anchor in the current protected build;
- published metadata-usage slot fallback: insufficient stable mappings for the required request anchor;
- direct executable references to response-handler function pointers: zero useful code xrefs in both 7.0 and 7.1, consistent with metadata/method-pointer-table registration;
- direct calls to the 7.0 request factory: zero useful direct callers; the accessor is used indirectly or inlined;
- reading a response type directly from the generic RPC-submit call arguments: the unlock submit call does not carry an obvious response type/handler argument.

Preserving these failures is important: they prevent future work from repeating attractive but already disproven shortcuts.

## External-project cross-checks

Grasscutter's historical gameplay flow is useful as a semantic reference: receive `UnlockTransPointReq`, idempotently unlock and persist the point, send `ScenePointUnlockNotify` for a newly unlocked point, then send `UnlockTransPointRsp`.

LunaGC 7.1 independently agrees with `ScenePointUnlockNotify` CmdId `25567` and the field-2 / field-15 scene-id / point-list interpretation, but still leaves `UnlockTransPointReq/Rsp` as unresolved placeholders. No reliable external 7.1 project was found that names either `36641` or `20290` as `UnlockTransPointRsp`.

External projects are supporting evidence only; the final mapping should close against the official 7.1 client.

## AstaPS integration state

Do not assign `PacketOpcodes.UnlockTransPointRsp` yet. The current 7.1 response identity remains a two-way static-recovery question.

Once the response is confirmed, the intended server lifecycle is:

```text
receive UnlockTransPointReq(sceneId, pointId)
    -> if newly unlocked:
         update player state
         persist
         send ScenePointUnlockNotify(sceneId, pointId)
    -> send UnlockTransPointRsp(retcode = 0)
```

The current `GetScenePointRsp` send in AstaPS should remain until a runtime test proves it redundant. Under the no-legacy policy, ordinary current-gameplay robustness or lifecycle fallbacks should not be deleted merely because the protocol pair has been recovered.

## Next decisive step

The remaining target is a current-client binding between `UnlockTransPointReq (9369)` and exactly one of the two 112-byte response handlers. Preferred evidence, in descending strength:

1. recover the scene protocol-handler registration table sufficiently to bind request lifecycle / response delegate to one candidate;
2. recover the delegate field's concrete generic/parameter type from metadata or runtime type information;
3. find a current-client callback registration path that uniquely references `NCBEHBOCBJJ (36641)` or `MAFFAFNMEBM (20290)` from the unlock scene flow;
4. use a minimal runtime packet probe only after static identity is strong enough to make the experiment unambiguous.

Until one of these closes, record `36641` as the preferred strong candidate and `20290` as the surviving alternate, with neither marked confirmed.
