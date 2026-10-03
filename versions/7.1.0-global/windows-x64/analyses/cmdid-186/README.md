# CmdId 186

Status: **HIGH_CONFIDENCE semantic candidate — `GetActivityInfoReq`**. Exact Global 7.1 identity/wire/sender structure is confirmed; the semantic name is withheld from canonical `known-opcodes.csv` until an exact-Global semantic edge closes the remaining region/build boundary.

Tracking issue: #1

## Runtime observation

```text
CmdId:    186 / 0xBA
Direction: client -> server
Payload:  72 02 d0 27
Time:     06:32:36 / +2858 ms from trace begin
Context:  fresh-account born / intro login trace
```

The primary trace was captured with Quest 351 startup intentionally suspended. `player.onLogin()` had already ended with `sceneLoadState=LOADING` before this packet arrived. Repository/library log recovery later found the same CmdId in at least four independent runs in the same login-init neighborhood.

The payload decodes as field 14, wire type 2, containing packed repeated uint32 `[5072]`.

## Exact Global 7.1 identity and protobuf shape

```text
registry index          48
CmdId                   186 / 0x00BA
client type             NLOMEGMJDGJ
typeDefinition          61556
type slot RVA           0x057F3858
GetCmdId                NLOMEGMJDGJ.AEGNNPENLNM @ 0x09ED2160
registry load RVA       0x07F7DB34
registry store RVA      0x07F7DB3B
identity status         static-verified-identity
```

`NLOMEGMJDGJ .cctor @ 0x09ED1F90` initializes tag `0x72` through the same `FieldCodec<uint32>` factory used by a confirmed `PlayerEnterSceneNotify` repeated-uint32 control. CopyFrom, size and parser paths operate on one collection at object offset `0x18`. Therefore field 14 is confirmed as packed repeated uint32.

The generated message method cluster is:

```text
CopyFrom(NLOMEGMJDGJ)          @ 0x09ED1E80
HKFIBILBMDF                     @ 0x09ED1EF0
.ctor                           @ 0x09ED1F40
.cctor                          @ 0x09ED1F90
EBAAKGIEFHO                     @ 0x09ED1FC0
NKFCABIOGLE                     @ 0x09ED2010
IENGFLPCLNM(EIBJNHDPEMB)       @ 0x09ED2100
AEGNNPENLNM / GetCmdId          @ 0x09ED2160
```

Direct E8-rel32 scanning found zero direct calls to these generated methods. The message is reached through its runtime type slot.

## Exact Global 7.1 sender path

The type slot has one external consumer outside registry construction and generated self-references:

```text
JKFCCMCAMGA.HMAPAFEOKJK(kind_0x15)
method index 457061
RVA          0x08EB3990
```

The previously temporary Actions artifact has now been reduced to `external-consumer-summary.json` so the evidence survives artifact expiry.

The callee has exactly one direct E8 caller:

```text
JKFCCMCAMGA.HMAPAFEOKJK()
method index 456625
RVA          0x08E2E4D0
call site    0x08E2E5FC
```

The parameterless overload conditionally forwards a collection/object from its own state into the one-parameter overload. The one-parameter overload then performs the message construction/send sequence:

```text
0x08EB39A2  load NLOMEGMJDGJ runtime type slot
0x08EB39A9  construct/resolve runtime object
0x08EB39B6  load message collection at +0x18
0x08EB39BF  pass caller-supplied collection
0x08EB39C5  copy/fill the collection
0x08EB39DA  load network sender instance from +0xA110
0x08EB39E6  pass the constructed NLOMEGMJDGJ message
0x08EB39F2  tail-jump to EDKMMIPJHJA.DMLCLHCBOBJ @ 0x147246860
```

This closes the Global sender mechanism: `JKFCCMCAMGA` constructs CmdId 186, fills its only repeated-uint32 collection and submits it through the generic network sender.

The runtime-class helper at `0x1184DFE0` has 26,201 direct callers and is generic; its fan-out is not semantic evidence.

## Independent current-version semantic cross-check

A separate LunaGC investigation used an exact **CN 7.1.0** client and independently recovered the same obfuscated pair:

```text
manager type   JKFCCMCAMGA
message type   NLOMEGMJDGJ
CmdId          186
message list   object +0x18
wire tag       0x72 = field 14 packed uint32
semantic name  GetActivityInfoReq
```

Its documented manager path collects opened activity IDs, constructs `NLOMEGMJDGJ`, writes that ID list to `+0x18`, and sends it. The same revision also assigns `PacketOpcodes.GetActivityInfoReq = 186`; its regression test verifies opcode 186 and packed field 14 `activity_id_list`.

This is unusually strong cross-project evidence because it matches the current version, obfuscated declaring type, obfuscated message type, CmdId, object offset, protobuf tag and send behavior. The source build is CN while this repository targets Global, so the semantic claim remains `HIGH_CONFIDENCE` until an exact-Global semantic edge is recovered.

Primary cross-project reference:

```text
invoker-bot/LunaGC
commit 1b363fac36d218ecfce3452a3c1893fe0fac6b31
docs/CRUCIBLE_PROTOCOL.md
src/main/java/emu/grasscutter/net/packet/PacketOpcodes.java
src/test/java/io/grasscutter/ActivityDisplayProtocolTest.java
```

## Current conclusion

The maintained semantic candidate is:

```text
CmdId 186 / NLOMEGMJDGJ
    -> GetActivityInfoReq
    -> repeated uint32 activity_id_list at field 14
```

Confidence: **HIGH_CONFIDENCE**.

The exact Global evidence already proves the identity, field type and sender structure. The independent CN 7.1 evidence supplies the activity-manager semantic binding. We do not promote this to `CONFIRMED`/canonical protocol data solely from a different regional executable.

## Historical warning

Some old Genshin versions used numeric CmdId 186 for `PlayerPropChangeNotify`. CmdIds were remapped across clients, so historical numeric equality remains rejected evidence.

## Remaining research plan

1. Resolve what the Global `JKFCCMCAMGA.HMAPAFEOKJK()` overload reads before calling `0x08EB3990`, and prove that collection is the current/open activity ID set.
2. Correlate the observed runtime value `5072` with exact Global 7.1 activity schedule/resource state.
3. Recover an exact-Global activity response/handler edge or another independent Global semantic anchor.
4. Promote `GetActivityInfoReq` to canonical protocol data only after the exact-Global semantic gate is satisfied.

Expected sample hashes are in `../../hashes.json`.
