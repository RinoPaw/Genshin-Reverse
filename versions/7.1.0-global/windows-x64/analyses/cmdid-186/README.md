# CmdId 186

Status: **UNRESOLVED**

Tracking issue: #1

## Runtime observation

```text
CmdId:    186 / 0xBA
Direction: client -> server
Payload:  72 02 d0 27
Time:     06:32:36 / +2858 ms from trace begin
Context:  fresh-account born / intro login trace
```

The primary trace was captured with Quest 351 startup intentionally suspended. `player.onLogin()` had already ended with `sceneLoadState=LOADING` before this packet arrived. Repository/library log recovery later found the same CmdId in at least four independent runs in the same login-init neighborhood. This supports a repeatable login or scene-initialization role, but does not establish a semantic packet name.

Immediate inbound sequence:

```text
+2716ms 7645 SetOpenStateReq                 38107001
+2724ms  982 GetPlayerSocialDetailReq        4093a704
+2766ms 7829 GetShopReq                      70d00f
+2842ms 7829 GetShopReq                      70d30f
+2846ms 3755 QueryCodexMonsterBeKilledNumReq <empty>
+2858ms  186 UNKNOWN                         7202d027
```

## Protobuf structure

The runtime payload parses as:

```text
0x72 -> field 14, wire type 2
0x02 -> length 2
body -> d0 27
```

Field 14 is now closed as **packed repeated uint32**, so the payload carries `[5072]`.

The exact 7.1 client proof is two-part. `NLOMEGMJDGJ .cctor @ 0x09ED1F90` loads tag `0x72`, calls codec factory `0x0AABBD80`, and stores the returned codec at class static offset `0x30320`. Its CopyFrom, size and parser paths all operate on one collection at object offset `0x18` using that codec.

A confirmed same-client control closes the scalar type: `PlayerEnterSceneNotify` (`DGGODBOJHNI`, CmdId 9582) has a known `repeated uint32 scene_tag_id_list = 5`; its exact 7.1 `.cctor @ 0x0F60AD20` loads tag `0x2A` and calls the same factory `0x0AABBD80`. Therefore `MJKCIJEILLP.OLACMCNHBHD @ 0x0AABBD80` is the relevant `FieldCodec<uint32>` factory family member and CmdId 186 field 14 is repeated uint32. The control evidence is preserved in `uint32-codec-control.json`.

`NLOMEGMJDGJ` has the generated repeated-field genericinst pair:

```text
DCCONFODELK   type index 476942   kind_0x15
MGMOJNPMFFK   type index 476943   kind_0x15
```

The same pair occurs together in 1,042 decoded generated message types. Their exact 7.1 runtime entries are preserved in `protobuf-structure.json`.

## Exact-client method evidence

The message method cluster is:

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

`IENGFLPCLNM @ 0x09ED2100` is the generated protobuf merge/parser path. `CopyFrom @ 0x09ED1E80` is preserved in `copyfrom.disasm.json`; the compact structural proof is in `protobuf-structure.json`.

## Current 7.1 static identity

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

Direct E8-rel32 scanning found zero direct calls to all eight generated `NLOMEGMJDGJ` methods, so that sender path is rejected and recorded in `direct-call-xrefs.json`.

The type slot itself has five code xrefs. Three are generated self-references, one is registry installation, and one is an external consumer:

```text
JKFCCMCAMGA.HMAPAFEOKJK @ 0x08EB3990
  type-slot read        @ 0x08EB39A2
  nearby helper         PFKFIFOEHNA.JGIBJCAEEBB(Il2CppRuntimeClassHandle)
  helper RVA            0x1184DFE0
```

This is the current static lead for indirect sender/context recovery. The persisted scene-handler-dispatch evidence has no row for CmdId 186, so that scene-owner dispatch table also does not identify its consumer path.

## Historical warning

Some old Genshin versions used numeric CmdId 186 for `PlayerPropChangeNotify`. CmdIds were remapped across clients, so that equality remains `historical-only` and is not current 7.1 semantic evidence.

## Remaining research plan

1. Classify `JKFCCMCAMGA.HMAPAFEOKJK @ 0x08EB3990` and trace its callers/registration role.
2. Follow indirect/interface/delegate/static sender paths from that consumer and correlate them with repeated login-init observations.
3. Generate exact-7.1 semantic candidates whose schema contains repeated uint32 at field 14, then require current-client context before promotion.
4. Promote a semantic name only when static identity, parser shape and runtime context agree.

Expected sample hashes are in `../../hashes.json`.
