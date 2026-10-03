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

## Wire and generated protobuf structure

The runtime payload parses as:

```text
0x72 -> field 14, wire type 2
0x02 -> length 2
body -> d0 27
```

Packed-varint decoding of the body yields `[5072]`. Exact 7.1 client code now independently proves that field 14 is represented by a generated repeated-field structure. The remaining uncertainty is the scalar codec overload, so `[5072]` is structurally supported as a packed repeated value while the exact scalar type remains unresolved.

`NLOMEGMJDGJ` has two decoded instance/static genericinst-related fields:

```text
DCCONFODELK   type index 476942   kind_0x15
MGMOJNPMFFK   type index 476943   kind_0x15
```

The same pair occurs together in 1,042 decoded generated message types. A confirmed control is `PlayerEnterSceneNotify` (`DGGODBOJHNI`, CmdId 9582), which also contains both type indexes. Their exact 7.1 runtime entries are preserved in `protobuf-structure.json`; the kind-0x15 data values are transformed/index-like values (`0x7638` and `0x763F`), not standard in-image generic-class pointers.

## Exact-client protobuf method evidence

The message method cluster is:

```text
CopyFrom(NLOMEGMJDGJ)          @ 0x09ED1E80
HKFIBILBMDF                     @ 0x09ED1EF0
.cctor                          @ 0x09ED1F90
EBAAKGIEFHO                     @ 0x09ED1FC0
IENGFLPCLNM(EIBJNHDPEMB)       @ 0x09ED2100
AEGNNPENLNM / GetCmdId          @ 0x09ED2160
```

The `.cctor` is decisive. At `0x09ED1F94` it loads `ecx = 0x72`, at `0x09ED1F99` it calls `0x0AABBD80`, and at `0x09ED1FA5` it stores the returned object into class static offset `0x30320`. Canonical metadata resolves `0x0AABBD80` to `MJKCIJEILLP.OLACMCNHBHD`, typeDefinition `84808`, method index `700560`, with a single `uint32` parameter. This establishes the tag-bearing field-codec factory call; the exact scalar FieldCodec overload is still open.

The generated methods all converge on one collection at object offset `0x18`:

- `CopyFrom @ 0x09ED1E80` reads the collection from both source and destination and tail-jumps to helper `0x182C4710`;
- the size-like path at `0x09ED1EF0` reads the same collection and static codec, then tail-jumps to `0x182C3AA0`;
- parser `IENGFLPCLNM @ 0x09ED2100` reads the same collection and static codec, passes the protobuf input object, and tail-jumps to `0x182C3E20`.

The exact sample evidence is summarized in `protobuf-structure.json`; the preserved `CopyFrom` disassembly is in `copyfrom.disasm.json`. Source probe provenance is Actions run `37095178757`, artifact `11264255696`, ZIP SHA-256 `f5c89aae9e08d5f52fb119567053bf2401d6857b9b2d57570f5237fc6d367fc0`.

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
slot xref count         3
xref method count       3
identity status         static-verified-identity
```

The registry/type identity and repeated-field parser shape are now closed independently. Runtime capture establishes C2S direction. Sender context, exact scalar codec overload, and semantic packet name remain unresolved. The persisted scene-handler-dispatch evidence has no row for CmdId 186, so that specific scene-owner dispatch table does not provide its consumer path.

## Historical warning

Some old Genshin versions used numeric CmdId 186 for `PlayerPropChangeNotify`. CmdIds were remapped across clients, so that equality remains `historical-only` and is not current 7.1 semantic evidence.

## Remaining research plan

1. Identify the exact scalar FieldCodec overload implemented by `MJKCIJEILLP.OLACMCNHBHD @ 0x0AABBD80` using exact-client controls.
2. Locate callers/constructor or sender-path xrefs for `NLOMEGMJDGJ` and compare them with the repeated login-init runtime observations.
3. Cross-check semantic candidates against current target-client evidence and related projects without importing historical numeric equality.
4. Promote a semantic name only when static identity, parser shape and runtime context agree.

Expected sample hashes are in `../../hashes.json`.
