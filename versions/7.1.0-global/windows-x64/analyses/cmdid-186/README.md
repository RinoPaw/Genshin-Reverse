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

The trace was captured with Quest 351 startup intentionally suspended. `player.onLogin()` had already ended with `sceneLoadState=LOADING` before this packet arrived.

Immediate inbound sequence:

```text
+2716ms 7645 SetOpenStateReq                 38107001
+2724ms  982 GetPlayerSocialDetailReq        4093a704
+2766ms 7829 GetShopReq                      70d00f
+2842ms 7829 GetShopReq                      70d30f
+2846ms 3755 QueryCodexMonsterBeKilledNumReq <empty>
+2858ms  186 UNKNOWN                         7202d027
```

No further inbound packet was observed before the client opened a new connection roughly 33 seconds later. Because the experiment deliberately withheld Quest 351, temporal proximity must not be treated as proof that CmdId 186 belongs to the born/intro lifecycle.

Repository/library log recovery later found the same CmdId in at least four independent runs in the same login-init neighborhood. In several runs it was followed a few seconds later by scene-area/scene-point traffic. This supports a repeatable login or scene-initialization role, but still does not establish a semantic packet name.

## Wire shape

```text
0x72 -> field 14, wire type 2
0x02 -> length 2
body -> d0 27
```

If the body is interpreted as packed varints, it is `[5072]`. That is a structural hypothesis only; field 14 may be bytes or a nested message.

## Historical warning

Some old Genshin versions used numeric CmdId 186 for `PlayerPropChangeNotify`. CmdIds were remapped in later clients, so the old equality is `historical-only` and must not be copied into the 7.1 mapping.

## Current 7.1 static identity

The current canonical 7.1 registry closes the client-side identity of CmdId 186 independently of its still-unknown semantic name:

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

The identity is backed by the verified 7.1 registry constructor slot, the dominant declaring-type RIP-relative slot xrefs, and the `AEGNNPENLNM` constant-return `GetCmdId` identity. The independent GetCmdId candidate graph also resolves CmdId 186 to the single type `NLOMEGMJDGJ` / typeDefinition `61556` with the same `0x09ED2160` method.

This closes the registry/type-identity question only. The canonical semantic direction remains unset, while runtime capture independently observes this packet client -> server. Parser shape, sender context, and semantic name remain unresolved.

## Current infrastructure baseline

The registry/metadata dependency that originally blocked this investigation has been closed:

- `../../registry/registry.csv` is the current canonical 7.1 client identity registry and contains the complete 4,896-row / 4,896-unique-CmdId population;
- `../../registry/registry.summary.json` records the publication/coverage summary;
- `../../registry/control-set.csv` is the broad AstaPS-derived comparison set and must not be treated as target-client semantic proof;
- `../../proto/known-opcodes.csv` contains the smaller evidence-gated target-client semantic mappings;
- the complete canonical metadata indexes are published under `../../metadata/`.

Do not repeat registry or metadata recovery as a prerequisite for CmdId 186. Start from the published artifacts and add packet-specific evidence.

## Remaining research plan

1. Resolve `NLOMEGMJDGJ` through the canonical metadata indexes and identify its parser/serializer methods.
2. Recover the concrete field-14 structure from parser behavior; keep packed-varint/bytes/nested-message interpretations separate until static evidence selects one.
3. Locate sender/call-site context and compare it with the repeated runtime login-init observations.
4. Cross-check any semantic candidate against current target-client evidence and related projects without importing historical numeric equality.
5. Promote a semantic name only when static identity, parser shape and runtime context agree.

Expected sample hashes are in `../../hashes.json`.
