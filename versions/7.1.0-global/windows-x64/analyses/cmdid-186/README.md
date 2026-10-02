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

## Current infrastructure baseline

The registry/metadata dependency that originally blocked this investigation has been closed:

- `../../registry/registry.csv` is the current canonical 7.1 client identity registry and contains the complete 4,896-row / 4,896-unique-CmdId population;
- `../../registry/registry.summary.json` records the publication/coverage summary;
- `../../registry/control-set.csv` is the broad AstaPS-derived comparison set and must not be treated as target-client semantic proof;
- `../../proto/known-opcodes.csv` contains the smaller evidence-gated target-client semantic mappings;
- the complete canonical metadata indexes are published under `../../metadata/`.

Do not repeat registry or metadata recovery as a prerequisite for CmdId 186. Start from the published artifacts and add packet-specific evidence.

## Remaining research plan

1. Query CmdId 186 in the canonical registry and record its obfuscated type, typeDefinitionIndex, type slot and available GetCmdId evidence in this analysis directory.
2. Resolve that type through the canonical metadata indexes and identify parser/serializer methods.
3. Recover the concrete field-14 structure from parser behavior; keep packed-varint/bytes/nested-message interpretations separate until static evidence selects one.
4. Locate sender/call-site context and compare it with the repeated runtime login-init observations.
5. Cross-check any semantic candidate against current target-client evidence and related projects without importing historical numeric equality.
6. Promote a semantic name only when static identity, parser shape and runtime context agree.

Expected sample hashes are in `../../hashes.json`.
