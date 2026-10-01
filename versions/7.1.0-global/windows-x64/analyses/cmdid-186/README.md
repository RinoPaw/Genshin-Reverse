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
+2716ms 7645 SetOpenStateReq                38107001
+2724ms  982 GetPlayerSocialDetailReq       4093a704
+2766ms 7829 GetShopReq                     70d00f
+2842ms 7829 GetShopReq                     70d30f
+2846ms 3755 QueryCodexMonsterBeKilledNumReq <empty>
+2858ms  186 UNKNOWN                        7202d027
```

No further inbound packet was observed before the client opened a new connection roughly 33 seconds later. Because the experiment deliberately withheld Quest 351, temporal proximity must not be treated as proof that CmdId 186 belongs to the born/intro lifecycle.

## Wire shape

```text
0x72 -> field 14, wire type 2
0x02 -> length 2
body -> d0 27
```

If the body is interpreted as packed varints, it is `[5072]`. That is a structural hypothesis only; field 14 may be bytes or a nested message.

## Historical warning

Some old Genshin versions used numeric CmdId 186 for `PlayerPropChangeNotify`. CmdIds were remapped in later clients, so the old equality is `historical-only` and must not be copied into the 7.1 mapping.

## Recovered prior-work evidence

A previous 7.1 static-analysis pass produced a client registry containing **4,896 unique CmdIds**. It was cross-checked against **1,540 known AstaPS opcodes**, all of which matched. That work also recovered examples such as:

```text
26105 -> HJDNCHODGOL (SetPlayerBornDataReq)
22899 -> ONKOPMILDMF (DoSetPlayerBornDataNotify)
```

The old audit references `decode_registry.py`, `registry/registry.csv` and `registry/registry_summary.json`, but those machine-readable artifacts were not preserved in an accessible repository. This investigation therefore treats regeneration/backfill of the canonical registry as the highest-priority dependency.

## Recovery plan

1. Regenerate or recover `registry/registry.csv` from the exact 7.1 sample.
2. Query `0xBA` to obtain the obfuscated type, `typeDefinitionIndex`, type-cache RVA and `GetCmdId` RVA.
3. Resolve the type in the metadata indexes and locate parser/serializer methods.
4. Recover field 14 structure from the parser.
5. Locate sender/call context and compare it with the runtime login timing.
6. Publish a semantic mapping only when static identity and runtime context agree.

Expected sample hashes are in `../../hashes.json`.
