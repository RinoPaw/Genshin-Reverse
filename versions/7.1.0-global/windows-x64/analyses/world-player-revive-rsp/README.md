# WorldPlayerReviveRsp opcode recovery

Status: **HIGH_CONFIDENCE** current-7.1 semantic binding to `CmdId 7003 / GFPMFMJPNMA`; protobuf shape and S2C client handler are **CONFIRMED**. Runtime transaction confirmation remains the promotion gate for `known-opcodes.csv`.

## Target

Exact sample:

- Genshin Impact 7.1.0 Global / Windows x64
- EXE SHA-256 `08a3086d5f3fe695f01dab61efa42e442006b18e5e475b2520df356f6a073b7d`
- metadata SHA-256 `05ae04d7a91b91cc880217a56b0b01f3e67f845b06e894216654ec5d160e0da0`

The gameplay transaction is:

```text
WorldPlayerReviveReq
  CmdId 5232
  C2S
    ->
WorldPlayerReviveRsp
  unknown 7.1 CmdId
  S2C
  int32 retcode = 14
```

`WorldPlayerReviveReq = 5232` was already runtime-confirmed from the team-wipe revive button. The current client maps it to `OCEMECOHKDK`, type slot `0x57F4EC8`, `GetCmdId` RVA `0x0E7431E0`.

## Candidate reduction

The current client receiver `LLCGIEDMIIG` contains 13 inbound protobuf types whose response-side shape can plausibly match the one-`int32` generated response family:

```text
4385, 4761, 5923, 7003, 8223, 9129,
21465, 22060, 22120, 22691, 22904, 23684, 24380
```

Exact 7.1 parser recovery was run for all 13. Only two consume protobuf tag `0x70`, i.e. **field 14 / wire type 0**:

```text
7003   GFPMFMJPNMA
22060  DAKFNDLCAHC
```

The other 11 are excluded by current-client wire layout. `candidate-wire-tags.csv` preserves the complete set.

## Finalists

### CmdId 7003

Stable identity:

```text
type             GFPMFMJPNMA
typeDefinition   30947
type slot RVA    0x057F55A0
GetCmdId RVA     0x0A5374C0
parser tag       0x70 = field 14, varint
client handler   LLCGIEDMIIG.AAHPLLIEFIB @ 0x0C241960
```

The handler reads `[message + 0x18]` as the retcode. A nonzero value enters the shared error path at `0x0B515410`. Success returns without additional native-side behavior.

That is a direct fit for a response whose generated schema is only:

```proto
int32 retcode = 14;
```

### CmdId 22060 rejection

Stable identity:

```text
type             DAKFNDLCAHC
typeDefinition   78860
type slot RVA    0x057DCD10
GetCmdId RVA     0x13F17FA0
parser tag       0x70 = field 14, varint
client handler   LLCGIEDMIIG.KCLOEKKLMLH @ 0x0C25D900
```

This handler also checks the retcode, but its success path constructs and fires internal client Notify value `0xA4E` / `2638`.

Current 7.1 metadata recovers the semantic Notify enum as obfuscated type `GFJCNBMJPCH`, typeDefinition `14478`. The enum is ordinal from `None = 0`:

```text
AvatarReviveRequested        = 514
SaveAvatarsToNewBackupTeam   = 2638
```

Therefore CmdId 22060's success side effect is a **backup-team** event, not the revive event. It is rejected as `WorldPlayerReviveRsp`.

## Conclusion

The surviving current-client binding is:

```text
WorldPlayerReviveRsp = 7003
direction            = S2C
type                 = GFPMFMJPNMA
retcode              = field 14 / varint
handler              = LLCGIEDMIIG.AAHPLLIEFIB @ 0x0C241960
```

Evidence level is `HIGH_CONFIDENCE` for the semantic name because this conclusion uses exhaustive structural reduction plus a semantic rejection of the only other field-14 finalist, but there is not yet a captured current-7.1 `5232 -> 7003` request/response transaction.

Do not add `WorldPlayerReviveRsp` to `proto/known-opcodes.csv` until runtime confirms that transaction.

## Provenance

Temporary exact-sample research workflows were used only on `research/world-player-revive-rsp`; they are not part of the persistent workflow surface.

Relevant hosted runs:

```text
37280196466  all 13 parser tags
37280399233  7003 / 22060 native finalist comparison
37280701902  current Notify metadata query
37280815012  AvatarReviveRequested ordinal recovery
37281259847  Notify 2638 semantic recovery
```

The final Notify query establishes:

```text
GFJCNBMJPCH.AvatarReviveRequested       = 514
GFJCNBMJPCH.SaveAvatarsToNewBackupTeam = 2638
```

## Runtime promotion target

Use an AstaPS build that emits `WorldPlayerReviveRsp` as CmdId `7003`, then perform:

```text
team wipe
  -> press revive
  -> observe C2S 5232
  -> server sends S2C 7003 with success retcode
  -> client accepts response and completes revive / scene transition
```

Capture packet direction, CmdId and payload. A successful current-7.1 transaction promotes the semantic binding to `CONFIRMED` and allows `known-opcodes.csv` publication.
