# Monster drowning packet — 7.1 Global (#11)

Status: **UNRESOLVED**. This is a static compatibility audit, not a recovered 7.1 packet mapping.

## Symptom and server consumer

On AstaPS, a monster falling into water can display zero HP client-side without
the authoritative server completing death/despawn/drop until another hit.
The server has `HandlerSceneEntityDrownReq` and
`HandlerEntityAiKillSelfNotify`, but the names alone do not establish which,
if either, is sent by the current client.

## Exact-client controls

The canonical registry at `registry/registry.csv` has **4,896 unique CmdIds**.

| Control | 7.1 registry result | Interpretation |
| --- | --- | --- |
| Legacy `EntityAiKillSelfNotify = 29500` | **Absent** | AstaPS currently retains this constant, but it cannot be mapped to the published current 7.1 GetCmdId registry |
| Legacy `SceneEntityDrownReq = 20113` | `NHHIOCJPICK`, type 60907, 2 declared metadata fields | AstaPS already assigns 20113 to `GadgetTalkChangeNotify`; the old drowning request ID must not be reused |
| Legacy `SceneEntityDrownRsp = 26715` | `NILBKHGJOMB`, type 14990, 2 declared metadata fields | Numeric type identity exists, but its response **semantic identity is not established** |

The metadata field counts come from `metadata/types.csv` and are **not**
proof of protobuf wire field numbers or semantic names.

Source pins: `RinoPaw/Genshin-Reverse@07ca782d`,
`RinoPaw/AstaPS@a27e5a75`. In AstaPS `PacketOpcodes.java`,
`SceneEntityDrownReq` and `SceneEntityDrownRsp` are explicitly zero/unknown
while `EntityAiKillSelfNotify` still reads 29500. This corrects Issue #11's
earlier claim that the latter was zero.

## Independent 7.1-server cross-check

`capyb2222/LunaGC_7.1.0@8be69a16` (branch `7.1`) uses placeholder
**negative sentinels**: `SceneEntityDrownReq = -22`,
`SceneEntityDrownRsp = -97`, `EntityAiKillSelfNotify = -150`.
It preserves historical `SceneEntityDrownReq` field
`uint32 entity_id = 3` and response fields
`uint32 entity_id = 4; int32 retcode = 13`, but these names/fields have
**not** been bound to an exact Global 7.1 client opcode. The branch is a
compatibility cross-check, not a current-client semantic authority.

## Reproduce the registry checks

```bash
genshinre query-registry versions/7.1.0-global/windows-x64/registry/registry.csv --cmd-id 20113
genshinre query-registry versions/7.1.0-global/windows-x64/registry/registry.csv --cmd-id 26715
genshinre query-registry versions/7.1.0-global/windows-x64/registry/registry.csv --cmd-id 29500
python -m unittest tests.test_monster_drowning_static_71 -v
```

All checks above use committed artifacts. No proprietary client binary or
packet capture is needed. The machine-readable controls are in
[`evidence.json`](evidence.json).

## Remaining discriminator

1. Reproduce a **single** monster-in-water event with AstaPS packet DEBUG
   diagnostics and record newly observed C2S opcode(s), packet payload hex,
   the matching entity ID and nearby timestamps. Include a no-drowning
   baseline; otherwise unrelated unknown login/movement packets can be
   misidentified. A zero-HP UI animation is not proof that any particular
   C2S packet was emitted.
2. Look up each observed opcode in the exact 7.1 registry. Decode its
   protobuf tags from the packet bytes using `genshinre wire <hex>`.
   Treat historical field numbers 3, 4 and 13 only as **comparison vectors**.
3. Trace the identified type's native sender/handler from the pinned client.
   Establish the actual entity-ID field and direction. Separate
   `SceneEntityDrownReq` from `EntityAiKillSelfNotify` or another
   environment-death path before changing AstaPS.

Only a matching current-client static/runtime transaction allows
`CONFIRMED` semantic promotion. The server handler must not be enabled
using the old numeric constants in the meantime.
