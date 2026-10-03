# Genshin 7.1 TPS protocol case study — historical AstaPS import

This case study preserves reusable results and methodology from the AstaPS 7.1 TPS work. It is a migration of existing work, not a new reverse-engineering pass. No claim in this document was independently revalidated while being moved here.

## Source provenance

Primary source: `MeChen618/AstaPS` PR #37, **Add 7.1 TPS weapons: protocol, equip switching, abilities, ammunition**.

- source branch: `ccr-53468249-3vfc4l`
- merged commit: `214c18e66ba5c89fb4d25283d2029687ab38a3b7`
- PR contained 14 commits and 60 changed files
- source testing: Gradle unit tests passed; TPS traveler swap and shooting HUD were tested in game; several ammunition details remained open

The branch also carried a small matching tool and a write-up under AstaPS `docs/tps/`. Those files should be treated as historical source material unless their reusable logic is deliberately promoted into maintained Genshin-Reverse tooling.

## Reusable method

The useful part of the TPS work is the matching discipline:

1. use a named older-version protocol only as a source of structural constraints;
2. compare against the current-version obfuscated definitions by message shape, child message types, and field-name consistency;
3. check field labels independently instead of assuming an old semantic label survives unchanged;
4. regenerate code from recovered descriptors and check that untouched generated files remain byte-identical;
5. keep uncertain identities and field semantics explicitly open instead of forcing names to make the server implementation convenient.

The source work found that a field name which is genuinely shared inside one version tends to share the same obfuscated spelling. That made same-version field-name consistency useful for rejecting inherited labels. The source specifically rejected five 7.0 labels during the 7.1 TPS port: `item_id`, `change_count`, `weapon_list`, `level`, and `progress`.

This is a cross-version matching technique. It supplies candidates and consistency checks; it does not replace current-version evidence gates defined by `docs/analysis-contract.md`.

## Imported protocol identities

The AstaPS source recorded these 7.1 identities:

| 7.1 obfuscated type | Imported semantic name | Imported CmdId / note |
| --- | --- | --- |
| `BLBLCMEFDEK` | `WearTpsEquipReq` | `20756` |
| `CNHCNOGBKAH` | `WearTpsEquipRsp` | `25902` |
| `FGIDLEPIPAG` | `TpsEquipChangeNotify` | `21312` |
| `JENJHKPCEOK` | `AbilityMetaUpdateTpsWeaponAmmunition` | Ability invoke argument `31` |
| `EGKCABANFKE` | `TpsWeaponAmmunitionInfo` | used at `SceneWeaponInfo` field `12` |
| `ONMCNLDIGJK` | `TpsAmmunitionChangeNotify` | `24371`; semantic name was marked inferred in the source |

The source also assigned readable TPS weapon-list fields to `SceneAvatarInfo` field 31, `AvatarInfo` field 37, `AvatarEnterSceneInfo` field 13, and `SceneTeamAvatar` field 382, plus `SceneWeaponInfo.ammunition_list` and `_TpsWeapon.accessory_id_list`.

These are preserved here as imported AstaPS evidence. They should not be copied into a canonical Genshin-Reverse protocol dataset merely because this case study records them; promotion still requires the canonical publication gate.

## Regeneration check used by the source

The AstaPS work recovered descriptors from generated sources, regenerated Java with protoc 3.18.1, and used byte-identical regeneration of untouched files as a consistency check. That is worth preserving as a general technique: when generated sources are part of the evidence, deterministic regeneration catches accidental hand edits and descriptor mistakes that compile successfully.

## Runtime/integration observations worth keeping separate

The source PR mixed protocol recovery with server integration. Some integration observations are still useful as validation context, but they should remain distinct from message identity:

- the shooting HUD required TPS weapon lists in more than `SceneAvatarInfo`;
- weapon entities also needed their abilities announced to the client;
- repeated weapon notifications required fresh entity ids in the tested server path;
- scene-entry ammunition synchronization was necessary for visible reserves in the tested implementation.

These are AstaPS behavior observations. They are not automatically protocol identity evidence.

## Open questions preserved from the source

The PR explicitly left these unresolved:

- what the client reads from `TpsWeaponAmmunitionInfo.ammunition_type` and `current_ammunition`;
- whether later CmdId `24371` messages represent deltas or totals;
- the semantics of `TpsWeaponAccessoryInfo` fields 12 and 14;
- the bool at field 7 of the ammunition meta;
- which of 5047 and 6316 belongs to Get/Set WidgetQuickSlotListRsp.

Preserving these questions matters because a later server implementation working around them does not resolve their protocol semantics.

## Maintenance lesson

AstaPS was a productive runtime laboratory, but durable reverse-engineering knowledge should live here with provenance and explicit confidence. Future work should reuse the imported constraints, then attach any stronger current-sample evidence to a focused `versions/<sample>/analyses/<topic>/` record instead of extending a server-only branch history.
