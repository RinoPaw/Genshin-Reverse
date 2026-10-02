# Barbara C6 revive chain

Status: client Ability trigger and 900-second skill cooldown are **CONFIG-CONFIRMED** on current 7.1 data; the exact Barbara C6 wire invoke is **UNRESOLVED**.

## Scope

This analysis separates two responsibilities:

1. who decides that Barbara C6 should fire after an avatar dies;
2. who commits and synchronizes the dead avatar back to an authoritative alive state.

The 7.1 configuration gives a strong answer to the first question. The second still needs an exact wire/native trace.

## Current 7.1 resource checkpoint

Current-version Ability evidence was checked against:

```text
DimbreathBot/AnimeGameData
commit 792978e5503ecfba73dcb3562ed44a0d35a2abe2
CNRELWin7.1.0_R48379043_S48511369_D48533839
2026-10-01
```

These resources establish Ability/config semantics. Concrete wire-local IDs and payloads are not promoted without packet or native evidence.

## C6 installs four abilities

`BinOutput/Talent/AvatarTalents/ConfigTalent_Barbara.json` maps `Barbara_Constellation_6` to four added abilities:

```text
Avatar_Barbara_ReBorn_Pre
Avatar_Barbara_ReBorn
Avatar_Barbara_ReBornEffect_01
Avatar_Barbara_ReBornEffect_02
```

The important trigger/execution pair is `ReBorn_Pre` + `ReBorn`.

## Death trigger

`Avatar_Barbara_ReBorn_Pre` contains a `DoReviveMixin` with `type = OffStage`.

The two action-list field names are obfuscated in the current output, but the embedded debug strings expose their roles. The kill-side list contains:

```text
DebugLog "onKillActions Start!!!!!!"
EntityDoSkill skillID=10076 doOffStage=true
```

The revive-side list contains:

```text
EntityDoSkill skillID=10079 doOffStage=true
EntityDoSkill skillID=10080 doOffStage=true
DebugLog "onReviveActions Start!!!!!!"
```

`ReBorn_Pre.onAdded` also contains:

```text
UnlockSkill skillID=10076
```

So the C6 ability itself observes the off-stage death/revive lifecycle and starts hidden skill `10076` from the kill path.

Older deobfuscated client metadata independently shows `AbilityDoReviveMixin : BaseAbilityMixin` implementing event-listener methods such as `ListenEvent`, `AddEventListener`, and `RemoveEventListener`. That is structural continuity evidence only; current 7.1 BinOutput is the version-specific evidence used above.

## Cooldown identity: skill 10076

Current 7.1 `ExcelBinOutput/AvatarSkillExcelConfigData.json` contains:

```text
id          = 10076
cdTime      = 900.0
buffIcon    = Skill_B_Barbara_01
abilityName = Avatar_Barbara_ReBorn
```

`900 s = 15 min`.

This closes the earlier cooldown uncertainty: Barbara C6 has a concrete hidden avatar-skill cooldown identity in 7.1. The cooldown is not merely an arbitrary 15-minute constant embedded in `DoReviveMixin`.

An official server can still validate, restore, or persist that skill cooldown. What the resource does not support is treating a Barbara-specific wall-clock timer in the generic server death hook as the native source of the C6 trigger decision.

## Revive action

`Avatar_Barbara_ReBorn.onAbilityStart` contains:

```text
AvatarSkillStart skillID=10076 cdRatio=1 doOffStage=true
DebugLog "10076 Start!!!!!!"
ReviveAvatar target=AllPlayerAvatars doOffStage=true
```

The same ability defines:

```text
abilitySpecials:
  HealHP = 1.0
```

The current configured sequence is therefore:

```text
Barbara C6 installed
  -> Avatar_Barbara_ReBorn_Pre
  -> off-stage DoReviveMixin receives the kill lifecycle event
  -> EntityDoSkill(10076)
  -> Avatar_Barbara_ReBorn
  -> AvatarSkillStart(10076), using the 900 s skill cooldown
  -> ReviveAvatar(AllPlayerAvatars, HealHP=1.0)
  -> revive lifecycle runs effect skills 10079 / 10080
```

### Naming correction

The concrete Barbara C6 action in current 7.1 BinOutput is `ReviveAvatar`.

Generic/historical references to `ReviveDeadAvatar` are useful for understanding the action family, but they must not be cited as the action name of this specific Barbara 7.1 chain.

## Network boundary

Current 7.1 protocol mappings identify:

```text
AbilityInvocationsNotify = 6622
```

The local 7.1 registry independently has CmdId `6622` as obfuscated protobuf type `ALPCFFANJPJ` with a high-confidence return-constant `GetCmdId` candidate.

AstaPS's current C2S handler parses `AbilityInvocationsNotify`, iterates its `AbilityInvokeEntry` values, and calls `AbilityManager.onAbilityInvoke(entry)`.

For an entry whose `head.local_id != 0`, AstaPS resolves the instanced ability/modifier, maps the local ID through the deterministic `localIdToAction` / `localIdToMixin` tables, and executes the corresponding resource action. The local-ID generator assigns those action IDs deterministically from the Ability config structure.

That gives the Barbara chain a normal client-Ability-to-server execution route without requiring a dedicated `BarbaraReviveReq` message.

Still unresolved:

```text
exact AbilityInvokeEntry emitted when Barbara C6 fires
exact head.local_id for the ReBorn action in the live client instance
exact argument_type and ability_data payload
whether hidden skill 10076 also emits EvtDoSkillSuccNotify
exact official-server cooldown validation/persistence behavior
```

Do not promote any of those values until a current 7.1 capture or native sender xref proves them.

## Implication for AstaPS

AstaPS currently has two potential trigger routes:

```text
A. Ability-driven
   client Ability invoke
     -> ActionReviveAvatar
     -> server Dead -> Alive commit/sync

B. server fallback
   generic death handling
     -> PartyReviveHelper.tryBarbaraC6AfterDeath()
     -> BARBARA_CD_UNTIL wall-clock timer
     -> automatic revive
```

The current 7.1 resource model supports A as the native trigger model. B is gameplay fallback/emulation and must not be used as evidence that the official server independently decides to fire C6 on every death.

`ActionReviveAvatar` remains useful: receiving a client Ability action does not remove the server's responsibility to validate and synchronize the resulting life state.

The known persistent-dead-state failure also means HP restoration alone is insufficient. A successful revive must explicitly complete the Dead -> Alive transition and clear any protected dead flag before later combat processing.

### Cooldown migration rule

Do not delete `BARBARA_CD_UNTIL` merely because skill `10076` is now identified.

Until AstaPS has generic avatar-skill cooldown validation/state for this hidden skill, the existing timer can remain as a temporary anti-replay guard. It should stop being the thing that *decides* C6 fires once the Ability-driven route is runtime-confirmed.

The long-term server model should validate the cooldown identity `skill 10076 / 900 s`, not maintain a parallel Barbara-specific trigger lifecycle.

## Confidence table

| Claim | Status | Evidence |
| --- | --- | --- |
| Barbara C6 adds the four `ReBorn*` abilities | CONFIRMED | current 7.1 talent config |
| `ReBorn_Pre` uses off-stage `DoReviveMixin` | CONFIRMED | current 7.1 ability config |
| kill lifecycle starts hidden skill 10076 | CONFIRMED | current 7.1 ability config + embedded debug semantic |
| skill 10076 is `Avatar_Barbara_ReBorn` | CONFIRMED | current 7.1 AvatarSkillExcel config |
| skill 10076 has `cdTime = 900` | CONFIRMED | current 7.1 AvatarSkillExcel config |
| `ReBorn` starts skill 10076 then runs `ReviveAvatar` | CONFIRMED | current 7.1 ability config |
| revive target is `AllPlayerAvatars` with `HealHP = 1.0` | CONFIRMED | current 7.1 ability config |
| current Ability C2S channel is CmdId 6622 | CONFIRMED | current 7.1 protocol mapping + registry candidate |
| Barbara C6 specifically uses 6622 with a recovered concrete local ID | PROBABLE / UNRESOLVED | generic Ability pipeline is known; exact live entry not captured |
| official server independently auto-triggers C6 from generic death handling | NO POSITIVE EVIDENCE | current config defines a dedicated client Ability lifecycle trigger |

## Runtime proof target

Capture three otherwise identical lethal events:

```text
A. Barbara C6 present, skill 10076 ready
B. Barbara C6 present, skill 10076 cooling down
C. Barbara absent / C6 unavailable
```

For CmdId `6622`, decode every batched `AbilityInvokeEntry` and compare:

```text
entity_id
head.instanced_ability_id
head.instanced_modifier_id
head.local_id
head.target_id
argument_type
ability_data
```

Also watch `EvtDoSkillSuccNotify` for skill `10076`, but do not assume the off-stage hidden skill sends it until observed.

The decisive result is an invoke/action sequence unique to case A that resolves to `Avatar_Barbara_ReBorn` / `ReviveAvatar`. A second death during the 900-second cooldown should suppress that trigger sequence.

Once the exact entry is captured, record its local-ID mapping here. At that point `PartyReviveHelper.tryBarbaraC6AfterDeath()` can be evaluated for removal while retaining authoritative revive-state synchronization and cooldown validation.
