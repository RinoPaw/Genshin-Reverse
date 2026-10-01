# Barbara C6 revive chain

Status: client-side trigger chain is **CONFIRMED** from 7.1 BinOutput; cooldown authority and the exact network/server commit path remain **UNRESOLVED**.

## Scope

This note separates two questions:

1. who decides that Barbara C6 should trigger;
2. who commits the dead avatar back to an authoritative alive state.

Those two responsibilities do not need to live on the same side of the client/server boundary.

## 7.1 constellation entry

The 7.1 talent config for `Barbara_Constellation_6` attaches four dynamic abilities:

```text
Avatar_Barbara_ReBorn_Pre
Avatar_Barbara_ReBorn
Avatar_Barbara_ReBornEffect_01
Avatar_Barbara_ReBornEffect_02
```

Source:

```text
iam-akuzihs/binout
commit 6736c676c273ea5da50712e1c5a6d58aa0e69749
v7.1.0-9587d1afbd/BinOutput/Talent/AvatarTalents/ConfigTalent_Barbara.json
```

This confirms that C6 installs a dedicated revive ability chain instead of relying only on Barbara's ordinary base skill logic.

## Confirmed 7.1 trigger chain

`Avatar_Barbara_ReBorn_Pre` contains a `DoReviveMixin` configured for `OffStage` operation.

Its kill-side actions are:

```text
DoReviveMixin
  type = OffStage
  onKillActions
    -> DebugLog("onKillActions Start!!!!!!")
    -> EntityDoSkill(skillID = 10076, doOffStage = true)
```

The same ability unlocks the hidden skill on add:

```text
Avatar_Barbara_ReBorn_Pre.onAdded
  -> UnlockSkill(skillID = 10076)
```

The revive-side actions then execute the two presentation/effect skills:

```text
onReviveActions
  -> EntityDoSkill(skillID = 10079)
  -> EntityDoSkill(skillID = 10080)
```

The actual revive ability begins by starting skill `10076`, then performs a revive action:

```text
Avatar_Barbara_ReBorn.onAbilityStart
  -> AvatarSkillStart(skillID = 10076, cdRatio = 1, doOffStage = true)
  -> DebugLog("10076 Start!!!!!!")
  -> ReviveAvatar(
       amountByTargetMaxHPRatio = "HealHP",
       target = AllPlayerAvatars,
       doOffStage = true)

abilitySpecials:
  HealHP = 1
```

So the resource-level chain is:

```text
Barbara C6 talent
  -> add ReBorn abilities
  -> off-stage DoReviveMixin observes the kill/death condition
  -> EntityDoSkill(10076)
  -> AvatarSkillStart(10076)
  -> ReviveAvatar(AllPlayerAvatars, 100% target max HP)
  -> effect skills 10079 / 10080
```

Source:

```text
iam-akuzihs/binout
commit 6736c676c273ea5da50712e1c5a6d58aa0e69749
v7.1.0-9587d1afbd/BinOutput/Ability/Temp/AvatarAbilities/ConfigAbility_Avatar_Barbara.json
```

### Naming correction

The concrete 7.1 Barbara C6 action recovered here is named `ReviveAvatar` in the extracted BinOutput. Earlier generic references to `ReviveDeadAvatar` should not be used as evidence for this specific 7.1 chain.

The Barbara 7.1 block also contains no visible `byServer` field on this `ReviveAvatar` action. That absence does not prove which side is authoritative; it only means the ownership question cannot be resolved from a `byServer` value in this block.

## Cooldown evidence

The hidden skill structure strongly suggests that the 15-minute C6 cooldown is represented through the skill system rather than a Barbara-specific timer embedded directly in `DoReviveMixin`.

Historical `AvatarSkillData` from 2.8 contains:

```text
10076  Avatar_Barbara_ReBorn           skill CD = 900
10079  Avatar_Barbara_ReBornEffect_01  skill CD = 900
10080  Avatar_Barbara_ReBornEffect_02  skill CD = 900
```

and marks skill `10076` as ignoring cooldown-reduction effects.

Historical source:

```text
Ahanlei123/2.8_live_data
commit f25e3155e38f9dc8f647493bf23a935147caf59e
txt/AvatarSkillData.txt
```

`900 s = 15 min`, matching Barbara C6's documented cooldown. This is strong continuity evidence, but it is still historical-only until the exact 7.1 `AvatarSkillExcelConfigData` row for skill `10076` is recovered.

Current status:

```text
PROBABLE: 10076 remains the cooldown carrier in 7.1.
UNKNOWN:  exact 7.1 skill-table fields / persistence flags.
UNKNOWN:  whether the official server independently validates or stores this cooldown.
```

## Network boundary

AstaPS exposes the normal client-to-server Ability path through `AbilityInvocationsNotify`: each client-provided `AbilityInvokeEntry` is passed to `AbilityManager.onAbilityInvoke()` and then forwarded according to its forward type.

That architecture proves that client-executed Ability state routinely crosses the C2S boundary, but the present evidence does **not** yet prove which concrete `AbilityInvokeArgument` carries Barbara's `ReviveAvatar` result in 7.1.

Therefore the current model is:

```text
CONFIRMED:
  client resource contains the C6 death-trigger and revive ability chain.

PROBABLE:
  the client executes the trigger/cooldown skill logic and reports resulting Ability state/invokes.

UNKNOWN:
  exact 7.1 AbilityInvokeEntry argument(s) produced by this chain.
  exact 7.1 AbilityInvocationsNotify opcode/type identity in the recovered registry.
  whether the server validates skill 10076 cooldown independently.
  whether the final authoritative LIFE_ALIVE transition is committed directly from the invoke
  or through a separate server-side life-state path after receiving it.
```

## AstaPS implication

AstaPS currently supplements this missing path with server-side `PartyReviveHelper` logic and a server-owned 15-minute cooldown. That is useful gameplay fallback, but it should not be treated as evidence of the official ownership model.

For protocol-faithful implementation, do not remove the fallback until the 7.1 invoke path is captured or statically identified. When that path is understood, the server should accept/validate the official revive transition without allowing duplicate revival from both the client-driven path and the fallback.

This also supports keeping generic damage/hit processing permissive: character abilities may depend on client Ability events around death, even when the associated combat event does not directly reduce HP.

## Next recovery steps

1. Recover the exact 7.1 `AvatarSkillExcelConfigData` entry for `10076`, plus `10079` and `10080`, and confirm the 900-second cooldown and persistence/share fields.
2. Capture or statically trace `AbilityInvocationsNotify` while Barbara C6 triggers.
3. Identify the emitted `AbilityInvokeEntry.argument_type`, entity id, head/ability identifier, and payload.
4. Recover the 7.1 CmdId/type for `AbilityInvocationsNotify` in the client registry.
5. Trace the receive-side handler from that invoke to the client's post-revive life-state handling.
6. Repeat once with C6 off cooldown and once while skill `10076` is still cooling down. Compare emitted invokes.
7. Test reconnect / scene transition during cooldown to determine whether cooldown persistence is client-local, server-restored, or both.

## Runtime validation target

A useful trace should contain this sequence around one lethal hit:

```text
victim reaches death state
Barbara is off-stage and C6 is installed
DoReviveMixin kill path fires
skill 10076 starts
revive-related AbilityInvokeEntry/entries are sent
server replies/forwards/synchronizes
victim transitions back to alive at full HP
skill 10076 remains unavailable for ~900 s
```

A second lethal hit during that window should show whether the client suppresses the revive chain before any C2S revive invoke is emitted.
