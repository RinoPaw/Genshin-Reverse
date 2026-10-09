# RPG progression proposal based on Genshin Impact 7.1

Status: `DESIGN DRAFT`

This proposal is intentionally separate from the native baseline.

## Design principle

Preserve the original RPG progression curve first, then remove real-world time gates.

Do not reduce material requirements before the native 7.1 drop economy is known.

## First-pass proposal

- Keep native character level/EXP curves.
- Keep native character ascension costs.
- Keep native weapon progression curves and costs once extracted.
- Keep native talent progression costs once extracted.
- Keep native artifact enhancement/randomization rules once fully verified.
- Original Resin no longer gates reward eligibility.
- One completed battle grants one native base reward claim.
- Do not enable unlimited multi-reward claiming by default.
- Remove Weekly Boss real-world weekly reward-claim limits while preserving boss difficulty and native drop tables.
- Open weekday-rotating material Domains every day.
- Remove other real-time refresh gates one by one rather than through a single catch-all switch.
- Client Resin UI may remain temporarily; server-side reward gating can ignore it.

## Why one battle should normally equal one base reward

The purpose is to remove waiting, not to remove gameplay.

If unlimited 2x/3x claiming remains available after Resin removal, combat count can collapse and the native farming loop loses meaning. Until reward averages are fully extracted, use one battle -> one base reward as the conservative RPG baseline.

## Systems that should become independent server switches

- Original Resin reward gate.
- Multi-reward / Condensed Resin.
- Weekly Boss reward limit.
- Weekly Boss Resin discount.
- Weekday Domain availability.
- Boss respawn.
- Reward respawn.
- Daily reset-dependent rewards.
- Weekly reset-dependent rewards.

## Required validation before balancing

Complete `7.1-native-drop-economy.md` first, then calculate pure battle counts for:

- character 1 -> 90;
- talents 10/10/10;
- 5-star weapon 1 -> 90;
- artifact enhancement.

Only after those battle counts are known should material requirements or reward yields be rebalanced.
