# Unresolved 7.1 protocol work

## Active

- [`CmdId 186 / 0xBA`](../analyses/cmdid-186/README.md) — repeated C2S packet during fresh-account born/intro flow. Current-client static identity is closed to `NLOMEGMJDGJ` / typeDefinition `61556`, and field 14 is closed as packed repeated `uint32` with the observed payload `[5072]`. Sender/context recovery and the semantic message name remain unresolved. Tracking issue: [#1](https://github.com/RinoPaw/Genshin-Reverse/issues/1).
- [`Barbara C6 revive wire invoke`](../analyses/barbara-c6-revive/README.md) — current 7.1 Ability trigger/config and 900-second cooldown are config-confirmed, while the exact authoritative revive wire invoke remains unresolved. Tracking issue: [#4](https://github.com/RinoPaw/Genshin-Reverse/issues/4).

## Paused

- [`UnlockTransPointRsp`](../analyses/unlock-trans-point/README.md) — request is confirmed as CmdId `9369`; static recovery is tied between S2C candidates `36641 / NCBEHBOCBJJ` and `20290 / MAFFAFNMEBM`. Corrected `ScenePointUnlockNotify` closes the current AstaPS waypoint gameplay path, and ACK/no-ACK controls show no observed gameplay dependency on the unresolved response. Resume only if gameplay requires it, an official-current capture becomes available incidentally, or new static evidence creates a unique semantic binding. If resumed, promotion requires a known-correct transaction with exactly one candidate sharing the request `PacketHead` sequence value.

## Ownership

This report is an index of open research questions, not a maintainer task list. Focused reverse-engineering work is owned by the researcher working the corresponding analysis/issue. Maintainers keep the evidence format, reusable tooling, publication gates and canonical datasets coherent, and review promotion when an investigation reaches its evidence threshold.

## Rule

Do not promote a historical opcode or local generated proto field to `CONFIRMED` without matching current-client evidence.
