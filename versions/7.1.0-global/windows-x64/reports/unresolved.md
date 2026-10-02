# Unresolved 7.1 protocol work

## Active

- [`CmdId 186 / 0xBA`](../analyses/cmdid-186/README.md) — repeated C2S packet during fresh-account born/intro flow. Current-client static identity is closed to `NLOMEGMJDGJ` / typeDefinition `61556`; concrete field-14 structure, sender context and semantic message name remain unresolved. Tracking issue: [#1](https://github.com/RinoPaw/Genshin-Reverse/issues/1).
- [`UnlockTransPointRsp`](../analyses/unlock-trans-point/README.md) — request currently known as CmdId `9369`; response mapping requires current-client recovery and runtime validation. The preserved case study keeps the surviving candidates and rejected heuristics explicit.
- [`Barbara C6 revive wire invoke`](../analyses/barbara-c6-revive/README.md) — current 7.1 Ability trigger/config and 900-second cooldown are config-confirmed, while the exact authoritative revive wire invoke remains unresolved.

## Ownership

This report is an index of open research questions, not a maintainer task list. Focused reverse-engineering work is owned by the researcher working the corresponding analysis/issue. Maintainers keep the evidence format, reusable tooling, publication gates and canonical datasets coherent, and review promotion when an investigation reaches its evidence threshold.

## Rule

Do not promote a historical opcode or local generated proto field to `CONFIRMED` without matching current-client evidence.
