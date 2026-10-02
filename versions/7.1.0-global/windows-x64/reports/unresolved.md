# Unresolved 7.1 protocol work

## Active

- `CmdId 186 / 0xBA` — C2S packet observed during fresh-account born/intro flow, payload `72 02 d0 27`; semantic type unresolved.
- `UnlockTransPointRsp` — request currently known as CmdId `9369`; response mapping requires current-client recovery and runtime validation.

## Ownership

This report is an index of open research questions, not a maintainer task list. Focused reverse-engineering work is owned by the researcher working the corresponding analysis/issue. Maintainers keep the evidence format, reusable tooling, publication gates and canonical datasets coherent, and review promotion when an investigation reaches its evidence threshold.

## Rule

Do not promote a historical opcode or local generated proto field to `CONFIRMED` without matching current-client evidence.
