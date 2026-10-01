# Unresolved 7.1 protocol work

## Active

- `CmdId 186 / 0xBA` — C2S packet observed during fresh-account born/intro flow, payload `72 02 d0 27`; semantic type unresolved.
- `UnlockTransPointRsp` — request currently known as CmdId `9369`; response mapping requires current-client recovery and runtime validation.

## Rule

Do not promote a historical opcode or local generated proto field to `CONFIRMED` without matching current-client evidence.
