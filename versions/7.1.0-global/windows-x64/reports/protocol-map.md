# 7.1 protocol map

This report summarizes only mappings with current 7.1 evidence. Machine-readable sources live under `registry/`, `proto/`, `metadata/`, and `xrefs/`.

| Message | CmdId | Direction | Status | Key evidence |
| --- | ---: | --- | --- | --- |
| DoSetPlayerBornDataNotify | 22899 | S2C | CONFIRMED | registry type `ONKOPMILDMF`; born UI handler chain; runtime |
| SetPlayerBornDataReq | 26105 | C2S | CONFIRMED | type `HJDNCHODGOL`; GetCmdId `0x10587260`; sender `0x725CEF0`; runtime |
| SetPlayerBornDataRsp | 4385 | S2C | CONFIRMED | GetCmdId + parser field 7 + isolated runtime response |
| PlayerNicknameNotify | 3064 | S2C | CONFIRMED | client handler/parser + runtime synchronization |
| PlayerEnterSceneNotify | 9582 | S2C | CONFIRMED | scene lifecycle/runtime |
| UnlockTransPointReq | 9369 | C2S | CONFIRMED | current handler/runtime anchor |
| UNKNOWN_186 | 186 | C2S | UNRESOLVED | static identity `NLOMEGMJDGJ` / tdef `61556`; repeated runtime field-14/wire-2 observation; semantic name unresolved |

## Data completeness

The 7.1 identity infrastructure is now regenerated and published rather than seed-only:

- `registry/registry.csv` contains the complete **4,896-row / 4,896-unique-CmdId** canonical identity registry with a strict slot/type/CmdId bijection;
- canonical metadata contains **88,904 types, 440,172 fields, 733,442 methods and 733,442 method-pointer rows**;
- `registry/control-set.csv` is the current broad AstaPS-imported comparison/control surface and remains supporting evidence rather than a source of target-client semantic truth;
- evidence-gated target-client semantic names are maintained separately in `proto/known-opcodes.csv`.

Focused investigations can therefore start from the canonical registry and metadata indexes. Remaining unresolved work is semantic/parser/xref/runtime evidence, as indexed in `reports/unresolved.md` and the corresponding analysis directories/issues.
