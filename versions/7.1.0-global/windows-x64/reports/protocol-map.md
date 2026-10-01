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
| UNKNOWN_186 | 186 | C2S | UNRESOLVED | repeated runtime observation; field 14/wire 2 payload shape |

## Data completeness

The committed registry is a seed. Preserved audit evidence states that an earlier complete recovery contained **4,896 unique CmdIds**, and all **1,540 known AstaPS opcode values** were present. The full generated files and generator were not preserved, so those counts are treated as historical recovery evidence until regeneration reproduces them.
