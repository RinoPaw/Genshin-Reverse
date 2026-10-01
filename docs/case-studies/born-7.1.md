# Genshin 7.1 born-protocol case study

This case study preserves the reusable results from the AstaPS `play/rino` born-flow investigation.

## Confirmed mappings

| Message | 7.1 CmdId | Structure / note |
| --- | ---: | --- |
| `DoSetPlayerBornDataNotify` | 22899 | empty |
| `SetPlayerBornDataReq` | 26105 | selected Traveler + nickname |
| `SetPlayerBornDataRsp` | 4385 | success can be empty; retcode is field 7 |
| `PlayerNicknameNotify` | 3064 | nickname is field 12 |
| `PlayerEnterSceneNotify` | 9582 | scene-entry lifecycle |

The important static result for `SetPlayerBornDataRsp` was a client `GetCmdId()` returning `0x1121` (`4385`), with its parser handling protobuf tag `0x38`, i.e. field 7 / varint. A minimal runtime experiment receiving `26105` and replying only with empty `4385` immediately allowed the naming stage to continue.

## Sample binding

The original analysis recorded:

```text
GenshinImpact.exe SHA256
08a3086d5f3fe695f01dab61efa42e442006b18e5e475b2520df356f6a073b7d

global-metadata.dat SHA256
05ae04d7a91b91cc880217a56b0b01f3e67f845b06e894216654ec5d160e0da0

PE ImageBase 0x140000000
```

## Useful anchors recovered

```text
GHAHAPOPLIH                         born naming page
  OnNotify      0x14BDEF5A0
  UpdateView    0x14BDEF640
  ClosePage     0x14BDEF7D0
  submit        0x14BDEE770

HJDNCHODGOL                         SetPlayerBornDataReq
  sender        0x14725CEF0
  CmdId         26105

ONKOPMILDMF                         DoSetPlayerBornDataNotify
  CmdId         22899

PlayerNicknameNotify handler        0x14C23BA20
SetPlayerNameRsp handler             0x14C2513A0
SetPlayerBornDataRsp GetCmdId        0x14A9E88B0
```

These addresses are sample-specific and should later be normalized into the versioned metadata/xref datasets.

## Failed paths worth preserving

- CmdId `4761` was tested as a candidate born response and rejected.
- `PlayerNicknameNotify (3064)` alone did not complete the born protocol.
- `4761 + 3064` also failed.
- invoking a broad `player.onLogin()` made the experiment noisy and introduced unrelated world/ability/quest behavior.

The strongest runtime probe was the smallest one: `26105 → persist → 4385 empty → stop`.

## General lesson

A correct individual response does not imply the whole gameplay lifecycle is complete. Protocol recovery and full born/world/quest sequencing should be validated as separate questions.
