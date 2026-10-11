# Amber 35601: quest-button guide does not show its blackmask (7.1 Global)

Status: **NATIVE GUIDE ENTRY/VIEW PATHS IDENTIFIED; 35601-SPECIFIC TRIGGER AND INPUT-LOCK CAUSE UNRESOLVED**.

## Observations, deliberately separated from inference

The player reports that after the first Amber conversation (`35601`) **the mandatory quest-button tutorial blackmask never appears**, and input immediately stops working. This is more specific than an unusable *visible* guide. The client resumes after process restart/reconnect. AstaPS finishes 35601, starts 35602 (hidden) and 35603 (visible), and keeps exchanging packets with the client. The server is not world/player paused. Sequence-number repair has been tested and did **not** resolve the symptom.

The 2026-10-10 21:45:37 (UTC+8, UID 70631) 45-second sample recorded `questing.enabled=true`, stored OpenState `1=1,2=1` and absent 7/8/16/17/24/60, with no decoded `SetOpenStateReq` / `OpenStateChangeNotify` during the trace. `enableScriptInBigWorld`, which also gates effective `QuestManager.isQuestingActive()`, was not captured. The 45-second sample alone does not prove that the client received a usable `35603` quest entry. On the other hand, when effective questing really is enabled, the current server `GameQuest.start() → PacketQuestListUpdateNotify(GameQuest)` *does* include unfinished 35603. Do not infer an empty quest list merely from the lack of UI.

## Exact 7.1 native guide lifecycle (source-bound)

Executable SHA-256: `08a3086d5f3fe695f01dab61efa42e442006b18e5e475b2520df356f6a073b7d`. Metadata SHA-256: `05ae04d7a91b91cc880217a56b0b01f3e67f845b06e894216654ec5d160e0da0`.

Hosted native call-edge/disassembly runs: [38107260146](https://github.com/RinoPaw/Genshin-Reverse/actions/runs/38107260146), [38107396455](https://github.com/RinoPaw/Genshin-Reverse/actions/runs/38107396455). They use the pinned sample fetched by `scripts/fetch-7.1-samples.sh`, hash-verified, and `tools/trace_native_call_edges.py` with current `metadata/methods.csv`.

* `GlobalActor.StartGuide(string) @ 0xFE284A0` calls `IJLMKPGOMFD.IOGLEEMLMIF(string) @ 0x758D8C0` at `0xFE284D4`; **only if it returns true** does it tail-call `IJLMKPGOMFD.NJCMLBJMBGP(string,string) @ 0x758DBD0` at `0xFE284EC`. Hence there is a native **pre-start gate** before the guide starts. The exact meaning of that gate (e.g. availability/config/progression) has not been established. `GlobalActor.StartGuide` is exposed via `MoleMoleGlobalActorWrap._m_StartGuide @ 0xC70CCF5`; direct-CALL scans cannot see originating Lua script calls.
* `GlobalActor.EndGuide(string) @ 0xFE28170` tail-calls `IJLMKPGOMFD.LMFFKFCOKFO(string,bool) @ 0x75901A0` at `0xFE2819D`, passing false. `IJLMKPGOMFD.OnNotify @ 0x75905C0` calls internal guide lifecycle helpers, and `ClearOnDisconnect @ 0x7590B60` tails into `HOACAKEFEEN @ 0x758F2F0`. This establishes a guide-state reset path on disconnect; **it does not prove this reset is the particular reason movement recovers**.
* The original `MonoNewbieMask` component contains `blackMask` and `compulsoryGrp` GameObjects (exact pinned metadata fields). Its `set_showCompulory(bool) @ 0x1163D740` has a validated direct caller `EPJNAHIFNCP.JOAGJNOIHDC @ 0x89F7693`. `EPJNAHIFNCP.JOAGJNOIHDC @ 0x89F7080` directly calls `MonoNewbieDialog.SetNewbieMaskIndex(int) @ 0x9E2C4B0` at `0x89F714F`. `EPJNAHIFNCP.SetupView @ 0x89FB050` calls `SetNewbieMaskIndex` at `0x89FB124`. These give an **actual guide-view and blackmask path**, distinct from the `GlobalActor.StartGuide` gate.
* `BaseInputAdapter.UpdateInputDisable(bool,InputAdapterDisableSource) @ 0xAC528D0` updates a bitfield at `+0x1C` (BTS/BTR), then sets the input-disabled byte at `+0x18` from `mask & 7 != 0`. A separate `UpdateDisableInputMask @ 0xAC529B0` updates the same mask. This confirms client input can be blocked without proving guide UI ever mounted; the exact disable-source used at 35601 is unresolved.
* `MonoBaseCanvas.SetBlockInputMaskEnable @ 0x9152EB0` controls a distinct canvas mask; no direct caller was established. Do **not** equate this canvas mask with the Amber input lock by name only.
* `NpcTalkRsp(3514)` client callback at `0xA5E18C0` tail-calls `InteractionManager.FinishCurrTalk(uint32) @ 0xFE57430`, reading protobuf field 7 (already correctly set by AstaPS). An RPC sequence header correction was tested and did not release input.

## Guide startup, blackmask and cleanup are different checkpoints

The native evidence permits three distinct failure classes: (1) conversation input-lock release fails before the guide starts; (2) the guide pre-start gate refuses a request, leaving a previous lock; (3) the guide starts, but UI view/mask setup never mounts. **No current-client evidence binds any one of these to `35601` yet**.

Original `BinOutput/Quest/356.json` includes `luaPath=Actor/Quest/AQ356`, but the checked `RinoPaw/AstaPS-Resource` tree does not contain that client Lua quest actor. The visible QuestExcel row `35601` has a COMPLETE_TALK finish condition and no explicit finishExec showing a `StartGuide` call. The generic `GuideTriggerExcelConfigData` and `GuideV2ClientTriggerExcelConfigData` checked here do not establish an Amber guide definition/name. Thus the missing link is **the actual 35601 script/guide name and the corresponding guide manager precondition**, not an invented S2C tutorial message.

7.1 registry structurally maps the time-adjacent inbound `CmdId 2178` to `LIGFLGNNAHP`, type definition 83525, registry index 516, one `uint32` metadata field. Its semantic identity is still unknown. Do not promote it to a tutorial opcode based on timing.

Historical [Grasscutter quest notes](https://cocalc.com/github/Grasscutters/Grasscutter/blob/development/docs/quests/lines/The-Outlander-Who-Caught-the-Wind-%28Prologue-Act-1%29.md) mention a possible `35602` softlock during tips, but are about an older client, not proof for 7.1.

## Next evidence gate before a gameplay-affecting fix

Recover `Actor/Quest/AQ356` (or independently identify its exact 7.1 guide request / name), inspect `IJLMKPGOMFD.IOGLEEMLMIF` return conditions for that name and correlate with `EPJNAHIFNCP.SetupView`. Instrument `QuestListUpdateNotify` *entry count* and the **effective** `QuestManager.isQuestingActive()` flag at 35601/35603, before claiming quest list visibility is causal. Pin the native input-disable *source* at the dialogue boundary if possible. Only then make a bounded server change with tests and CI.

Do **not** force finish 35602, mass-unlock OpenState7, bypass the guide, fabricate ShowClientGuideNotify opcode, or revisit sequence/pause fixes as a purported root-cause solution.
