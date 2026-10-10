## 2026-10-10: native quest-list receiver and guide pre-mask gate

Two read-only, exact-7.1 sample Actions succeeded: [call edges (38063931980)](https://github.com/RinoPaw/Genshin-Reverse/actions/runs/38063931980), [RVA disassembly (38064178431)](https://github.com/RinoPaw/Genshin-Reverse/actions/runs/38064178431).

- **Outer quest-update wire field verified.** AstaPS 7.1 `protocol.desc` declares `QuestListUpdateNotify.quest_list` as repeated message **field 7**. Exact-client `CmdId 3610 -> JDLMELOENCN` (typeDefinition 53289), native reader `JDLMELOENCN.NLGBJEEJDLG @ 0xA8AB0C0` tests protobuf tag **`0x3A` at `0xA8AB0F8`** (field 7, wire type 2). The *outer* field number matches; actual nested Quest data, nonempty entries, and tutorial execution remain unverified.
- **Receiving branch.** `HBBDJPCGCAH.GCLIDIPCOEH(JDLMELOENCN) @ 0xA5CE790` has four validated direct E8 callers (`0xA5CE342`, `0xA5CE6C7`, `0xA5ED89C`, `0xA606ABF`). Disassembly branches on receiver byte **`[rdi+0x2B5]` at `0xA5CE7A9`**. The nonzero branch reads the message list pointer `[rsi+0x18]` and tail-jumps to `HBBDJPCGCAH.PHFGNFBDFFH @ 0xA5D5220`; the other branch goes through an indirect-listener/queued path. Meaning of the flag and subsequent UI events **unresolved**.
- **Newer UI controller.** `CHLCICFENAG.Init @ 0xF57D0D0` invokes `BaseContextComponent.RegisterNotfiy` five times (RVA `0xF57D114/121/12E/13B/148`), indicating registered event-based callbacks. `CHLCICFENAG.OnNotify @ 0xF57CFF0` calls `JMKHJFFKJGF @ 0xF57A6C0`. There is no established link to the Mondstadt mandatory task-button guide or to the quest receiver: validated E8 edges are not exhaustive of event/delegate/Lua dispatch.
- **Input release remains distinct.** `InteractionManager.FinishCurrTalk @ 0xFE57430` directly calls `MOHDLCGJEHG.Finish @ 0x90FF4F0`, not `UnLockInter`. Do not conclude that a talk callback cleared every input-lock reason.
- **Next:** identify `[rdi+0x2B5]` semantic conditions and `PHFGNFBDFFH` dispatch; follow the client's `GlobalActor.StartGuide(string)` path/Lua task-button guide and distinct `ELockReason.QUEST_CHECK` lifecycle. Verify actual `35603` quest entry count + effective questing flag before proposing any server change.

These are static native facts, not proof that any specific guide method ran in the user's stuck session. The user reported **no visible BlackMask at all**, so investigate failure *before UI creation*, not a masked tutorial that merely awaits clicking.

# Amber 35601: no newbie mask, controls locked (7.1 exact-client study)

**Status: native metadata anchors verified; causal input-lock/guide chain not yet recovered.**  
**Observed client:** Global 7.1 Windows x64, `GenshinImpact.exe` SHA-256 `08a3086d5f3fe695f01dab61efa42e442006b18e5e475b2520df356f6a073b7d`.  
**Report:** On 2026-10-10, the player explicitly clarified that **no BlackMask appeared at all** after talking to Amber (`35601`); character controls locked immediately. This supersedes any implication that a visible mask was waiting for a click.

## Two transitions to investigate separately

1. **Interaction/input release:** Whether the inbound `NpcTalkRsp(3514)` invokes `InteractionManager.FinishCurrTalk(35601)` and then the actual control-release path. The pinned response receiver at RVA `0xA5E18C0` is already known to tail-call `FinishCurrTalk(uint32) @ 0xFE57430`; server response field 7 is correct and the sequence-echo experiment failed to fix the lock. Function existence alone does **not** show the callback executed in the stuck session.
2. **Tutorial UI creation:** Whether this talk/quest transition causes `MonoNewbieDialog` / `MonoNewbieMask` (or another tutorial UI) to initialize. The player reports that no visible guide mask is drawn, so do not describe the observed failure as a completed guide overlay whose button is unclickable. No causal call graph from Quest 35601 to this UI has yet been established.

These paths may be related, but a mask missing on screen does not demonstrate that the client entered any specific guide state. Equally, a false-valued InteractionManager C2S marker does not prove that gameplay input was released.

## Exact metadata anchors (7.1 Global Windows x64)

Extracted from the committed native `metadata/methods.csv`, `metadata/types.csv`, and `metadata/fields.csv`. These are **metadata identities and RVAs**, not disassembly of their bodies or evidence of runtime execution.

| Type (typeDefinition) | Native method and RVA | Relevant fields |
| --- | --- | --- |
| `MonoNewbieDialog` (24217) | `SetNewbieMaskIndex(int32) @ 0x9E2C4B0`, `Reset @ 0x9E2BC20`, `Awake @ 0x9E2C180` | `defaultAreaMask: MonoNewbieMask`, `areaMaskList`, `dialogCanvas`, `bgButton`, `inputKeyHint` |
| `MonoNewbieMask` (51604) | `set_showCompulory(bool) @ 0x1163D740`, `Reset @ 0x1163D8A0` | `blackMask: GameObject`, `compulsoryGrp: GameObject`, `focusAnimGrp` |
| `MonoNewbieDialogV2` (67242) | constructor `@ 0x1163D720` | `maskRoot`, `hintRoot`, `bannerRoot` |
| `MonoNewbieMaskV2` (44656) | constructor `@ 0x121FB7D0` | `blackMaskGroup`, `focusGroup`, `rectGroup` |
| `MonoGuideV2ClickTarget` (60391) | `OnPointerClick @ 0x7A577D0` | `onClick` delegate backing field |
| `InteractionManager` (84348) | `OnCreateTalkFinish @ 0xFE33B70`; `FinishCurrTalk @ 0xFE57430`; `ClearAfterInteractionFinish @ 0xFE3D630`; `ClearOnDisconnect @ 0xFE50930`; `ClearAfterKeyListFinish` (resolve RVA by exact metadata lookup) | Native per-interaction control flow requires direct-call and indirect-callback examination |

**Boundary:** `MonoGuideV2ClickTarget` may be a different generation of the tutorial system; its presence is not proof that it implements the early Mondstadt quest-button guide. Likewise, `MonoUIDisableInput` is a UI component, not evidence of this particular movement lock.

## Server data and exact test behavior

- The confirmed earlier failed test had `questing.enabled=true`, completed `35601`, started hidden `35602` and visible `35603`, then stayed unable to move until relog. A subsequent 21:45:37 diagnostic window (UID 70631) has the same quest/network/pause pattern; it does not itself explicitly assert the final movement result.
- `35603` includes `QUEST_GUIDE_LOCATION` with guide point `Q356Ambor4` in `AstaPS-Resource/BinOutput/Quest/356.json`. This is a **quest waypoint guide**, not proof of the mandatory *quest-button newbie mask* logic.
- `GuideTriggerExcelConfigData.json` contains OpenState-driven guides; keyword inspection does not independently identify the specific 35601 quest-button tutorial. Therefore do not assume that changing `OPEN_STATE_QUEST_REMIND (7)` will create a missing mask.
- The 21:45 log shows `7/8/16/17/24/60` absent from both explicit/default OpenState summary. It does not prove the client has them unlocked or that it entered a guide.
- C2S `27447` lacked bool field 7, which decodes to protobuf default false; source-bound code has several false sender paths. It cannot be used as an unconditional proof that the client cleared movement lock.
- `QuestManager.isQuestingActive()` requires `enableScriptInBigWorld && questing.enabled`. Verify transmitted QuestListUpdateNotify **entry counts** and effective flag, not only packet opcode counts.

## Targeted next native graph probe

Use the existing pinned native sample with `tools/trace_native_call_edges.py`, beginning with **callers** of the guide methods and the known response handler/interaction clearing methods:

```bash
python tools/trace_native_call_edges.py \
  inputs/7.1.0-global/GenshinImpact.exe \
  versions/7.1.0-global/windows-x64/metadata/methods.csv \
  /tmp/amber-newbie-call-edges.json \
  --focus newbie_mask_index:0x9E2C4B0 \
  --focus compulsory_mask:0x1163D740 \
  --focus newbie_mask_reset:0x1163D8A0 \
  --focus newbie_dialog_awake:0x9E2C180 \
  --focus talk_finish:0xFE57430 \
  --focus clear_after_inter:0xFE3D630 \
  --focus clear_on_disconnect:0xFE50930 \
  --focus guide_v2_click:0x7A577D0
```

The tracer only proves validated *direct E8* call sites, and does not resolve virtual dispatch, delegates, UI event bindings, Lua callbacks or indirect jumps. Inspect relevant method bodies and call-site state checks before promoting any claims.

**Promote only when established:** (a) which method turns on movement/input suppression after 35601, (b) which predicate leaves it enabled, (c) whether the newbie UI setup was skipped or failed, (d) what original state transition releases it, and (e) why reconnect resets it. Do not force-complete quests, enable all OpenStates, suppress tutorials globally, or invent missing guide opcodes.

## 2026-10-10 quest 35601 guide-entry source cross-check

Further source audit confirms the *no visible BlackMask* distinction and narrows—but does not settle—the tutorial-entry side:

- The 7.1 native metadata directly exposes `MoleMole.GlobalActor.StartGuide(string) @ 0xFE284A0` and `EndGuide(string) @ 0xFE28170` (typeDefinition 60967, method indices 490695/490692). These are possible Lua/script-mediated guide entry points; **no caller or relation to 35601 has been established**. Do not assume they are invoked at this handoff without native call-site or Lua-script evidence.
- In `RinoPaw/AstaPS-Resource/BinOutput/Quest/356.json`, subquest `35601` has `QUEST_CONTENT_COMPLETE_TALK(35601)` and **no `finishExec`**. The next steps are hidden `35602` (trigger 1126) and visible `35603` (location guide `Q356Ambor4`). The location guide is a quest objective marker, not the mandatory quest-button newbie overlay.
- `Scripts/Quest/Share/Q356ShareConfig.lua` lists subquests and NPC/position spawn data but does not call a guide API. This does **not** exclude client-side `Actor/Quest/AQ356` script activity: the Quest JSON points to that `luaPath`, and the shared config is not the full actor script.
- `GuideTriggerExcelConfigData.json` contains 171 guide-trigger rows, including later quest-hub/focus and OpenState-driven guides, but no entry identified as the specific 35601 quest-button compulsory mask. A negative name search is not evidence that the tutorial does not exist.
- Server `GameQuest.finish()` sends the 35601 quest-list update and applies any configured finish exec (none for this subquest). The server's `PacketShowClientGuideNotify` has unresolved opcode 0 in the exact 7.1 mapping, but this fact alone does not establish the packet is required for this transition.

**Next concrete evidence gate:** Recover the exact native call graph around `GlobalActor.StartGuide`, `MonoNewbieDialog.SetNewbieMaskIndex`, the guide controller `EPJNAHIFNCP.JOAGJNOIHDC`, and the `InteractionManager` lock-reason transitions; establish which component is supposed to run after the 35601 quest-list update and whether its inputs/conditions are satisfied. The absence of BlackMask makes the **entry/init path** the primary target. Keep quest visibility, OpenState changes and C2S 2178 as supporting probes only.

