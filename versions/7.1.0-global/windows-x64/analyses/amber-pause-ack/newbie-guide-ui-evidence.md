## Verified client StartGuide preflight gate (before mask creation)

A fresh read of the pinned exact-7.1 disassembly of `MoleMole.GlobalActor.StartGuide(string) @ 0xFE284A0` identifies a concrete **guide-start rejection branch**:

1. At `0xFE284B9`, the routine loads a guide manager pointer; when null, it reaches the failure return at `0xFE284F1`.
2. When the manager is present, `0xFE284D4` calls `IJLMKPGOMFD.IOGLEEMLMIF(string) @ 0x758D8C0` with the proposed guide name. `0xFE284D9` tests `AL`; if false, `0xFE284DB` branches to `0xFE284F1`, returning 0 **without starting the guide**.
3. If the predicate is true, `0xFE284EC` tail-jumps into `IJLMKPGOMFD.NJCMLBJMBGP(string,string) @ 0x758DBD0`, with its second string argument null. This is a downstream guide-start dispatch; its success and eventual BlackMask rendering are not proven by this branch alone.

The method identities and signatures are recovered from exact-client `metadata/methods.csv` (indices 490695, 206526, 206501 respectively), and instruction addresses from [pinned Quest/UI native disassembly (run 38064178431)](https://github.com/RinoPaw/Genshin-Reverse/actions/runs/38064178431).

**Important boundary:** We have not shown that the 35601 tutorial actually calls `GlobalActor.StartGuide`. If it does, a false predicate or missing manager would explain why **no BlackMask was created**, but still would not directly establish which `InteractionManager` lock reason remained active.

The read-only research probe has therefore been extended to record the `StartGuide` request, the **actual native predicate result** (`0x758D8C0` return `AL`), and downstream dispatch entry (`0x758DBD0`) on the same timeline as input lock/unlock. It currently has **14 hooks** and has not been runtime-tested. The probe never forces the predicate or manually unlocks the client.

## Prepared read-only 7.1 client lock/guide event capture (not yet runtime-tested)

The research branch now contains [`capture_amber_guide_locks_71.py`](../../../../../tools/runtime/capture_amber_guide_locks_71.py) and [`capture_amber_guide_locks_71.js`](../../../../../tools/runtime/capture_amber_guide_locks_71.js), a narrow **prototype** to record, in one monotonic timeline, exact 7.1 native entries for:

- `NpcTalkRsp` receiver `0xA5E18C0` and `InteractionManager.FinishCurrTalk` `0xFE57430` (talk ID);
- `InteractionManager.LockInter` `0xFE508D0` and `UnLockInter` `0xFE552F0` (numeric enum values **without guessing names**);
- `GlobalActor.StartGuide` `0xFE284A0` and `EndGuide` `0xFE28170` (bounded native string);
- `MonoNewbieDialog.SetNewbieMaskIndex` `0x9E2C4B0`, `MonoNewbieMask.set_showCompulory` `0x1163D740`, and the quest-list receiver `0xA5CE790`;
- optional verbose `EPJNAHIFNCP.OnNotify` `0x89FC100` and compulsory guide controller `0x89F7080`.

The launcher calls `require_profile_exe` with pinned `PROFILE_71` before attaching and stores NDJSON without packet bodies or authentication tokens. It only records method-entry events; it **does not bypass input locks, alter client state, or send packets**. The actual running process must use the same binary as the hash-verified `--exe` path. Neither the hook ABI nor real game compatibility is verified until a controlled client run and project CI; **do not ask for a new reproduction yet**.

Causal decision table for that eventual capture: (a) `FinishCurrTalk` absent after the 3514 receiver means talk callback path needs examination; (b) talk callback present, but a newly acquired lock reason lacks a matching release means follow that reason's owner; (c) `StartGuide` observed without `SetNewbieMaskIndex`/visible mask means follow guide initialization; (d) no guide event at all means investigate the 35601 quest-notify-to-Lua/UI handoff. Because hooks begin at attach time, absence of a `LockInter` event cannot prove no lock was acquired **before** attachment.

## Exact 7.1 UnLockInter(1) owners: event-dependent releases

Re-read the pinned 7.1 [unlock-owner native probe (run 38060685595)](https://github.com/RinoPaw/Genshin-Reverse/actions/runs/38060685595). It validates three **distinct direct callers** of `InteractionManager.UnLockInter(ELockReason) @ 0xFE552F0`; each passes numeric `edx=1`, but metadata alone does not prove whether enum value 1 is `QUEST_CHECK` or `UI_CLOCK`.

- `IBOJCEGJPEM.IFMMKPLAMEL @ 0xCB9FD90`: checks local byte flag `[this+0x13]` at `0xCB9FDA1`; calls `UnLockInter(1)` at `0xCB9FDBF` **only if that flag was set** and a manager pointer exists; finally clears the flag at `0xCB9FDC4`.
- `IBOJCEGJPEM.HOACAKEFEEN @ 0xCBA02B0`: a broader reset path; checks the same local flag at `0xCBA02DF`, conditionally calls `UnLockInter(1)` at `0xCBA02FD`, then clears local flags at offsets `+0x13`, `+0x12`, `+0x10` (and `+0x11` earlier).
- `DDDKDOPHINB.LDOPCEKPOBN @ 0x11C9AD90`: invokes a separate helper `0xBA004B0`, performs lookups, and calls `UnLockInter(1)` at `0x11C9AE63`; its type has `Notify` and `Action` members. It subsequently dispatches an `Action` through an indirect jump at `0x11C9AEB9`. A `Notify` member and an indirect dispatch are **not** by themselves proof of a tutorial event or callback.

None of these owner methods has a validated direct E8 caller. Therefore a callback/indirect path remains plausible; their runtime activation after `35601` is still unknown. The first two paths establish an important static property: **release of numeric lock reason 1 is conditional on local UI/controller state**. If its expected state never initializes, observing no BlackMask would be compatible with no unlock callback. This is a hypothesis, not a demonstrated AstaPS bug.

**Next gate:** map the exact enum constants and owner `IBOJCEGJPEM` lifecycle to the original `35601` tutorial event, and find which code calls `LockInter` or inserts that lock reason. Never force an unconditional `UnLockInter(1)` without establishing the matching acquisition and trigger.

## Exact 7.1 native pre-mask branching: separate UI compatibility and mask setup

A bounded review of the exact-hash native disassembly/call-graph artifacts adds the following **direct control-flow facts**, without proving any of these methods executed after Amber's talk:

- `EPJNAHIFNCP.SetupView @ 0x89FB050` checks `HOJDOIALMHI.EAEPAEOMOJI(0x1A3D) @ 0x8CEC570` at callsite `0x89FB10A`. When its return value is false, the method invokes `MonoNewbieDialog.SetNewbieMaskIndex(-1) @ 0x9E2C4B0` at `0x89FB124` (subject to a nonnull view at `[rsi+0x220]`). This is a **concrete mask-clearing path**; the meaning of argument `0x1A3D` and its relationship to the Mondstadt task-button guide are **unknown**.
- `EPJNAHIFNCP.OnNotify @ 0x89FC100` has two distinct branches (callsites `0x89FC1F3/1FB` and `0x89FC284/28C`) that call `EPJNAHIFNCP.DEMHBOJPEPK` followed by `EPJNAHIFNCP.EEBOFEGNDIG` (guide state application and refresh). This confirms an event-driven refresh **path**, not which event name causes the 35601 transition.
- `EEBOFEGNDIG @ 0x89F9AF0` calls `MonoNewbieDialog.SetNewbieMaskIndex(-1)` at `0x89F9B87`, after checking the dialog at `[rsi+0x220]` and its index field `[dialog+0x140]`. It can clear the visible mask on a different path from `SetupView`.
- The compulsory-guide UI method `EPJNAHIFNCP.JOAGJNOIHDC @ 0x89F7080` has **separate** calls: `EasyTouch.SetUICompatibily @ 0x6FAB8A0` at `0x89F7625`, and `MonoNewbieMask.set_showCompulory @ 0x1163D740` at `0x89F7693`. The latter receives the result of `currentStage != 3` (comparison at `0x89F7688`). The former is conditional on state `[r13+0x88]` and is invoked with argument 0. Because `EasyTouch` is not a proven Windows movement-lock controller, **do not infer** that it explains the player's inability to move.

**Implication / next gate:** No BlackMask is fully compatible with a client-side branch that chooses mask index -1, but it does **not** establish why the separate `InteractionManager._lockedReasonSet` still suppresses control. Continue by identifying the `SetupView` `0x1A3D` predicate, the actual event dispatched after `QuestListUpdateNotify(35601)`, and which code adds/removes `ELockReason.QUEST_CHECK`. These guide-v1 functions have no established 35601 caller or runtime execution proof. Do not ship an unlock or open-state patch from these findings alone.

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

