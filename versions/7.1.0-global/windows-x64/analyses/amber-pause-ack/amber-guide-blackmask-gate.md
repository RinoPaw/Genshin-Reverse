# Amber 35601: no black mask before input lock (Global 7.1)

Status: **research in progress; not a confirmed root cause**. Target: exact 7.1.0 Global / Windows x64 GenshinImpact.exe SHA-256 `08a3086d5f3fe695f01dab61efa42e442006b18e5e475b2520df356f6a073b7d`. The user specifically observed **no tutorial black mask at all** in the stuck session. Unlike the normal client, where the quest-button tutorial visibly dims the screen after Amber's first conversation, the AstaPS client loses controls without the visible overlay. This favors investigation of the **pre-display handoff** before assuming a displayed tutorial is merely awaiting clicks.

## Source-backed entry points

Exact-client canonical registry and recovered metadata, not generic opcode-name inference:

| Path | Native identity / RVA | Scope |
| --- | --- | --- |
| S2C `NpcTalkRsp(3514)` | `IMLLBMOMMEH`; `HBBDJPCGCAH.JCIMEKEEFOH @ 0xA5E18C0` → `InteractionManager.FinishCurrTalk(uint32) @ 0xFE57430` | Direct handler-to-finish call confirmed by prior native disassembly. Does not prove the call ran in the stuck session. |
| S2C `QuestListUpdateNotify(3610)` | `JDLMELOENCN` (type definition 53289); `HBBDJPCGCAH.GCLIDIPCOEH(JDLMELOENCN) @ 0xA5CE790` | **Signature / registry identity only**. Need disassembly to establish what it actually updates. |
| Client talk-finish event | `InteractionManager.OnCreateTalkFinish(...) @ 0xFE33B70` | Metadata method identity, no connection to tutorial proven. |
| Older newbie overlay control | `MonoNewbieDialog` (type 24217), `MonoNewbieMask` (51604), controller `OEGGKJOHMOP` (14629) | Metadata references and class fields; could be independent of the specific task-button guide. |
| Newer newbie overlay control | `MonoNewbieMaskV2` (44656), `MonoNewbieMaskContainer` (41793), controller `CHLCICFENAG` (39270) | Controller methods `Init @ 0xF57D0D0`, `OnNotify @ 0xF57CFF0`, `OnInputHotSwap @ 0xF57CC90`, `Destroy @ 0xF57C300`; native metadata, not yet tied to quest 35601. |
| Mask UI click | `MonoGuideV2ClickTarget.OnPointerClick @ 0x7A577D0` | Candidate client-only guide completion action; no relation to this guide established. |

The newer mask's verified fields include `rectGroup`, `focusGroup` and **`blackMaskGroup`**, and the old mask has a `blackMask` field. Neither class's existence establishes which variant the Amber guide uses. **Do not infer input-lock ownership just from these names.**

## Server observations and boundaries

- Dialogue `35601` completes, `35602` and `35603` begin. The 21:45 UID 70631 log has no black-mask client observation in the log itself; absence of the overlay comes from the user's direct gameplay report.
- `GameQuest.start()` constructs `PacketQuestListUpdateNotify` when 35602/35603 begin, but the packet condition uses `QuestManager.isQuestingActive()`, which requires `enableScriptInBigWorld && questing.enabled`. Effective value and actual packet entry count were not logged during the earlier capture.
- `OpenState` 7, 8, 16, 17, 24 and 60 are absent in the saved/default server state at the handoff; 1 and 2 were `stored:1`. An omitted state is **not** proof of either an unlocked quest button or a particular client guide state.
- C2S CmdId `2178` appeared 32ms after talk in the new capture. Registry resolves it to `LIGFLGNNAHP` (definition 83525), but its meaning is unknown. Keep it secondary to guide-entry and dialogue-cleanup analysis.

## Focused native evidence gate

Run `trace_native_call_edges.py` on the pinned sample for (a) talk-response handler / FinishCurrTalk, (b) quest-list-update receiver, (c) pre-display newbie mask controller and UI callbacks. Identify whether the quest handler invokes the guide manager, whether `FinishCurrTalk` preserves a lock pending a subsequent event, and what opens the overlay. Direct call graphs cannot establish virtual/delegate/event-bus transitions; if absent, explicitly record the boundary and follow receiver registration / notify dispatch next.

**Do not change OpenState 7, force quest completion, or submit upstream patches on this static evidence alone.**
