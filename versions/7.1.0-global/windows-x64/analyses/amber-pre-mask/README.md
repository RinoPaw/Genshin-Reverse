# 7.1 Amber 35601 input lock before newbie mask

**Status:** active native-client investigation. AstaPS UID 70631 was observed after `NpcTalkRsp(35601)` with `35602/35603` newly started, an unpaused world and continued network traffic; earlier replays confirmed stuck input. **The user explicitly reports that no dark newbie mask/blackmask appears before controls stop responding.** This observation shifts priority to the transition **between the talk-ending callback, input lock, and guide UI creation**, rather than a guide mask already visible but stuck.

## Source-verified static anchors

Pinned Global 7.1 Windows x64 executable SHA-256:
`08a3086d5f3fe695f01dab61efa42e442006b18e5e475b2520df356f6a073b7d`.
Entries below are decoded **client metadata type/method/field identities only**. Native control-flow/cause has **not** yet been verified by an xref/disassembly.

| Component / function | Type index | Method RVA / field |
| --- | ---: | --- |
| `InteractionManager.FinishCurrTalk(uint32)` | 84348 | `0xFE57430` (prior native response-handler analysis) |
| `NpcTalkRsp` handler | — | `HBBDJPCGCAH.JCIMEKEEFOH @ 0xA5E18C0` (prior proven direct callback) |
| `MonoNewbieDialog.SetNewbieMaskIndex(int32)` | 24217 | `0x9E2C4B0` |
| `MonoNewbieMask.blackMask` | 51604 | field index 258379 |
| `MonoNewbieMask.compulsoryGrp` | 51604 | field index 258384 |
| `MonoNewbieMask.set_showCompulory(bool)` | 51604 | `0x1163D740` |
| `OEGGKJOHMOP.NGAMKMPIGHC(MonoNewbieMask)` | 14629 | `0xCB9BAB0` |
| `OEGGKJOHMOP.NGAMKMPIGHC(MonoNewbieMask,uint32,EDHAIIJJGAP)` | 14629 | `0xCB9BD70` |
| `CHLCICFENAG.Init(GameObject)` | 39270 | `0xF57D0D0` |
| `CHLCICFENAG.OnNotify(Notify)` | 39270 | `0xF57CFF0` |
| `CHLCICFENAG.OJMHHIOHJJP(MonoNewbieMaskV2,ACJBHCGDOEB)` | 39270 | `0xF57A550` |
| `MonoNewbieMaskV2.blackMaskGroup` | 44656 | field index 223153 |

The native metadata explicitly exposes both V1 and V2 mask components. This **does not prove** that the Amber tutorial uses either specific controller. The branch's focused native callgraph is intended to establish callers and sequencing with exact executable hash.

## Resource-side cross-check

- `AstaPS-Resource/BinOutput/Quest/356.json` has no `finishExec` for `35601`, and its successor `35603` is the visible unfinished guided-location task; `35602` is hidden. Thus the server's key handoff is quest state/notify, with other client-local guide triggering still unresolved.
- `TutorialExcelConfigData.json` entry `id=356` is **not Amber**; `TutorialDetailExcelConfigData.json` identifies `detailId=35601` as `UI_InazumaTutorial_ElecMagnetGear`. The matching number is accidental.
- `GuideV2ExcelConfigData.json` and `GuideV2ClientTriggerExcelConfigData.json` concern a small set of named guides, not a confirmed Amber newbie entry. `GuideTriggerExcelConfigData.json` is not proof that the quest-button onboarding mechanism uses those rows.
- The 21:45 server snapshot reports `OpenState 7=absent`, as well as 8/16/17/24/60 absent. This is server map/default absence, **not native-client UI-state proof**.

## 2026-10-10: Exact-client native xrefs (verified)

The pinned 7.1 workflow [run 38065483298](https://github.com/RinoPaw/Genshin-Reverse/actions/runs/38065483298) completed successfully and saved `amber-pre-mask-guide-callgraph-71`. A further [run 38065540799](https://github.com/RinoPaw/Genshin-Reverse/actions/runs/38065540799) repeated the expanded scan. All entries below have native direct-call instruction and metadata owner evidence; **none establishes that the Amber tutorial specifically uses these classes**.

1. `EPJNAHIFNCP` (type index 74707) is a candidate V1 newbie **view controller**, because it holds a `MonoNewbieDialog` field, and its `SetupView @ 0x89FB050` invokes `MonoNewbieDialog.SetNewbieMaskIndex @ 0x9E2C4B0` at RVA `0x89FB124`. Its `ClearView @ 0x89F9600` invokes `MonoNewbieDialog.Reset @ 0x9E2BC20` at `0x89F9629`. `SetupView` can return early at `0x89FB0D1` when a required UI object is null; the real gameplay branch remains unobserved.
2. The same class method `EPJNAHIFNCP.JOAGJNOIHDC @ 0x89F7080` calls `MonoNewbieDialog.SetNewbieMaskIndex` (`0x89F714F`), `EasyTouch.SetUICompatibily @ 0x6FAB8A0` (`0x89F7625`), and `MonoNewbieMask.set_showCompulory @ 0x1163D740` (`0x89F7693`). This **proves UI-touch configuration and compulsory-mask visibility are coordinated in one client routine**, but does not prove whether the input is locked before the mask is hidden or why either change occurs. The `EasyTouch` name alone cannot establish a stuck-input mechanism.
3. `EPJNAHIFNCP.OnNotify @ 0x89FC100` handles notify IDs `0x1e9`, `0x1ea`, `0x1f2`, `0x1f3` and calls two own methods (`DEMHBOJPEPK @ 0x89FB1B0`, `EEBOFEGNDIG @ 0x89F9AF0`). These IDs currently have **no verified quest/tutorial semantic names**. Virtual notification registration does not show as an ordinary direct E8 call.
4. Another controller `CHLCICFENAG` (type index 39270) holds V2 newbie-mask methods. `Init @ 0xF57D0D0` registers five notifications `0x1e9`, `0x1ea`, `0xc0d`, `0x3e0`, `0x3dd` and immediately calls its `JMKHJFFKJGF @ 0xF57A6C0`. `OnNotify @ 0xF57CFF0` calls the same method after matching those types. V1/V2 sharing `0x1e9/0x1ea` is a cross-controller clue, **not a claim that either is used for the Amber prompt**.
5. `NpcTalkRsp` receiver and `InteractionManager.FinishCurrTalk @ 0xFE57430` remain connected by the previously confirmed tail jump; `FinishCurrTalk` has confirmed calls to `InteractionManager.RefreshNpcTalkManual @ 0xFE4FAF0`, `MOHDLCGJEHG.Finish @ 0x90FF4F0` and `InteractionManager.DestroyMarkedNPC @ 0xFE470F0`. The native callgraph has **not found a direct call edge from the talk-ending routine to the studied newbie-mask controller**; event/virtual/context transitions still need mapping.

**Next evidence gate:** Determine which guide context is triggered by the `35601 FINISHED → 35603 UNFINISHED` transition and locate the *effective player input-disable transition*, then establish its execution order relative to the newbie view's `SetupView`/mask activation. Only the same guide instance/transition can explain the missing blackmask. Do not modify the server on these xrefs alone.

## 2026-10-10: Verified ordering inside candidate V1 compulsory guide state

The expanded [run 38065838364](https://github.com/RinoPaw/Genshin-Reverse/actions/runs/38065838364) succeeded (CI for commit `9c92de6e` also [passed](https://github.com/RinoPaw/Genshin-Reverse/actions/runs/38065838320)). It confirms the `EasyTouch.SetUICompatibily @0x6FAB8A0` native routine has **one validated direct E8 caller** in the scanned executable: `EPJNAHIFNCP.JOAGJNOIHDC @ 0x89F7625`. This setter gets the EasyTouch singleton and stores its bool parameter into object byte offset `+0x82` at `0x6FAB8E2`; the true meaning of that flag and all indirect callers have not been established.

The caller executes `xor ecx,ecx` at `0x89F7623`, then `call EasyTouch.SetUICompatibily` at `0x89F7625`. On that branch the client therefore **writes false to its EasyTouch compatibility flag**. This call is conditional on a nonzero flag at candidate controller state `[r13+0x88]` and a global initialized-state check; it is not necessarily executed on every newbie guide.

**Proven instruction order in this one routine:** the EasyTouch setter call at `0x89F7625` precedes `MonoNewbieMask.set_showCompulory` at `0x89F7693`. The latter receives `[r13+0x74] != 3` (`cmp ... 3; setne dl`), so **state 3 explicitly passes false to the compulsory-mask setting**. Therefore the machine code admits a path where the compatibility flag is set false and compulsory-mask visibility is set false afterward—*a useful mechanism to investigate in light of the reported missing blackmask*. It is **not evidence that Amber 35601 takes this branch, or that this flag alone freezes player controls**.

Also recovered: `EPJNAHIFNCP.OnNotify @0x89FC100` directly calls the controller's event transition method `DEMHBOJPEPK @0x89FB1B0` and mask-step refresh `EEBOFEGNDIG @0x89F9AF0`; the latter invokes `MonoNewbieDialog.SetNewbieMaskIndex` at `0x89F9B87`. The other attempted focus `0x8CEC570` has **5,569 direct callers** and is a broad utility, so the workflow label `guide_eligibility_check` is misleading and **must not be promoted as guide-specific evidence**.

**Next critical target:** identify which notifications/actions select `[r13+0x74] == 3` and `[r13+0x88] != 0`, and whether Amber's `35601` handoff invokes this candidate guide controller at all. Until that source link is proven, no AstaPS gameplay patch or client test is justified.

## Next causal gates

1. Trace `FinishCurrTalk` -> direct callers/callees, and the candidate tutorial UI controller constructors/notifications.
2. Identify **where input gets locked** relative to `MonoNewbieMask` creation or activation, and whether mask creation is conditional on a usable active quest button/context.
3. Tie the candidate onboarding activation specifically to task `35601` or its follow-up `35603`, not just generic guide terminology.
4. Compare `questing.enabled` and effective `QuestManager.isQuestingActive() = enableScriptInBigWorld && questing.enabled`, then confirm sent quest entries if necessary.
5. Only after native proof, modify AstaPS with focused regression; CI before asking the user to run the client.

Do **not** set guessed OpenState values, fabricate ShowClientGuideNotify CmdId, force quest completion, or treat CmdId 2178 as the guide message without type and call-path proof.

Run source: `.github/workflows/research-amber-pre-mask-71.yml`. Reusable generic scanner: `tools/trace_native_call_edges.py`.
