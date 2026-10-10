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

## Next causal gates

1. Trace `FinishCurrTalk` -> direct callers/callees, and the candidate tutorial UI controller constructors/notifications.
2. Identify **where input gets locked** relative to `MonoNewbieMask` creation or activation, and whether mask creation is conditional on a usable active quest button/context.
3. Tie the candidate onboarding activation specifically to task `35601` or its follow-up `35603`, not just generic guide terminology.
4. Compare `questing.enabled` and effective `QuestManager.isQuestingActive() = enableScriptInBigWorld && questing.enabled`, then confirm sent quest entries if necessary.
5. Only after native proof, modify AstaPS with focused regression; CI before asking the user to run the client.

Do **not** set guessed OpenState values, fabricate ShowClientGuideNotify CmdId, force quest completion, or treat CmdId 2178 as the guide message without type and call-path proof.

Run source: `.github/workflows/research-amber-pre-mask-71.yml`. Reusable generic scanner: `tools/trace_native_call_edges.py`.
