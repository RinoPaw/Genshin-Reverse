# Statue unlock follow-up — complete 7.1 quest 303 and resource gap

## Conclusion

The normal Statue of the Seven activation model is now confirmed across the modern 7.1 map, not only the old Mondstadt/Liyue/Inazuma subset.

DimbreathBot/AnimeGameData commit `792978e5503ecfba73dcb3562ed44a0d35a2abe2` is explicitly `CNRELWin7.1.0_R48379043_S48511369_D48533839` (2026-10-01). Its `BinOutput/Quest/303.json` contains the statue activation subquests through `30362`.

Every inspected entry keeps the same data-driven shape:

```text
QUEST_CONTENT_COMPLETE_TALK(303xx)
    -> QUEST_EXEC_UNLOCK_POINT(scene=3, point)
    -> QUEST_EXEC_UNLOCK_AREA(scene=3, area[, area2])
```

So the 303xx activation chain did not disappear in Sumeru, Fontaine, Natlan, or Nod-Krai. The incomplete chain seen in the LunaGC resource pack is a resource-pack omission.

## Historical implementation evidence

Grasscutter commit `1940b22dc55dae76dd51f81ed5dab1ba1d8528aa` is titled:

```text
Fix statue unlocks, and probably other quests involving talks
```

The meaningful fix moved quest talk events outside the `talkData != null` block in `TalkManager.triggerTalkAction()`.

Before the fix, a missing `TalkExcelConfigData` row caused an early return. After the fix, `QUEST_CONTENT_COMPLETE_TALK(talkId)` is still queued even when there is no normal TalkExcel record. This is exactly how statue activation talks can drive hidden quest 303.

Current AstaPS `play/rino` already retains this corrected TalkManager behavior. Therefore a statue-specific guessed packet handler is unnecessary for quest-backed activation.

## Current AstaPS semantic regression

`PlayerProgressManager.addStatueQuestsOnLogin()` currently starts/creates the 303 children and then directly sets every existing child to `QUEST_STATE_FINISHED`, intentionally avoiding `GameQuest.finish()`.

That preserves post-unlock goddess/F UI, but it destroys the activation transaction:

```text
303xx already FINISHED
    -> NpcTalkReq(303xx)
    -> COMPLETE_TALK is queued correctly
    -> tryFinishSubQuests only examines UNFINISHED children
    -> 303xx cannot finish
    -> finishExec never runs
    -> point/area remain locked
```

Upstream Grasscutter's `addStatueQuestsOnLogin()` keeps 303 children active and UNFINISHED until the matching activation talk completes. This is the correct server-side lifecycle for entries that exist in Quest 303.

## The apparent 30317 cutoff was a resource-pack bug

The comparison `capyb2222/LunaGC-Resources` copy of `BinOutput/Quest/303.json` ends at `30317`. That made later AstaPS code appear to require client-only forged 303xx state and EnterTrans auto-unlock fallbacks.

The actual 7.1 BinOutput disproves that assumption. Representative modern entries are:

```text
30318 -> point 462  -> area 20
30319 -> point 463  -> area 21
30320 -> point 464  -> area 29
30321 -> point 465  -> area 23
30322 -> point 471  -> area 24
30323 -> point 472  -> area 25
30324 -> point 625  -> area 22
30325 -> point 534  -> area 26
30326 -> point 535  -> area 27
30327 -> point 536  -> area 28
30328 -> point 629  -> area 32
30329 -> point 744  -> area 30
30330 -> point 811  -> area 31

30331 -> point 770  -> area 33
30332 -> point 771  -> area 34
30333 -> point 772  -> area 35
30334 -> point 814  -> area 36
30335 -> point 815  -> area 37
30336 -> point 922  -> area 38
30337 -> point 923  -> area 39
30338 -> point 947  -> area 40 (+ progress 31801)
30339 -> point 948  -> area 41 (+ progress 31801)
30340 -> point 1121 -> area 42

30341 -> point 1166 -> area 43
30342 -> point 1167 -> area 44
30343 -> point 1168 -> area 45
30344 -> point 1169 -> area 46
30345 -> point 1232 -> area 48
30346 -> point 1233 -> area 49
30347 -> point 1429 -> area 53
30348 -> point 1359 -> area 51
30349 -> point 1515 -> area 70
30350 -> point 1516 -> area 71
30351 -> point 1517 -> area 72
30352 -> point 1376 -> areas 52,54
30353 -> point 1613 -> area 73
30354 -> point 1614 -> area 74
30355 -> point 1615 -> area 75
30356 -> point 1885 -> area 77
30357 -> point 1752 -> area 76
30358 -> point 1757 -> area 55
30359 -> point 1758 -> area 56
30360 -> point 1759 -> area 57
30361 -> point 1760 -> area 58
30362 -> point 1761 -> area 59
```

Current `StatueTalkQuests` stops at `30352`; the 7.1 source therefore also exposes missing late mappings `30353..30362`.

## Correct repair model

For a no-legacy implementation, the authority should be quest 303 data rather than `EnterTransPointRegionNotify` or a nearest-statue guess.

1. Supply/restore complete 7.1 quest 303 data (`30302..30362`) in a form AstaPS can parse.
2. Keep real 303 children active/UNFINISHED until their matching talk completes.
3. Let the existing `NpcTalkReq -> TalkManager -> COMPLETE_TALK -> GameQuest.finish() -> finishExec` chain perform the unlock.
4. Let `QUEST_EXEC_UNLOCK_POINT` use `TransPointUnlockHelper`; let `QUEST_EXEC_UNLOCK_AREA` perform map-area unlocks.
5. Do not pre-finish real 303 children on login.
6. Treat FINISHED client-only forging as a post-unlock compatibility tool only, if it is still needed for goddess/heal/offer UI after the real quest state has naturally become FINISHED.
7. Remove/disable locked-statue auto-unlock from EnterTrans after the native chain is validated, because it masks regressions.

The starter statue remains a separate quest-352 case.

## Remaining runtime check

Static evidence is now sufficient to choose the implementation direction. One narrow runtime trace is still valuable as validation, not discovery:

```text
locked non-starter statue
  NpcTalkReq CmdId 283, talk_id = matching 303xx
  server quest 303xx before request = UNFINISHED
  COMPLETE_TALK finishes it
  finishExec runs
  ScenePointUnlockNotify sent
  area unlock notify sent
```

If this succeeds with EnterTrans auto-unlock disabled, the native 7.1 activation chain is closed end-to-end.