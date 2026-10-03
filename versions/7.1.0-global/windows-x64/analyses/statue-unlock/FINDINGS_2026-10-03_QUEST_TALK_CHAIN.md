# Statue unlock follow-up — quest/talk chain

## Conclusion

The current evidence changes the leading model for normal non-starter Statue of the Seven activation.

The missing bridge is not expected to be a statue-specific request carrying `scene_id` / `point_id` directly. Main quest `303` already encodes the bridge as a data-driven quest flow:

```text
client selects statue activation talk
    -> NpcTalkReq(talk_id = 303xx)
    -> QUEST_CONTENT_COMPLETE_TALK(303xx)
    -> finish the matching unfinished 303xx subquest
    -> QUEST_EXEC_UNLOCK_POINT(scene, point)
    -> QUEST_EXEC_UNLOCK_AREA(scene, area)
    -> existing trans-point/area unlock business logic
```

This fits the runtime symptom much better than the previous `UnlockTransPointReq` hypothesis: the statue interaction UI opens, the selection is accepted as a talk action, but no waypoint-style `UnlockTransPointReq` needs to be emitted for the statue quest to unlock the point.

## Resource evidence: main quest 303 owns statue activation

The same-version resource set used for comparison contains `BinOutput/Quest/303.json`. Its hidden subquests are explicit statue unlock transactions.

Examples:

```text
30302
  finish: QUEST_CONTENT_COMPLETE_TALK 30302
  exec:   QUEST_EXEC_UNLOCK_POINT 3 3
          QUEST_EXEC_UNLOCK_AREA  3 3

30303
  finish: QUEST_CONTENT_COMPLETE_TALK 30303
  exec:   QUEST_EXEC_UNLOCK_POINT 3 4
          QUEST_EXEC_UNLOCK_AREA  3 2

30304
  finish: QUEST_CONTENT_COMPLETE_TALK 30304
  exec:   QUEST_EXEC_UNLOCK_POINT 3 29
          QUEST_EXEC_UNLOCK_AREA  3 4

30305
  finish: QUEST_CONTENT_COMPLETE_TALK 30305
  exec:   QUEST_EXEC_UNLOCK_POINT 3 72
          QUEST_EXEC_UNLOCK_AREA  3 5
```

The pattern continues through the later 303xx statue subquests. AstaPS's own `StatueTalkQuests` table independently maps statue area ids to these same 303xx ids.

Therefore 303xx is not merely a cosmetic F-button gate. It is the server-side activation transaction definition.

## AstaPS talk path already supplies the content trigger

Current `play/rino` has the required generic path:

```text
HandlerNpcTalkReq
  -> TalkManager.triggerTalkAction(req.talk_id, ...)

TalkManager.triggerTalkAction
  -> queue QUEST_CONTENT_COMPLETE_ANY_TALK(talk_id)
  -> queue QUEST_CONTENT_COMPLETE_TALK(talk_id)
  -> queue QUEST_COND_COMPLETE_TALK(talk_id)

QuestManager
  -> GameMainQuest.tryFinishSubQuests(...)

GameMainQuest.tryFinishSubQuests
  -> only considers QUEST_STATE_UNFINISHED children
  -> matching content succeeds
  -> GameQuest.finish()

GameQuest.finish
  -> executes finishExec

ExecUnlockPoint
  -> TransPointUnlockHelper.unlock(player, scene_id, point_id, isStatue)
```

No new statue-specific handler is necessary for this chain if the 303xx quest remains active.

## Current AstaPS bug

`PlayerProgressManager.addStatueQuestsOnLogin()` currently does this for the 303 quest family:

1. ensure each 303xx child exists;
2. directly set the child state to `QUEST_STATE_FINISHED`;
3. save it;
4. deliberately do not call `GameQuest.finish()` because the old implementation observed login hangs / white screens when finish execs were run during login.

`buildForgedStatueTalkQuests()` follows the same model: an existing 303xx server quest is mutated to FINISHED instead of keeping server progress live.

That creates a precise semantic contradiction:

```text
client side:
  sees the quest gate as FINISHED
  -> goddess/F/statue UI is available

server side:
  matching 303xx quest is already FINISHED
  -> GameMainQuest.tryFinishSubQuests ignores it
  -> COMPLETE_TALK can no longer finish it
  -> finishExec never runs
  -> point/area never unlocks
```

This matches the reproduced failure exactly: the interaction surface works, selecting the activation option does not unlock the statue, and there is no waypoint-style `UnlockTransPointReq` diagnostic.

The direct FINISHED mutation is therefore the leading root cause.

## 7.1 talk packet evidence

Current AstaPS and an independent same-version LunaGC 7.1 tree both map:

```text
NpcTalkReq CmdId = 283
NpcTalkRsp CmdId = 3514
```

The same-version proto mapping for `NpcTalkReq` is:

```proto
uint32 talk_id       = 2;
uint32 npc_entity_id = 3;
uint32 entity_id     = 7;
```

This is strong integration evidence for the packet that carries the `303xx` selection into the existing talk/quest path. It has not yet been independently promoted as an official-binary identity inside Genshin-Reverse's small curated `known-opcodes.csv`; keep that distinction in documentation.

A narrow runtime log of CmdId 283 / `talk_id` on a locked non-Windrise statue is sufficient to close the last packet-level observation cheaply. The expected value is the area's 303xx id.

## EnterTransPointRegionNotify

The current `HandlerEnterTransPointRegionNotify` contains a private-server auto-unlock fallback for locked statues. That is not part of the data-driven activation chain above and can hide regressions.

The useful native role of EnterTransPoint remains the statue region behavior such as healing/revive. Activation should be tested without relying on its auto-unlock branch.

## Starter statue is separate

The starter Mondstadt statue is tied to main quest `352`, especially `35205`:

```text
35205 finish condition: QUEST_CONTENT_FINISH_PLOT 35205
finishExec:
  QUEST_EXEC_UNLOCK_POINT 3 7
  QUEST_EXEC_UNLOCK_AREA  3 1
  QUEST_EXEC_CHANGE_AVATAR_ELEMET 7 0
```

So point 7 should not be used as the generic 303xx control sample. AstaPS also seeds point 7 separately. Keep the early Archon-quest / Windrise investigation separate from generic statue activation.

## Fix direction

Do not add a guessed `NpcTalkReq -> nearest statue -> unlock` special case.

The cleaner repair is to restore the existing quest semantics:

1. keep real server-side 303xx children `UNFINISHED` until their matching talk completes;
2. if the client requires a FINISHED quest view to expose the goddess/F interaction, forge only the client-facing quest entry and do not mutate the actual `GameQuest` state;
3. let the normal `NpcTalkReq -> COMPLETE_TALK -> GameQuest.finish -> finishExec` path unlock point and area;
4. remove/disable locked-statue auto-unlock from `EnterTransPointRegionNotify` while validating the native flow;
5. retain the already-confirmed `TransPointUnlockHelper` / `ScenePointUnlockNotify` downstream implementation.

## Next validation

On a locked non-Windrise statue whose UI already opens, capture only these facts:

```text
NpcTalkReq CmdId 283 received
  talk_id = expected 303xx
  entity_id / npc_entity_id recorded

before request:
  303xx server state = UNFINISHED
  point locked

then:
  COMPLETE_TALK finishes 303xx
  QUEST_EXEC_UNLOCK_POINT runs
  QUEST_EXEC_UNLOCK_AREA runs
  ScenePointUnlockNotify is sent
  point becomes map-usable
  area fog clears
```

If that trace closes, the statue activation investigation no longer needs a new protocol message or an `UnlockTransPointReq` bridge.