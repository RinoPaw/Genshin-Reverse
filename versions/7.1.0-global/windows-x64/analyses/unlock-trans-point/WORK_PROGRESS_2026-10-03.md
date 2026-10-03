# Waypoint unlock work checkpoint — 2026-10-03

This file is the handoff checkpoint for the Genshin 7.1 waypoint-unlock work. The gameplay bug is closed; `UnlockTransPointRsp` identity research is intentionally paused because it has no observed gameplay value for the current AstaPS implementation.

## Current conclusion

For ordinary waypoint activation, the smallest client/server chain that has been validated on the current 7.1 client is:

```text
C -> S  UnlockTransPointReq        CmdId 9369
        scene_id = field 12
        point_id = field 1

S       update unlocked point state
        grant configured unlock reward
        trigger quest/script unlock events
        persist player

S -> C  ScenePointUnlockNotify     CmdId 25567
        scene_id = field 2
        point_list = field 15
```

`ScenePointUnlockNotify` is an official current-client protocol message, not an AstaPS workaround. Its current 7.1 semantic field mapping recovered from the official client is:

```text
field 2   scene_id
field 4   locked_point_list
field 6   hide_point_list
field 8   unhide_point_list
field 15  point_list
```

The old AstaPS implementation put the same newly unlocked waypoint into field 15 and generated `unhide_point_list` field 4. The generated name was stale/wrong for this exact client; the official 7.1 client interprets field 4 as `locked_point_list`. That produced a contradictory live update: unlock the point and lock the same point. This explains the historical behavior where the physical waypoint activated and rewards were granted while the world-map waypoint remained gray/unusable.

The corrected normal unlock notification sends only `scene_id + point_list`.

## Runtime validation matrix

All tests below used the corrected `ScenePointUnlockNotify` and deliberately omitted the old full `GetScenePointRsp` refresh fallback.

```text
UnlockTransPointRsp candidate 36641  -> physical activation OK
                                      -> map icon immediately usable OK
                                      -> teleport from map OK

UnlockTransPointRsp candidate 20290  -> physical activation OK
                                      -> map icon immediately usable OK
                                      -> teleport from map OK

No UnlockTransPointRsp at all         -> physical activation OK
                                      -> map icon immediately usable OK
                                      -> teleport from map OK
```

The no-response control happened once through an invalid probe value (`1`): the server completed the unlock and sent the corrected live notification, then threw while constructing the probe response. Since all three visible behaviors still succeeded, no `UnlockTransPointRsp` was required for the tested unlock/map/teleport behavior.

Therefore visible private-server behavior cannot distinguish candidate 36641 from 20290, and neither candidate is needed by AstaPS for the currently targeted gameplay path.

## `UnlockTransPointRsp` status

Current 7.1 static candidates remain:

```text
36641  NCBEHBOCBJJ  int32 retcode = 6
20290  MAFFAFNMEBM  int32 retcode = 6
```

Both use the same generic scene ACK handler shape. Static neighborhood, type order, handler proximity, native equality, generic submit fan-out, and private-server visual behavior are not sufficient promotion evidence.

Research on the exact response identity is PAUSED by project decision. Do not spend further time resolving it unless a later feature demonstrates that the response is required or a genuine official 7.1 packet capture becomes available incidentally.

If research resumes, the only maintained promotion criterion is a known-correct official transaction:

```text
C2S 9369  seq=N
S2C X     seq=N
```

where exactly one of `X = 36641` or `X = 20290` matches `client_sequence_id=N`.

## AstaPS implementation state

The production `play/rino` path has been tightened to match the runtime evidence:

```text
HandlerUnlockTransPointReq
    -> TransPointUnlockHelper.unlock(...)

TransPointUnlockHelper.unlock(...)
    -> update state/reward/events
    -> PacketScenePointUnlockNotify(sceneId, pointId)
    -> save
```

The old proactive `GetScenePointRsp` full refresh after each unlock was a workaround and has been removed from the live unlock path. `GetScenePointReq/GetScenePointRsp` remains the normal full-state synchronization path used when the client requests scene-point state, such as during login/scene reconstruction.

AstaPS also does not send an unconfirmed `UnlockTransPointRsp` CmdId. `PacketOpcodes.UnlockTransPointRsp` should remain unresolved until independent evidence exists.

Relevant implementation files:

```text
src/main/java/emu/grasscutter/server/packet/recv/HandlerUnlockTransPointReq.java
src/main/java/emu/grasscutter/game/player/TransPointUnlockHelper.java
src/main/java/emu/grasscutter/server/packet/send/PacketScenePointUnlockNotify.java
src/main/java/emu/grasscutter/server/packet/recv/HandlerGetScenePointReq.java
src/main/java/emu/grasscutter/server/packet/send/PacketGetScenePointRsp.java
src/main/java/emu/grasscutter/server/packet/recv/HandlerSceneTransToPointReq.java
src/main/java/emu/grasscutter/server/packet/send/PacketSceneTransToPointRsp.java
```

The fix that removed the unlock-time full refresh and unconfirmed response was introduced as:

```text
daa5c5f  fix(scene): trust confirmed live waypoint unlock notify
```

`play/rino` has continued to advance after that commit; do not reset the branch back to this SHA.

## Related packet chain

Full scene-point state synchronization:

```text
C -> S  GetScenePointReq        CmdId 1649
S -> C  GetScenePointRsp        CmdId 26
```

Actual use of an unlocked waypoint:

```text
C -> S  SceneTransToPointReq    CmdId 1252
        scene_id = field 4
        point_id = field 10

S -> C  SceneTransToPointRsp    CmdId 23515
        scene_id = field 7
        retcode = field 12
        point_id = field 15
```

A scene-changing teleport is then followed by the ordinary scene-entry lifecycle (`PlayerEnterSceneNotify`, `EnterSceneReady`, `SceneInitFinish`, `EnterSceneDone`, `PostEnterScene`, plus any client-requested state refreshes).

`GadgetInteractReq/GadgetInteractRsp` exists as the generic gadget-interaction path, but it is not currently treated as a required step in the validated ordinary waypoint-unlock chain. Statue/Worktop/Talk behavior should be investigated separately when needed.

## Stop / resume rule

Treat the ordinary waypoint-map bug as fixed and closed unless a regression appears.

Do not resume `UnlockTransPointRsp` reverse engineering solely to obtain a semantically pretty Req/Rsp pair. Resume only when one of these changes the premise:

1. a gameplay feature actually requires the missing response;
2. an official-current-7.1 capture is available and can resolve the sequence correlation cheaply;
3. new static evidence creates a unique semantic binding.

Until then, spend reverse-engineering time on packets that affect observable 7.1 gameplay.