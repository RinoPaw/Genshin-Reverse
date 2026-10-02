# UnlockTransPoint runtime observation — 2026-10-02 21:16:53

This note preserves the latest live-client observation before session handoff. It does **not** promote either surviving `UnlockTransPointRsp` candidate to canonical semantic status.

## Observed server timeline

```text
21:16:53 <INFO:HandlerUnlockTransPointReq> UnlockTransPointRsp probe uid=70561 scene=3 point=122 statue=false unlocked=true cmd=36641 clientSeq=10485 retcode=0
21:16:57 <WARN:Scene> Scene 3 tick: sceneTime=151850 (advancing), scenePaused=true, worldPaused=true, timeLocked=false, entities=501, players=[70561:LOADED]
21:17:07 <WARN:Scene> Scene 3 tick: sceneTime=151850 (not advancing), scenePaused=true, worldPaused=true, timeLocked=false, entities=501, players=[70561:LOADED]
21:17:08 <INFO:HandlerEnterSceneReadyReq> [intro-handshake] EnterSceneReadyReq uid=70561 state=ACTIVE loadState=LOADING token=19894 len=4
21:17:08 <INFO:HandlerSceneInitFinishReq> [intro-handshake] SceneInitFinishReq uid=70561 state=ACTIVE loadState=LOADING token=19894 len=4
21:17:08 <INFO:HandlerEnterSceneDoneReq> [intro-handshake] EnterSceneDoneReq uid=70561 state=ACTIVE loadState=INIT token=19894 len=6
21:17:08 <INFO:HandlerEnterSceneDoneReq> [intro-handshake] EnterSceneDoneReq uid=70561 state=ACTIVE loadState=LOADED token=19894 len=6
21:17:08 <INFO:HandlerPostEnterSceneReq> [intro-handshake] PostEnterSceneReq uid=70561 state=ACTIVE loadState=LOADED token=19894 len=6
21:18:17 <WARN:Scene> Scene 3 tick: sceneTime=217811 (advancing), scenePaused=true, worldPaused=true, timeLocked=false, entities=467, players=[70561:LOADED]
21:18:27 <WARN:Scene> Scene 3 tick: sceneTime=217811 (not advancing), scenePaused=true, worldPaused=true, timeLocked=false, entities=467, players=[70561:LOADED]
21:18:50 <INFO:HandlerEnterSceneReadyReq> [intro-handshake] EnterSceneReadyReq uid=70561 state=ACTIVE loadState=LOADING token=6561 len=4
21:18:50 <INFO:HandlerSceneInitFinishReq> [intro-handshake] SceneInitFinishReq uid=70561 state=ACTIVE loadState=LOADING token=6561 len=4
21:18:50 <INFO:HandlerEnterSceneDoneReq> [intro-handshake] EnterSceneDoneReq uid=70561 state=ACTIVE loadState=INIT token=6561 len=6
21:18:50 <INFO:HandlerEnterSceneDoneReq> [intro-handshake] EnterSceneDoneReq uid=70561 state=ACTIVE loadState=LOADED token=6561 len=6
21:18:50 <INFO:HandlerPostEnterSceneReq> [intro-handshake] PostEnterSceneReq uid=70561 state=ACTIVE loadState=LOADED token=6561 len=6
```

User-visible result: the teleport point did **not** appear unlocked immediately after the 21:16:53 request/response probe. After some time and a subsequent scene-entry handshake, it changed to unlocked state.

## What this establishes

1. Server-side unlock state was already true at 21:16:53 for `scene=3, point=122`.
2. The persistent/current server state is therefore capable of surviving until a later scene reconstruction and being presented to the client as unlocked.
3. The delayed client refresh strongly suggests the immediate unlock transaction is incomplete or malformed somewhere in the live update path. Candidate areas include the response semantic id, `ScenePointUnlockNotify` serialization/content, send ordering, or another current-client refresh message.
4. The later scene-entry handshake is a useful boundary: some state sent during scene re-entry is sufficient to make the client converge to the correct unlocked state.

## What this does NOT establish

- It does not prove `36641` is `UnlockTransPointRsp`.
- It does not prove `36641` is wrong either. The client may ignore/mis-handle a different live-update message while accepting an otherwise correct ACK.
- It does not prove that Genshin 7.1 requires a full scene reload for waypoint unlocks.
- AstaPS is not an independent known-correct 7.1 protocol oracle while the response id and live notification path are under investigation.

## Immediate comparison target

Same-version LunaGC behavior is useful as an implementation control: its waypoint unlock flow sends `ScenePointUnlockNotify(sceneId, pointId)` directly after recording the unlock, with no obvious requirement for a later full scene reload. Therefore the next high-value check is the exact current 7.1 `ScenePointUnlockNotify` wire shape and the AstaPS-generated packet fields/tags, followed by capture of what is sent during the scene-entry handshake that finally flips the client state.

Current confirmed control remains:

```text
ScenePointUnlockNotify
  CmdId      25567
  proto type DBNMIKBJIPE
  handler    KLLNGCPBLMM.IPADDHFIGMF @ 0xF05F0F0
  method idx 615937
```

Current unresolved response candidates remain:

```text
36641 / NCBEHBOCBJJ / handler 0xF045790
20290 / MAFFAFNMEBM / handler 0xF0462A0
```

Keep the canonical semantic mapping unresolved until a current-client transaction uniquely binds one candidate.

## Recommended continuation

1. Verify the generated/provided `ScenePointUnlockNotify` field numbers against the recovered 7.1 parser, not only its semantic field names.
2. Capture the exact S2C `25567` frame emitted immediately after `9369`, including body bytes.
3. Capture the scene-entry frames around the first handshake that makes the point appear unlocked and identify the message that carries point 122 as unlocked.
4. Compare those two wire representations. If the immediate `25567` body is malformed or missing the point list, fix that path before using visual client behavior as evidence for `36641` vs `20290`.
5. Only after the live notification path is known-good should the response-candidate runtime probe be treated as semantic evidence.
