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

## Same-version `ScenePointUnlockNotify` implementation comparison

Follow-up inspection found a concrete implementation difference worth carrying into the next session.

AstaPS test branch `test/unlock-trans-point-rsp` currently builds the immediate unlock notification as:

```java
ScenePointUnlockNotify.newBuilder()
    .setSceneId(sceneId)
    .addPointList(pointId)
    .addUnhidePointList(pointId);
```

The same-version `capyb2222/LunaGC_7.1.0` implementation builds the ordinary waypoint unlock notification with only:

```java
ScenePointUnlockNotify.newBuilder()
    .setSceneId(sceneId)
    .addPointList(pointId);
```

Its published 7.1 proto declares:

```proto
message ScenePointUnlockNotify {
    repeated uint32 unhide_point_list = 50000;
    repeated uint32 locked_point_list = 50001;
    repeated uint32 point_list = 15;
    repeated uint32 hide_point_list = 6;
    uint32 scene_id = 2;
}
```

Thus the minimum same-version live-unlock payload used by Luna is `scene_id(field 2) + point_list(field 15)`. AstaPS additionally emits `unhide_point_list(field 50000)` for the same operation.

This difference is **not yet proven causal**. It is plausible that `unhide_point_list` is harmless, required only for a different hide/unhide lifecycle, or that AstaPS inherited it from an older/other semantic use. Do not remove it from production solely from this comparison. The important next step is to verify the official 7.1 client parser/wire semantics and capture the actual immediate packet body.

The AstaPS packet class also has hide/relock helpers that fill hide-related repeated fields; this reinforces that `point_list` and hide/unhide state are distinct semantic axes and should not be assumed interchangeable.

## Handoff state

At handoff time the strongest live observation remains:

```text
9369 UnlockTransPointReq
  -> server records point 122 unlocked immediately
  -> AstaPS sends normal ScenePointUnlockNotify plus candidate UnlockTransPointRsp
  -> client map remains gray initially
  -> later full scene-entry handshake occurs
  -> client eventually shows point unlocked
```

The visual result therefore cannot yet rank `36641` over `20290`.

The next session should start from these checks, in order:

1. Recover/verify official 7.1 `ScenePointUnlockNotify` parser field numbers and meanings from `Genshin-Reverse`, especially fields 2, 15, 50000, and 50001.
2. Confirm AstaPS's generated `ScenePointUnlockNotify` descriptors/tags exactly match those recovered fields; do not trust names alone.
3. Capture the exact S2C `25567` body emitted after a fresh `9369`, including body hex. Decode which fields are really present on wire.
4. Identify which S2C packet during the first later scene-entry handshake carries the newly unlocked point and makes the client converge. Compare its representation with the immediate `25567`.
5. If the immediate notification path is fixed/verified, repeat the controlled `36641` vs `20290` response probe on fresh ordinary waypoints. Only then use client behavior as response-semantic evidence.
6. Preserve the removed `GetScenePointRsp` workaround on the test branch during this investigation; reintroducing it would mask the live notification failure.

Do not publish either response candidate into the canonical semantic opcode map until this path converges.
