# UnlockTransPoint protocol recovery

Status: ordinary waypoint unlock behavior is **CLOSED / VALIDATED** for Genshin 7.1 Global Windows x64. `UnlockTransPointReq` and the live unlock notification path are confirmed. Exact `UnlockTransPointRsp` identity remains an **UNRESOLVED STATIC TIE** and further response research is **PAUSED** because the current AstaPS gameplay path does not depend on it.

Pinned sample:

```text
GenshinImpact.exe    08a3086d5f3fe695f01dab61efa42e442006b18e5e475b2520df356f6a073b7d
global-metadata.dat 05ae04d7a91b91cc880217a56b0b01f3e67f845b06e894216654ec5d160e0da0
```

## Current result

Confirmed request:

```text
UnlockTransPointReq
CmdId      9369 / 0x2499
type       DMMJNICDOHM
scene_id   field 12
point_id   field 1
sender     KLLNGCPBLMM.OIFANGMCKNJ @ 0x0F0452B0
```

Confirmed live notification:

```text
ScenePointUnlockNotify
CmdId      25567
type       DBNMIKBJIPE

field 2    scene_id
field 4    locked_point_list
field 6    hide_point_list
field 8    unhide_point_list
field 15   point_list
```

A normal unlock notification uses `scene_id + point_list`. The previous server path also populated field 4 for the newly unlocked point. Exact-client recovery shows field 4 is `locked_point_list`, so that update contradicted the unlock and caused the gray/unusable map state. The corrected notification was validated with immediate map usability and teleport.

Current response candidates:

```text
36641  NCBEHBOCBJJ  int32 retcode = 6  handler KLLNGCPBLMM.GDILHLIGMPI @ 0xF045790
20290  MAFFAFNMEBM  int32 retcode = 6  handler KLLNGCPBLMM.OAEILOAJOML @ 0xF0462A0
```

Treat them as a tie. Do not prefer `36641` from local method distance or handler ordering.

Runtime controls with the corrected notification produced the same successful ordinary waypoint activation, map use and teleport when the server sent candidate `36641`, candidate `20290`, or no `UnlockTransPointRsp`. Private-server visible success therefore provides no semantic discrimination and the current AstaPS path does not need either unconfirmed response.

## Static boundary

The following evidence classes were tested and do not distinguish the two response candidates:

- ACK native-body equality;
- local owner-method distance or cross-version owner-order interpolation;
- `0x4B2Axx` values, which are per-method ILFix/hotfix storage rather than protocol slots;
- decoded signature consumers and direct handler references;
- generic submit fan-out or a hidden response-type argument;
- registry / TypeDefinition ordering;
- plaintext semantic names or normal generated descriptor Base64 in the exact sample;
- same-version public forks that also leave the response unresolved;
- forcing either response candidate on the private server.

The complete chronology, rejected paths and corrections remain in `RESEARCH_LOG.md` so they are available when a premise genuinely changes.

## Maintained capture path

Exact 7.1 packet-framing/XOR recovery established these plaintext boundaries:

```text
S2C post-XOR boundary   0xA01846A
C2S pre-XOR boundary    0xA01A0EF
```

Derivation and caller evidence are preserved in `RUNTIME_CAPTURE_RECOVERY_2026-10-02.md`.

The maintained collector is:

```text
tools/runtime/capture_game_packets_71.js
tools/runtime/capture_game_packets_71.py
```

If response research resumes:

```bash
python -m pip install frida
python tools/runtime/capture_game_packets_71.py \
  --output work/unlock-trans-point-71.ndjson

genshinre correlate-capture \
  work/unlock-trans-point-71.ndjson \
  --request-cmd 9369 \
  --candidate-cmd 36641 \
  --candidate-cmd 20290 \
  --sequence-field 3 \
  --output work/unlock-trans-point-71-analysis.json
```

Promotion requires a known-correct current-7.1 transaction where exactly one candidate S2C response shares the request `PacketHead` sequence value. Traffic produced by a server that is itself guessing the response CmdId is circular evidence.

## AstaPS integration rule

Validated ordinary waypoint path:

```text
receive UnlockTransPointReq(sceneId, pointId)
    -> update unlocked state / reward / unlock events
    -> send ScenePointUnlockNotify(sceneId, pointId)
    -> persist
```

Keep normal request-driven `GetScenePointReq/GetScenePointRsp` support for full scene-point synchronization. Do not proactively push a full scene-point response after each unlock, and do not send either unconfirmed `UnlockTransPointRsp` candidate simply to complete a Req/Rsp pair.

Statue activation has its own quest/talk gating investigation under `../statue-unlock/`; do not transfer ordinary waypoint conclusions onto that path without evidence.

## Evidence map

Use these as the current evidence set:

```text
README.md                                  current summary / resume rule
RESEARCH_LOG.md                            chronology, rejected paths, corrections
RUNTIME_CAPTURE_RECOVERY_2026-10-02.md     exact framing/XOR derivation
RUNTIME_OBSERVATION_2026-10-02_211653.md   live observation record
SCENE_POINT_UNLOCK_FIELD_MAPPING_2026-10-02.md
candidates.csv
retcode6-single-field-candidates.csv
docs/case-studies/unlock-trans-point-7.1.md
```

Git history retains retired intermediate checkpoints and one-off probes.

## Resume rule

Treat the ordinary waypoint-map bug as closed unless a regression appears. Resume exact `UnlockTransPointRsp` work only when at least one premise changes:

1. a gameplay feature actually requires the missing response;
2. a genuine official-current 7.1 capture becomes available cheaply;
3. new static evidence creates a unique semantic binding.

Until then, spend reverse-engineering effort on unresolved behavior that affects observable 7.1 gameplay.
