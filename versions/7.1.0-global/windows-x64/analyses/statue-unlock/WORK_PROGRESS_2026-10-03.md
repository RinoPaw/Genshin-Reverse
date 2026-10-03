# Statue of the Seven unlock investigation checkpoint — 2026-10-03

## Scope

This checkpoint records the current state of the Genshin 7.1 Statue of the Seven investigation. Keep this separate from the already-resolved ordinary waypoint unlock work.

## Current AstaPS production branch

Observed `RinoPaw/AstaPS` branch:

- branch: `play/rino`
- observed HEAD at checkpoint time: `e976250f8a3c0c4d596e2cb9a348017d999b23c7`
- message: `fix: evaluate team element count predicates`

The branch may move independently; always re-read the remote HEAD before writing.

## Ordinary waypoint work is already closed

Do not reopen the ordinary waypoint `UnlockTransPointRsp` search unless new official packet-correlation evidence appears.

Confirmed ordinary waypoint flow remains:

1. C -> S `UnlockTransPointReq` (`9369`)
2. server updates persistent unlock state / reward / quest-script content
3. S -> C `ScenePointUnlockNotify` (`25567`) with `scene_id` and `point_list`
4. map becomes active and `SceneTransToPointReq` can be used

The historical gray-map bug came from AstaPS encoding the same point in official 7.1 field 4 (`locked_point_list`) while also sending field 15 (`point_list`). The full `GetScenePointRsp` unlock-time workaround and unconfirmed `UnlockTransPointRsp` send were removed from the production waypoint path.

## Statue observations confirmed in runtime

### Windrise / quest-gated sample

The Windrise statue did not expose an interaction button while the corresponding early main-quest chain was not in the expected state.

Do not use that sample to diagnose generic statue interaction. The user is investigating the broken quest chain separately.

### Other locked statues

A different locked Statue of the Seven was reached directly by point teleport and behaved differently:

- the statue entity was present;
- the interaction button was available;
- selecting it opened the normal `Statue of The Seven` interaction UI;
- the UI showed the normal statue text (runtime screenshot confirms the interaction surface is client-visible);
- after choosing the interaction option, the statue did **not** become unlocked;
- AstaPS produced no corresponding statue-unlock diagnostic / `UnlockTransPointReq` log.

This is the key current reproduction.

## What this rules out

For the non-Windrise sample, the failure is downstream of basic statue entity exposure.

The following stages are already demonstrated to work well enough to reach the client interaction UI:

- scene point / statue entity exists;
- player can approach it;
- client receives enough interaction metadata to display the F interaction;
- the normal `Statue of The Seven` UI can open.

Therefore the current breakpoint is narrower:

`locked statue -> interaction UI opens -> option selected -> ??? -> server unlock transaction`

Do not spend the next pass re-debugging generic entity spawn, proximity, or the Windrise quest gate unless new evidence contradicts this.

## Current leading code finding

Current `play/rino` `HandlerNpcTalkReq` / talk flow is generic. It advances talk and triggers ordinary talk actions, but the investigation has not yet found a statue-specific unlock bridge there.

At checkpoint time, there is no confirmed mapping from the client-side statue option selection to:

- `scene_id` / `point_id`, then
- `TransPointUnlockHelper.unlock(...)` (or an equivalent official statue unlock handler).

This matches the runtime symptom: the statue menu opens, but selecting the option produces no visible unlock transaction in AstaPS diagnostics.

This is still a hypothesis boundary, not a final protocol conclusion. The next pass must identify the exact request sent after choosing the statue option before adding any server-side hook.

## Related statue server logic already present

AstaPS already contains statue-specific business logic around the normal trans-point helper / statue systems, including concepts such as:

- statue point identification;
- area hierarchy unlock;
- statue talk-gate refresh;
- statue healing / `SotSManager` region behavior;
- `ScenePointUnlockNotify` after a successful point unlock.

So the likely missing piece is the **selection-to-unlock trigger**, not the downstream persistent unlock implementation.

## EnterTransPointRegionNotify

Historical AstaPS logic had used `EnterTransPointRegionNotify` as an opportunity to automatically unlock a statue and push map refresh packets. That behavior can hide the native client transaction and must not be treated as proof of the official 7.1 statue unlock trigger.

For investigation purposes, distinguish:

- entering the statue healing / trans-point region;
- opening the statue interaction UI;
- selecting the activation option;
- actual point/area unlock.

Do not conflate them.

## Test/support work already done in AstaPS

The production branch has accumulated supporting changes for this investigation:

- point-based `/tp <pointId> [sceneId]` support intended to reach locked waypoints/statues without requiring them to be unlocked;
- fresh-account intro behavior moved toward config-driven control;
- default traveler/avatar and nickname settings are conceptually independent from intro skipping;
- the legacy starter-statue auto-unlock is being neutralized for fresh-account testing without intentionally relocking already-persisted legitimate old-account unlocks.

Because `play/rino` can advance via parallel work, inspect current code before relying on the exact implementation details above.

## Current research target

Do **not** guess a statue unlock handler yet.

The next useful step is to determine what the 7.1 client sends after the user chooses the activation option in the normal Statue of the Seven UI.

Priority order:

1. inspect current AstaPS handlers around `NpcTalkReq`, worktop/gadget interaction, and statue/goddess talk plumbing;
2. add narrowly-scoped inbound diagnostics if the request is not already visible;
3. reproduce on a non-Windrise locked statue whose interaction UI is known to open;
4. identify the exact request opcode and payload/fields produced by selecting the activation option;
5. map the request to `scene_id` / `point_id` using official 7.1 resources / reverse data;
6. only then wire the request to the existing statue unlock business path;
7. validate: visual statue activation, map unlock / area reveal, teleportability, subsequent statue menu and healing.

## Important separation from quest investigation

The user is separately investigating the early quest chain where `捕风的异乡人` / Paimon progression failed to start after the prologue segment. That can explain the Windrise-specific interaction gate, but it does not explain the confirmed failure of another statue whose full interaction UI already opens.

Treat these as independent bugs until runtime evidence links them.

## Resume point

Resume here:

> Find the exact 7.1 C2S packet emitted when the player selects the activation option in a normal locked Statue of the Seven UI. The entity and UI-open stages have already been validated on a non-Windrise sample. Do not modify the unlock path based only on talk-handler assumptions.
