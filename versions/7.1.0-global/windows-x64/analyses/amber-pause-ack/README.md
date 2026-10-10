# Amber 35601: PlayerSetPause acknowledgement and input lock (7.1 Global)

## 2026-10-10: No visible tutorial mask; native interaction-lock gate

**New first-hand observation:** On the AstaPS 7.1 Amber 35601 reproduction, the user sees **no black mask / forced tutorial overlay at all**; controls become unresponsive directly after the dialogue. Earlier notes about how the **official game** normally displays a task-button guide do not imply that AstaPS ever reaches the guide UI. Preserve this difference. A complete 45-second server trace does not itself prove the client-side owner of the input lock.

**Exact client evidence** (7.1 Global Windows x64 executable SHA-256 `08a3086d5f3fe695f01dab61efa42e442006b18e5e475b2520df356f6a073b7d`): `metadata/types.csv` defines `MoleMole.InteractionManager` typeDefinition **84348**, with field `_lockedReasonSet` (field index **418074**). `ELockReason` typeDefinition **84351** defines named fields `UI_CLOCK` (418172) and `QUEST_CHECK` (418173); *actual constant numeric values have not been independently extracted*. Methods: `LockInter(ELockReason) @ 0xFE508D0`, `UnLockInter(ELockReason) @ 0xFE552F0`, `IsLocked() @ 0xFE5F5B0`, and `FinishCurrTalk(uint32) @ 0xFE57430`. The distinct lock-reason set is a stronger static target for a UI-less stuck state than an assumed visible guide overlay.

**Native direct-edge probe:** [focused hash-pinned run](https://github.com/RinoPaw/Genshin-Reverse/actions/runs/38060342999) confirms **0 validated direct E8 callers** of `LockInter` and **3 validated direct E8 callers** of `UnLockInter`: `IBOJCEGJPEM.IFMMKPLAMEL @ 0xCB9FDBF`, `IBOJCEGJPEM.HOACAKEFEEN @ 0xCBA02FD`, and `DDDKDOPHINB.LDOPCEKPOBN @ 0x11C9AE63`. All three call contexts load `edx=1` before calling `UnLockInter`. This proves **numeric argument 1**, not yet which named enum constant it represents. Zero direct `LockInter` calls does **not** prove it never executes: indirect, delegate, virtual and inlined paths are outside this probe.

`FinishCurrTalk` has additional native callees, including `MOHDLCGJEHG.Finish @ 0x90FF4F0` (callsite `0xFE57574`). It does **not** directly call `UnLockInter` in its probed direct-call edges. Its registered `NpcTalkRsp` receiver still forwards `cur_talk_id` into `FinishCurrTalk` in previously confirmed evidence, but receipt and completion of the entire interaction lifecycle remain unproven in a stuck runtime session. The relation of the `MOHDLCGJEHG.Finish` action to guide/input cleanup has not been established.

**One hop deeper** ([exact 7.1 owner-callers run](https://github.com/RinoPaw/Genshin-Reverse/actions/runs/38060685595)): the three `UnLockInter(1)` owner methods `IBOJCEGJPEM.IFMMKPLAMEL @ 0xCB9FD90`, `IBOJCEGJPEM.HOACAKEFEEN @ 0xCBA02B0`, and `DDDKDOPHINB.LDOPCEKPOBN @ 0x11C9AD90` each have **zero validated direct E8 callers**. That makes indirect/delegate/event registration or native method inlining the next necessary investigation, not a justification to assume these handlers never run. `MOHDLCGJEHG.Finish @ 0x90FF4F0` has exactly one validated E8 caller, `InteractionManager.FinishCurrTalk @ 0xFE57574`, and no direct `UnLockInter` call. The UI controller `EPJNAHIFNCP.JOAGJNOIHDC @ 0x89F7080` directly invokes `MonoNewbieDialog.SetNewbieMaskIndex` but has **zero validated E8 callers**; neither native probe establishes a bridge between that mask UI controller and the lock owners.

**7.1 resource cross-check:** `AstaPS-Resource/ExcelBinOutput/OpenStateConfigData.json` contains **41** states marked both `defaultState=true` and `allowClientOpen=true`, including `OPEN_STATE_QUEST_REMIND (7)`. AstaPS excludes this combination from its server-side `DEFAULT_OPEN_STATES`. This is a real divergence from the raw resource flag but is **not proof of incorrect client behavior**: the client might self-default those states. Do not globally force all 41 until the client's interpretation of omitted entries is established.

**Next evidence gate:** identify `ELockReason` constant values, then follow the three `UnLockInter(1)` callers and their trigger conditions and look for indirect/`_lockedReasonSet` additions. Verify whether the quest-check tutorial's entrypoint schedules an unlock callback **before** a black mask is shown, and whether that callback can fail when `35603` or OpenState 7 is missing. Do not create an unconditional unlock, mark quests complete, change open states or name CmdId 2178 as a tutorial event without stronger evidence.



**Status: ACTIVE / UNRESOLVED response identity and causal link.** Tracking issue: [#23](https://github.com/RinoPaw/Genshin-Reverse/issues/23). This investigation has independently closed the *request construction and client caller path*. It has **not** identified the 7.1 `PlayerSetPauseRsp` CmdId or shown that an absent response is what locks the controls after talking to Amber. Do not implement or promote a response opcode from this note.

## Exact target and evidence

| Source | SHA-256 |
| --- | --- |
| 7.1.0 Global / Windows x64 `GenshinImpact.exe` | `08a3086d5f3fe695f01dab61efa42e442006b18e5e475b2520df356f6a073b7d` |
| 7.1.0 Global `global-metadata.dat` | `05ae04d7a91b91cc880217a56b0b01f3e67f845b06e894216654ec5d160e0da0` |

The exact executable hash was checked by the pinned `NativeProfile` before the native probes ran. Machine-readable source-bound findings are in [`native-probe.json`](native-probe.json) and [`client-pause-field-xrefs.json`](client-pause-field-xrefs.json); the earlier registry-only result is [`static-probe.json`](static-probe.json). These are **static** artifacts, not a decrypted gameplay capture.

## Confirmed request chain

The canonical current-client registry binds `CmdId 5963` to `GLIHKBGFALC`:

- Registry index `1404`, typeDefinition `50277`, type slot RVA `0x057F5160`.
- `AEGNNPENLNM` (GetCmdId) @ `0x0A580740`, registry load `0x07F8255C`, store `0x07F82563`.
- One `bool` field `PJHLOKDIPNO`; the generated serializer `IENGFLPCLNM` @ `0x0A580610` writes tag `0x58` at `0x0A58066E`, proving **protobuf field 11, wire type 0**. Its value is loaded from message object offset `+0x18`.

The external type-slot consumer is `EDKMMIPJHJA.GHNMMIIFKIG(bool)` @ `0x07262BC0`. The slot load at `0x07262BD5`, message field write at `0x07262BF5` and tail send to `EDKMMIPJHJA.DMLCLHCBOBJ` @ RVA `0x07246860` establish a current-client **C2S bool message construction/sender**. Together with AstaPS's observed `PlayerSetPauseReq=5963` and `Miscs.PauseLevelTime` entry point, this supports the request's semantic identity. It is not evidence for the *response* identity.

All three exact-client direct callers of `GHNMMIIFKIG(bool)` are:

| Client entry point | Caller RVA | Call site | Evidence |
| --- | --- | --- | --- |
| `LLCGIEDMIIG.FGIJAHDHCAD(BDAAFIBNLEJ,PGKFPMENDPA)` | `0x0C237D60` | `0x0C237E10` | Inbound `BDAAFIBNLEJ`, registry CmdId **1307**, bool at `+0x24` |
| `LLCGIEDMIIG.ANMHAFAPOMJ(KNHBIEFHDFO,PGKFPMENDPA)` | `0x0C252C70` | `0x0C252D1F` | Inbound `KNHBIEFHDFO`, registry CmdId **20114**, bool at `+0x28` |
| `Miscs.PauseLevelTime(bool,DLIMDNJEDEC)` | `0x12E26EB0` | `0x12E27057` | Time-pause entry point; exact metadata enum `DLIMDNJEDEC` contains `Talk` |

AstaPS calls the two inbound CmdIds `SceneTimeNotify` (1307) and `PlayerTimeNotify` (20114). These server-side names are useful corroboration **only**, not independently confirmed native semantic labels. Both native handlers update client pause-related state at `LLCGIEDMIIG +0x1D0` before conditionally emitting the request. This is an important path for stuck-vs-reconnect packet comparison.

A focused scan of all 543 `LLCGIEDMIIG` methods found **nine** native instructions with memory displacement `+0x1D0`; only the two handler stores above have their object base resolved as the receiver. Other matches include stack and unrelated-object bases and must not be counted as receiver pause-field accesses without additional tracing.

## New 2026-10-10 reproduction: InteractionManager CmdId 27447

The server console capture of Amber talk 35601 (19:43:41) proves that the server sent `NpcTalkRsp`, finished quest `35601`, started **both** `35602` and `35603`, and received a previously unnamed client CmdId **27447** about 1.05 seconds after the talk request. `QuestDestroyNpcReq(23280)` arrived immediately afterward, and the server sent `QuestDestroyNpcRsp(3992)`. The console transcript ends around 2.7 seconds after the request and contains **no** 45-second trace summary or reconnect comparison.

New [source-bound 7.1 evidence](posttalk-interaction-27447.json) establishes:

- Canonical registry: `27447` → `NDAJDBCBAAE`, typeDefinition `75026`, slot RVA `0x57F83A0`. Native serializer `IENGFLPCLNM` @ `0x7AD8C30` writes protobuf **bool field 7** (tag `0x38`). This is distinct from `PlayerSetPauseReq(5963)`, which writes bool field 11.
- Native C2S construction: `LLCGIEDMIIG.GKJKIBOALJO(bool)` @ `0xC22D780` loads the message slot at `0xC22D791`, writes the bool at `0xC22D7B5`, and sends via the shared path.
- Five direct callers belong to `InteractionManager`: `OnCreateTalkFinish` at `0xFE33C1C` calls with **true**; `ClearOnDisconnect`, `ResumeGameTime`, `ClearAll` and `ClearAfterKeyListFinish` call with **false**.
- Two direct callers of `OnCreateTalkFinish` are `CreateTalkActionByTalkConfigInternal` and `CreateTalkActionByPerformCfgInternal`. `OnEvtInterruptIntee` is a direct caller of `ClearAfterKeyListFinish`; `ResumeGameTime` had no direct E8 callers in the scan (indirect calls are outside its evidence boundary).

The native-client investigation used [registry/metadata lookup](https://github.com/RinoPaw/Genshin-Reverse/actions/runs/38049568765), [serializer and sender scan](https://github.com/RinoPaw/Genshin-Reverse/actions/runs/38049670386), [sender caller scan](https://github.com/RinoPaw/Genshin-Reverse/actions/runs/38049772524) and [lifecycle caller scan](https://github.com/RinoPaw/Genshin-Reverse/actions/runs/38049957451), all bound to the exact 7.1 Global executable hash.

**Interpretation boundary:** The log has no payload for the observed `27447`, so the in-game message's bool is not yet confirmed. The client's true/false call sites are proven, but a missing false notification is only a **candidate explanation** for the input lock. A client-originated event does not automatically require a server response. Do not assign an unproved semantic name, implement an ACK, or force an interaction-state packet. AstaPS diagnostics now decode the field 7 bool on the Amber trace; compare the stuck window and the reconnect window.

## 2026-10-10 second capture: same pause state, distinct scene reinitialization

The full server transcript now contains two 45-second windows. Immediately after Amber talk 35601, the client still communicates normally; `35602` and `35603` are UNFINISHED, `SceneTimeNotify.is_paused=false`, and both server world and player paused flags are false. During the new session after forced reconnect (20:09:32), the server transmits `PlayerTimeNotify.is_paused=false`, sends its scene-enter initialization, and the client emits `PlayerSetPauseReq(is_paused=false)` at +1648ms. The server **drops** the 7.1 `PlayerSetPauseRsp` because its opcode is unresolved, but the user previously confirmed movement recovers on relog. This **weighs against missing pause ACK being a sufficient cause** of the dialogue lock; the native request and ACK identity research remains independently valid.

The earlier interaction marker `27447` was present only in the stuck talk window; this version of the running server did not decode its bool field 7, so the observed value is unknown. The absence of a 27447 false transition during the stuck window remains a candidate local `InteractionManager` cleanup gap.

Current Global 7.1 native receivers now also verify that the existing server protobuf field numbers match for both:
- `NpcTalkRsp(3514)`: native client tags `0x28/0x38/0x40/0x68` (fields **5,7,8,13**); server `retcode=5,cur_talk_id=7,npc_entity_id=8,entity_id=13`.
- `QuestDestroyNpcRsp(3992)`: native tags `0x48/0x68/0x78` (fields **9,13,15**); server `npc_id=9,parent_quest_id=13,retcode=15`.

Wire tag equality excludes these two **field-number mismatch hypotheses**, not invalid values, response-header correlation, or client callback timing. The 45-second stuck window shows two `QuestDestroyNpcReq` and two corresponding response send events, but logs contain no second-request timestamp or bodies, so retransmission is not established. [Native and descriptor cross-check](posttalk-response-wire-crosscheck.json) and [hosted 7.1 parser disassembly](https://github.com/RinoPaw/Genshin-Reverse/actions/runs/38051410917) preserve these results.

## Exact-client response callback (2026-10-10)

Further pinned 7.1 native disassembly shows that `NpcTalkRsp(3514)` has a direct handoff to the interaction-ending method. The native message reader `IMLLBMOMMEH.NLGBJEEJDLG @ 0x11E83970` stores protobuf **field 7 (tag 0x38)** to object offset `+0x24`. The response handler `HBBDJPCGCAH.JCIMEKEEFOH @ 0xA5E18C0` loads `[response+0x24]` and tail-calls `InteractionManager.FinishCurrTalk(uint32) @ 0xFE57430`. The generated AstaPS `NpcTalkRsp.cur_talk_id` is already field **7** and is populated with `35601`; **do not** overwrite `retcode` (field 5) with a talk ID.

`QuestDestroyNpcRsp(3992)` is handled by `HBBDJPCGCAH.HGDBBLBCPMH @ 0xA5E1D30`, whose ordinary path returns when given a non-null response, without directly calling `FinishCurrTalk`. The native callback path therefore prioritizes `NpcTalkRsp`, not `QuestDestroyNpcRsp`, as the immediate talk-ending message.

The AstaPS header audit found no echoed request sequence in `NpcTalkRsp` and a newly generated **server** sequence in `QuestDestroyNpcRsp`. An independent `GetPlayerSocialDetailRsp` fix documents a real 7.1 client sequence-matching requirement for **that** RPC. Whether `NpcTalkRsp` requires sequence matching for its dispatch is still unproven: its native receiver might be registered by opcode only. The isolated [candidate branch](https://github.com/RinoPaw/AstaPS/tree/fix/amber-talk-rpc-sequence-71) sends both responses with the incoming `clientSequenceId` without changing payloads. [CI proof](https://github.com/RinoPaw/Genshin-Reverse/actions/runs/38052210813) covers JAR, focused tests and non-integration suite, **not** a client playback.

Evidence: [client response callback mapping](posttalk-response-callback-71.json), [native handler disassembly](https://github.com/RinoPaw/Genshin-Reverse/actions/runs/38052537265), [native response-type uses](https://github.com/RinoPaw/Genshin-Reverse/actions/runs/38052277064). The complete stuck-vs-reconnect trace is preserved separately. Causal recovery remains unverified.

## Server descriptor cross-check and conditional field-4 candidates

The 7.1 AstaPS `protocol/7.1/protocol.desc` (SHA-256 `dfc0fe457558b86d661b24f0c0ac023a39bbbc37b95a35e603deb4c7efbedfa5`) was parsed in [workflow run 37967149153](https://github.com/RinoPaw/Genshin-Reverse/actions/runs/37967149153). The [cross-check artifact](astaps-descriptor-crosscheck.json) preserves each field:

- `PlayerSetPauseReq.is_paused = 11` (bool): **matches the exact 7.1 client serializer** at tag `0x58`. This excludes a request-side field-number mismatch for the generated AstaPS descriptor.
- `PlayerSetPauseRsp.retcode = 4` (int32): **AstaPS descriptor only**. Current-client retention of this field number is not proven.
- `SceneTimeNotify.is_paused = 1`; `PlayerTimeNotify.is_paused = 15`: server descriptor values, not independently established client parser numbers.

As a **conditional search**, if the native 7.1 pause response is still a single `int32` at field 4, and if it is handled by the recovered client `LLCGIEDMIIG` receiver class, the previously published [13 one-int32 receiver parser tags](../world-player-revive-rsp/candidate-wire-tags.csv) narrow the field-4 candidates to **22120** and **24380**. A fresh registry/metadata join of all 197 receiver signature types agrees on the 13 one-primitive-int32 candidates ([hosted run 37967365477](https://github.com/RinoPaw/Genshin-Reverse/actions/runs/37967365477)). Do not treat these conditional candidates as a response identity.

Both candidates were inspected against the pinned executable ([exact-sample disassembly](field4-receiver-candidates.json), [workflow run 37967503945](https://github.com/RinoPaw/Genshin-Reverse/actions/runs/37967503945)):

| CmdId | Native message / handler | Zero-retcode path | Nonzero-retcode path |
| --- | --- | --- | --- |
| 22120 | `IGNKDDIOJEO`, `LLCGIEDMIIG.HBCNAMCDHAH` @ `0xC257AF0` | returns at `0xC257B62` | specialized error conversion/notification |
| 24380 | `HIADLALFEFD`, `LLCGIEDMIIG.DDABJLEOBCD` @ `0xC2433E0` | returns at `0xC243417` | shared error path `0xB515410` |

**Neither inspected success path writes the receiver's `+0x1D0` pause field directly.** A separate pending-RPC/callback mechanism may still depend on an acknowledgement, so this observation does **not** rule out the ACK hypothesis. The match to `retcode = 4` is a hypothesis about the **server descriptor**, not an established fact about the native 7.1 response. Recovery of response identity and gameplay effect remains unresolved.

## Unsupported response candidates / causal hypotheses

`CmdId 2870` was the **historical 7.0** `PlayerSetPauseRsp`; it is **not promoted or assumed for 7.1**. The exact 7.1 registry binds it to `DKPJBENLNFD`, typeDefinition `81784`, slot `0x057F0B60`, GetCmdId `0x07EAAF10`. The current metadata shows four generated collection/codec fields plus one `int32`, unlike a simple retcode-only response. Its observed native type-slot xrefs are confined to generated class methods and registry construction, and the inspected `LLCGIEDMIIG` method signatures contain no handler for that type. These facts **reject copying historical 2870 as a current confirmed response**, but do not by themselves prove its complete semantics.

AstaPS currently defines `PlayerSetPauseRsp=0` and drops nonpositive opcodes in `GameSession.send()`, so its handler transmits **no** response. That server fact does **not** establish the client's post-Amber input lock mechanism. The native request sender has an ordinary generic send path; there is no recovered response handler, correlation hook or stuck-session capture proving that game control waits for this ACK.

## Remaining evidence gate

1. Capture a **decrypted, header-preserving** stuck interaction around `NpcTalkReq/Rsp(35601)`, all `5963` booleans, `1307`/`20114` time notifications, subsequent S2C messages and cutscene/plot transitions. Capture the same window after force-close/reconnect. The maintained exact-hash-guarded Frida launcher is `tools/runtime/capture_game_packets_71.py` and its hook is `capture_game_packets_71.js`. Watch `5963`, `1307` and `20114` (and the relevant dialogue/cutscene CmdIds); **unwatched headers still appear**, allowing discovery without guessing an ACK.
2. Trace client receiver/registry identity for any response candidate; recover its `GetCmdId`, handler or pending-response consumer, protobuf field numbers, direction and semantic confirmation. Do not equate adjacent time with causality.
3. If absent ACK correlates with the stuck state, prove a recovered candidate unlocks it with a focused AstaPS server regression and **full CI before client testing**. Otherwise record the rejected ACK hypothesis and identify the minimal missing post-talk state transition.
4. Promote `PlayerSetPauseRsp` into `proto/known-opcodes.csv` only after the exact-sample semantic/direction gate. Do not patch an opcode in AstaPS before this gate.

The temporary exact-sample GitHub Actions workflow and ad-hoc query wrapper used to obtain these artifacts are retired. The maintained sample acquisition, disassembly and field-displacement tools reproduce the underlying observations; the JSON outputs preserve method ownership, disassembly, registry rows, hashes and confidence boundaries.
