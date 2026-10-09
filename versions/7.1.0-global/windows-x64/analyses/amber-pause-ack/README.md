# Amber 35601: PlayerSetPause acknowledgement and input lock (7.1 Global)

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
