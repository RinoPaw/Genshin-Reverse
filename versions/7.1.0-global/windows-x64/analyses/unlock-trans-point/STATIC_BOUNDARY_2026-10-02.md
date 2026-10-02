# UnlockTransPointRsp static-recovery boundary — 2026-10-02

This note continues `RESEARCH_LOG.md` and records the point where the current static evidence stopped adding semantic discrimination between the two surviving 7.1 response candidates.

## Latest candidate state

```text
UnlockTransPointReq = 9369 / DMMJNICDOHM     confirmed

candidate A
  CmdId       36641
  type        NCBEHBOCBJJ
  handler     KLLNGCPBLMM.GDILHLIGMPI @ 0xF045790
  method idx  615758

candidate B
  CmdId       20290
  type        MAFFAFNMEBM
  handler     KLLNGCPBLMM.OAEILOAJOML @ 0xF0462A0
  method idx  615762
```

Both remain unresolved. Earlier preference for `36641` came mainly from local method neighborhood. The continuation below showed that local/cross-version order is too unstable to carry meaningful promotion weight, so the two candidates should now be treated as a semantic tie until a new evidence class appears.

## Full decoded-signature reference check

A lightweight exact-table scan was added as `.github/workflows/check-7.1-unlock-rsp-external-refs.yml` and run against the checked-in current `metadata/methods.csv`.

Successful run:

```text
run       37004973598
artifact  unlock-rsp-external-refs-71
artifact id 11224837704
```

Results:

```text
NCBEHBOCBJJ / 36641
  references          2
  self references     CopyFrom
  external references 1
  external target     KLLNGCPBLMM.GDILHLIGMPI @ 0xF045790

MAFFAFNMEBM / 20290
  references          2
  self references     CopyFrom
  external references 1
  external target     KLLNGCPBLMM.OAEILOAJOML @ 0xF0462A0

DBNMIKBJIPE / ScenePointUnlockNotify 25567
  external references 1
  external target     KLLNGCPBLMM.IPADDHFIGMF @ 0xF05F0F0

DKJCMHENKAI / GetSceneAreaRsp 23366
  external references 1
  external target     KLLNGCPBLMM.GCDHLNLACDK @ 0xF046780
```

The controls show the scan is behaving as expected: protocol response/notify types typically expose their scene handler as the only external decoded signature reference. Neither response candidate exposes a second consumer, return-type use, callback, factory, or other semantic edge in the current decoded method table.

## Submit call calling-convention check

The confirmed unlock sender performs:

```text
0xF045405  mov rcx, [rax + 0xA110]
0xF045415  mov rdx, rdi        ; request object
0xF045418  xor r8d, r8d        ; second explicit argument = 0
0xF04541B  call 0x7246860      ; EDKMMIPJHJA.DMLCLHCBOBJ
```

Metadata reports `DMLCLHCBOBJ` with parameter count 2. The immediately preceding native call at `0xF0453DC` also means a stale volatile `r9` value cannot be treated as a meaningful response binding. No trustworthy response `Type`, callback, or generic `MethodInfo` argument is visible at the submit edge.

## Cross-version semantic controls recovered during continuation

The public 7.0 packet map plus a named 7.0 LunaGC opcode table gives useful controls:

```text
CFBLHIJCOEN  = 8813   = UnlockTransPointReq
CPKAHGFBBIH  = 1776   = UnlockTransPointRsp
PANBIAIAIDH  = 7929   = ScenePointUnlockNotify
NHIAAMFAPEG  = 1717   = PersonalSceneJumpRsp
GKDMGDMHPCF  = 20709  = PlayerQuitDungeonRsp
OPKHJMGDMAD  = 9878   = DungeonDieOptionRsp
```

The last four examples matter because several of these unrelated responses compile to the same small ACK template as the historical `UnlockTransPointRsp`. Exact/native-template equality therefore classifies handler shape only.

A useful positive cross-version control was also recovered:

```text
7.0 PANBIAIAIDH / ScenePointUnlockNotify / CmdId 7929
    large scene handler
        -> 7.1 DBNMIKBJIPE / ScenePointUnlockNotify / CmdId 25567
```

The native match is strong, but nearby owner methods do not preserve order globally enough to transfer the old Unlock response position.

## New 🕳️: monotonic scene-owner alignment

A temporary hypothesis used several strong non-template anchors and appeared promising:

```text
7.1 unlock sender       -> 7.0 owner position 76
7.1 BFGE... handler     -> 7.0 owner position 135
7.0 UnlockTransPointRsp -> owner position 157
7.1 GetSceneAreaRsp     -> 7.0 owner position 250
```

Taken literally this would place the historical response after the BFGE anchor and would seem to favor current `20290` over `36641`.

Validation against additional large, distinctive methods disproved the premise. Methods from the same small historical window map to widely separated current owner positions (examples included current positions 13, 67, 111, 185 and 317). The scene controller underwent substantial method reordering between 7.0 and 7.1.

Conclusion: cross-version native fingerprints are useful for identifying individual distinctive methods, but owner position is not a monotonic coordinate system. Do not use sequence interpolation to choose the response.

## New 🕳️: local protocol adjacency implies business family

Current methods near the two candidates include scene and dungeon protocol traffic in a short span. For example `GetSceneAreaRsp / 23366` is followed only a few methods later by a type independently named `DungeonEntryInfoRsp / 9782` in the same-version public opcode table.

Conclusion: local scene-owner adjacency is an implementation-layout fact, not a reliable RPC-family grouping. This further weakens the old local-neighborhood preference for `36641`.

## New 🕳️: ILFix trampoline mistaken for gameplay callback

Both candidate ACK handlers begin with an ILFix/hotfix check. If the hotfix flag is enabled, they dereference the runtime hotfix table and branch through their per-method `0x4B2Axx` slot.

Normal, unpatched path:

```text
response == null -> common null/error path
retcode != 0     -> common error handler
retcode == 0     -> ret
```

There is no success-specific waypoint callback in either native body. The indirect branch through `0x4B2A90` or `0x4B2AB0` is method replacement infrastructure and cannot be chased back to request semantics.

Conclusion: do not search these ACK bodies for a business callback registration edge unless a genuinely new runtime registration structure is identified.

## New 🕳️: forcing either candidate on the private server as a semantic test

A private-server experiment that merely sends `36641` or `20290` with `retcode = 0` is weak: both client handlers accept the same shape and their success paths simply return. “The client looked fine” cannot identify which semantic name belongs to the packet.

A runtime test becomes decisive only when it observes what a known-correct 7.1 server actually sends in response to the real unlock flow, or when another independent semantic source binds one obfuscated type.

## Current static boundary

The current client statically establishes:

```text
9369  -> DMMJNICDOHM -> confirmed UnlockTransPointReq
36641 -> NCBEHBOCBJJ -> one-field retcode ACK -> scene ACK handler
20290 -> MAFFAFNMEBM -> one-field retcode ACK -> scene ACK handler
```

It does not currently expose a second decoded signature reference, success callback, generic submit response parameter, stable owner-order relation, or public same-version semantic label that distinguishes the two ACK types.

The next maintained evidence step is therefore `RUNTIME_PROBE.md`: observe the decrypted packet header CmdId in a genuine 7.1 unlock transaction. The companion parser is `tools/parse_decrypted_game_packet.py`.
