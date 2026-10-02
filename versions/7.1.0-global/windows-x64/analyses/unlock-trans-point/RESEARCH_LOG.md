# UnlockTransPointRsp research log (Genshin 7.1)

This log records the investigation path, evidence strength, dead ends, and reusable artifacts for the current `UnlockTransPointRsp` recovery. It intentionally keeps failed approaches that should not be repeated without a changed premise. The compact case study in `docs/case-studies/unlock-trans-point-7.1.md` remains the place for stable conclusions.

## Scope and promotion rule

Target: official global Genshin 7.1 Windows x64 client.

Pinned sample hashes used by the successful research workflows:

```text
GenshinImpact.exe   08a3086d5f3fe695f01dab61efa42e442006b18e5e475b2520df356f6a073b7d
global-metadata.dat 05ae04d7a91b91cc880217a56b0b01f3e67f845b06e894216654ec5d160e0da0
```

Current promotion rule: do not assign `UnlockTransPointRsp` in the canonical opcode table until current-client evidence uniquely binds the confirmed request lifecycle to one surviving response type/handler. Native similarity, local ordering, field shape, slot proximity, or cross-version ordering may support a candidate but cannot individually promote it to confirmed.

## Current snapshot

```text
UnlockTransPointReq
  CmdId        9369
  proto type   DMMJNICDOHM
  status       confirmed

UnlockTransPointRsp candidate A
  CmdId        36641
  proto type   NCBEHBOCBJJ
  handler      KLLNGCPBLMM.GDILHLIGMPI @ 0xF045790
  delegate     0x4B2A90
  status       preferred strong candidate, not confirmed

UnlockTransPointRsp candidate B
  CmdId        20290
  proto type   MAFFAFNMEBM
  handler      KLLNGCPBLMM.OAEILOAJOML @ 0xF0462A0
  delegate     0x4B2AB0
  status       surviving alternate, not confirmed

ScenePointUnlockNotify
  CmdId        25567
  status       confirmed
```

Both response candidates parse the expected one-field `int32 field 6` response shape and both compile to the same 112-byte scene ACK-handler template. That equivalence is the central reason the final identity is still open.

## Research path

### 1. Establish the current request and semantic controls

`UnlockTransPointReq` was recovered as `DMMJNICDOHM / CmdId 9369`, with two `uint32` fields matching scene id and point id. `ScenePointUnlockNotify / CmdId 25567` was independently recovered as a current 7.1 control for the unlock lifecycle.

This gave a reliable semantic anchor without copying historical opcodes forward from 7.0.

### 2. Reduce response candidates by wire shape

Starting from current 7.1 protocol types whose parser matched a single `int32 field 6`, 40 structural candidates survived. Protected method-parameter metadata recovery reduced those to three real scene-controller handler parameters:

```text
36641 / NCBEHBOCBJJ
20290 / MAFFAFNMEBM
2666  / another special-handler shape
```

Comparison with the known 7.0 `UnlockTransPointRsp` native handler removed `2666`. The remaining pair both match the generic scene ACK template.

Reusable result from this step: the protected 7.1 method-parameter decoder is valuable beyond this case because it turns an obfuscated method body into a concrete protocol parameter type.

### 3. Identify the current unlock sender

The current scene owner method is:

```text
KLLNGCPBLMM.OIFANGMCKNJ @ 0xF0452B0
```

Near the submit call it constructs and fills the request object, then passes it as `rdx`:

```text
0xF0453D0  write request field
0xF0453EE  write request field
0xF045415  mov rdx, rdi
0xF045418  xor r8d, r8d
0xF04541B  call EDKMMIPJHJA.DMLCLHCBOBJ @ 0x7246860
```

The generic submitter has 491 direct callers. Its arguments do not expose an obvious response protocol type or response handler pointer. This establishes the request send edge, but does not close the request/response pair.

### 4. Recover exact candidate handler parameter types

A successful pre-existing method-context artifact decoded the local owner band around the sender:

```text
0xF0452B0  KLLNGCPBLMM.OIFANGMCKNJ      confirmed unlock sender
0xF045640  KLLNGCPBLMM.CHOHMONDPNJ      helper
0xF045710  KLLNGCPBLMM.HBLEMPNBAAO      helper
0xF045720  KLLNGCPBLMM.CJJIJIHCAHM      HAKKLGNCKJM / CmdId 26552
0xF045790  KLLNGCPBLMM.GDILHLIGMPI      NCBEHBOCBJJ / CmdId 36641
0xF045800  KLLNGCPBLMM.GJHPOFKNM        helper/other
...
0xF0460C0  KLLNGCPBLMM.HMICLHMGNCB      BFGEIFDEOKH handler
0xF0462A0  KLLNGCPBLMM.OAEILOAJOML      MAFFAFNMEBM / CmdId 20290
0xF046310  KLLNGCPBLMM.LHDHFIHDFNM      helper/other
```

This is strong local evidence for `36641`: it is the first surviving one-field ACK candidate immediately after the unlock sender cluster. It is still neighborhood evidence, so it is not sufficient for confirmation.

### 5. Cross-version sender fingerprint

The 7.1 sender has a strong 7.0 native match:

```text
7.1  KLLNGCPBLMM.OIFANGMCKNJ @ 0xF0452B0
7.0  KGCKOFPFBLA.ECEGLMADOOM @ 0xB6EA6B0
size                  0x390 in both builds
mnemonic similarity   97.27%
token similarity      81.39%
```

The known 7.0 response is:

```text
UnlockTransPointRsp
  CmdId      1776
  type       CPKAHGFBBIH
  handler    KGCKOFPFBLA.NDKDCLAKKIG @ 0xB6F18D0
```

This validates the sender identity and provides a historical control, but the response layout is not stable enough across versions to transfer the handler by simple position.

### 6. Compare delegate/static slots

Observed slots:

```text
7.0 unlock sender      0x36E6E8
7.0 unlock response    0x36E970

7.1 unlock sender      0x4B2A70
7.1 candidate 36641    0x4B2A90
7.1 candidate 20290    0x4B2AB0
7.1 GetSceneAreaRsp    0x4B2AC0   control
```

The two 7.1 candidates are both real one-parameter scene protocol handlers, and `36641` is closer to the sender slot. The 7.0 sender-to-response slot spacing is very different, so cross-version slot distance is not an identity mapping.

### 7. Trace exact delegate-slot xrefs

A full exact-displacement trace for the scene controls found only reads for all relevant slots:

```text
0x4B2A70  unlock sender      read only
0x4B2A90  rsp 36641          read only
0x4B2AB0  rsp 20290          read only
0x4B2AC0  GetSceneAreaRsp    read only
```

No direct write to either candidate slot was found. The handlers read the delegate and dispatch through it, but the registration edge is hidden behind the IL2CPP static/runtime initialization machinery.

### 8. Scan the whole protocol slot domain for writers

The wider current-client scan covered aligned displacements in `0x4B0000..0x4B7fff` and explicitly retained writes, RMW operations, and address-taking instructions.

Result:

```text
raw slot candidates       12360
aligned slot candidates    4142
validated slot writes         0
```

The upstream `0x24F40` table access is extremely common (over one million validated reads), while the protocol-slot domain has no visible direct writer in executable code. This closes the direct-native-write hypothesis: expanding the same xref scan is not useful.

### 9. Inspect the scene static constructor

`KLLNGCPBLMM..cctor @ 0xF074540` is only 96 bytes and initializes a separate static object/field path. It does not directly initialize the `0x4B2Axx` protocol delegate slots. Therefore the candidate binding is not recoverable by treating the class static constructor as a simple list of handler assignments.

## Candidate evidence matrix

| Evidence | 36641 | 20290 | Decision value |
| --- | --- | --- | --- |
| expected `int32 field 6` parser | yes | yes | tie |
| 112-byte ACK handler template | yes | yes | tie |
| exact scene handler parameter type | `NCBEHBOCBJJ` | `MAFFAFNMEBM` | tie |
| same current scene owner | yes | yes | tie |
| local sender neighborhood | stronger | weaker | supports 36641 |
| native-neighborhood score | 0.4076 | 0.3223 | supports 36641 |
| delegate slot proximity | closer | farther | weak support only |
| direct slot write / registration edge | none found | none found | unresolved |
| independent external 7.1 semantic mapping | none | none | unresolved |

Current verdict: keep `36641` preferred, keep `20290` alive, confirm neither.

## 🕳️ Dead ends and traps

### 🕳️ Generic RPC submitter caller explosion

`EDKMMIPJHJA.DMLCLHCBOBJ @ 0x7246860` has 491 direct callers. Following ordinary callers of the generic sender creates a huge graph and does not encode the response identity. Only a concrete response callback/type edge would make this path useful again.

### 🕳️ ACK-handler machine code looks unique but is template-generated

Both surviving candidates and the known historical control share a tiny retcode-check/delegate-dispatch pattern. Native similarity confirms handler class, not semantic message identity.

### 🕳️ Direct response-handler function-pointer xrefs

Useful direct code xrefs to the response handlers are absent. Registration is mediated through metadata/method-pointer/static runtime structures. Re-running ordinary direct-call or direct-pointer searches is low value.

### 🕳️ Direct delegate-slot write search

Exact candidate-slot scans and a domain-wide `0x4B0000..0x4B7fff` scan found zero direct writes/address-taking operations. The premise that registration will appear as `mov [base + 0x4B2A90], ...` is disproven for this build.

### 🕳️ Treating slot distance as cross-version identity

7.0 and 7.1 slot layouts drift. `36641` being closer to the sender is useful local evidence, not a stable cross-version mapping rule.

### 🕳️ Registry / TypeDefinition ordering interpolation

Global registry order and TypeDefinition order were tested against controls and are unstable across 7.0 -> 7.1. A control produced poor/negative correlation. Ordering heuristics must not decide the final CmdId.

### 🕳️ Shared-owner inference from type-slot xrefs

The attractive assumption that Req/Rsp types should expose a shared external owner failed even on a known request/response control pair. Absence of a shared xref is not negative evidence.

### 🕳️ Looking for a contiguous native CmdId/flags table

The expected simple native array layout was not present in the protected current build. Treat the registry as reconstructed structure, not as an assumed contiguous C array.

### 🕳️ Metadata-usage anchor shortcuts

Protected metadata-usage recovery did not yield a unique stable anchor for the response. Published/fallback mappings were also insufficient for the exact request anchor.

### 🕳️ Successful response packet capture can be empty

For `retcode = 0`, `UnlockTransPointRsp` normally serializes to an empty protobuf body. Capturing only the payload cannot distinguish two empty-response protocol types. A runtime probe must observe the packet CmdId/header or deliberately force a non-zero response with understood semantics.

### 🕳️ Static constructor as a registration list

`KLLNGCPBLMM..cctor` does not enumerate or directly fill the candidate protocol slots. The actual mapping is deeper in IL2CPP runtime/static-field machinery.

### 🕳️ Re-running CI when a valid artifact already exists

Several later research workflows failed after tooling changed, while older successful artifacts remain valid for the same pinned client hashes. Prefer recovering the successful artifact by commit SHA and run id instead of spending time reproducing it.

### 🕳️ GitHub connector workflow-runs endpoint quirk

With the current connector, querying runs through the workflow-file endpoint can fail even though repository-level Actions runs are readable. Reliable recovery path:

```text
workflow file -> commits touching that file -> head SHA
             -> repository Actions runs filtered by head_sha
             -> successful workflow run -> artifact
```

This path recovered all artifacts used in the current continuation without starting a new CI run.

### 🕳️ Large checked-in metadata files through the connector

Large files such as `type-methods.json` can exceed connector fetch limits. Prefer the smaller indexed CSV queries, purpose-built scripts, or already-produced Actions artifacts. Do not repeatedly attempt full-file fetches when the connector has already rejected the size.

## Reusable successful artifacts recovered in this continuation

These artifacts were reused instead of rerunning CI. They are ephemeral Actions artifacts, so durable conclusions are copied into this log/case study.

```text
unlock-trans-point-rpc-lifecycle
  run       36874705860
  artifact  11168019318
  use       confirmed request submit edge; showed generic sender fan-out

trans-point-method-context
  run       36887732493
  artifact  11174923824
  use       exact candidate parameter types, method band, delegate slots

unlock-sender-fingerprint-70-71
  run       36957449474
  artifact  11206785178
  use       7.0/7.1 sender fingerprint and static-slot controls

scene-delegate-slot-xrefs
  run       36978637970
  artifact  11214118342
  use       proved candidate/control slots are read-only in direct native xrefs

scene-static-layout-71
  run       36979394339
  artifact  11215245557
  use       enumerated scene slot domain and 91 owner fields / 28 generic field types

kllngcpblmm-cctor
  run       36980959091
  artifact  11214369782
  use       ruled out simple .cctor-based candidate registration

protocol-dispatch-root-71
  run       36981016005
  artifact  11215945062
  use       domain-wide scan: zero direct protocol-slot writers
```

## Next decisive probes

Do not spend another iteration on candidate ranking. The next work should seek a new class of edge:

1. decode `KLLNGCPBLMM` generic static-field types far enough to recover the delegate generic argument associated with candidate/control slots;
2. use known controls such as `GetSceneAreaRsp`, `EnterWorldAreaRsp`, `ScenePointUnlockNotify`, and `SceneTransToPointRsp` to validate any field-ordinal -> native-slot mapping before applying it to `0x4B2A90/0x4B2AB0`;
3. recover the IL2CPP/static-field registration structure behind the `0x24F40` indirection rather than scanning for direct native slot writes;
4. if static recovery remains ambiguous, perform a minimal runtime experiment that observes the packet CmdId/header, not merely the protobuf body.

The result is considered closed only when one surviving candidate gains a unique current-client semantic binding or the other is independently identified as a different protocol message.