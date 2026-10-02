# UnlockTransPointRsp research log (Genshin 7.1)

This log records the investigation path, evidence strength, dead ends, corrections, and reusable artifacts for the current `UnlockTransPointRsp` recovery. Failed approaches are intentionally retained so later work does not repeat them without a changed premise. Stable conclusions belong in `docs/case-studies/unlock-trans-point-7.1.md`.

## Scope and promotion rule

Target: official global Genshin 7.1 Windows x64 client.

Pinned sample hashes used by the successful research workflows:

```text
GenshinImpact.exe    08a3086d5f3fe695f01dab61efa42e442006b18e5e475b2520df356f6a073b7d
global-metadata.dat 05ae04d7a91b91cc880217a56b0b01f3e67f845b06e894216654ec5d160e0da0
```

Do not assign `UnlockTransPointRsp` in the canonical semantic opcode table until current-client evidence uniquely binds the unlock lifecycle to one surviving response type/handler. Wire shape, local ordering, duplicated ACK machine code, registry ordering, or cross-version ordering cannot individually promote a candidate.

## Current snapshot

```text
UnlockTransPointReq
  CmdId        9369
  proto type   DMMJNICDOHM
  status       confirmed

UnlockTransPointRsp candidate A
  CmdId        36641
  proto type   NCBEHBOCBJJ
  typeDef      70557
  registry idx 4878
  type slot    0x57F9080
  handler      KLLNGCPBLMM.GDILHLIGMPI @ 0xF045790
  status       preferred candidate, not confirmed

UnlockTransPointRsp candidate B
  CmdId        20290
  proto type   MAFFAFNMEBM
  typeDef      76295
  registry idx 2466
  type slot    0x57F63D0
  handler      KLLNGCPBLMM.OAEILOAJOML @ 0xF0462A0
  status       surviving alternate, not confirmed

ScenePointUnlockNotify
  CmdId        25567
  status       confirmed

GetSceneAreaRsp
  CmdId        23366
  status       confirmed control
```

Both response candidates parse the expected one-field `int32 field 6` response shape and both compile to the same 112-byte scene ACK-handler template.

## Important correction: `0x4B2Axx` is hotfix method storage

Earlier investigation temporarily treated offsets such as `0x4B2A90` and `0x4B2AB0` as protocol/delegate registration slots. That interpretation is wrong.

The current method band proves that these offsets are per-method ILFix/hotfix delegate/cache slots. They advance by exactly eight bytes with method index, including ordinary helper methods:

```text
method_index  method                                   hotfix slot
615754        KLLNGCPBLMM.OIFANGMCKNJ                  0x4B2A70
615755        KLLNGCPBLMM.CHOHMONDPNJ                  0x4B2A78
615756        KLLNGCPBLMM.HBLEMPNBAAO                  0x4B2A80
615757        KLLNGCPBLMM.CJJIJIHCAHM                  0x4B2A88
615758        KLLNGCPBLMM.GDILHLIGMPI   / 36641        0x4B2A90
615759        KLLNGCPBLMM.GJHPOFKNMEB                  0x4B2A98
615760        KLLNGCPBLMM.OEHHCMEMGNA                  0x4B2AA0
615761        KLLNGCPBLMM.HMICLHMGNCB                  0x4B2AA8
615762        KLLNGCPBLMM.OAEILOAJOML   / 20290        0x4B2AB0
615763        KLLNGCPBLMM.LHDHFIHDFNM                  0x4B2AB8
615764        KLLNGCPBLMM.GCDHLNLACDK   / 23366        0x4B2AC0
615765        KLLNGCPBLMM.LCMIADIHLOF                  0x4B2AC8
615766        KLLNGCPBLMM.JOKPKODHAGM                  0x4B2AD0
615767        KLLNGCPBLMM.OPBPNIKCFKL                  0x4B2AD8
```

The methods read the same runtime root, dereference `[root + 0x24F40]`, then load the per-method slot and branch through an ILFix wrapper. The slot is therefore a hotfix implementation override/cache for that method, not a protocol identity or request/response registration record.

Consequences:

- `36641` being closer to the unlock sender in the `0x4B2Axx` range adds **zero independent evidence**; it only restates method ordering.
- the absence of direct writes to `0x4B2Axx` is no longer evidence about protocol registration;
- the old “protocol slot domain” / “delegate slot proximity” terminology must not be reused;
- the real protocol identity slots are the canonical registry `type_slot_rva` values such as `0x57F9080` and `0x57F63D0`.

This correction is one of the most important outcomes of the continuation because it removes a seemingly attractive but circular evidence source.

## Research path

### 1. Establish the request and semantic controls

`UnlockTransPointReq` was recovered as `DMMJNICDOHM / CmdId 9369`, with two `uint32` fields matching scene id and point id. `ScenePointUnlockNotify / CmdId 25567` was independently recovered as a current 7.1 lifecycle control. `GetSceneAreaRsp / CmdId 23366` is a useful nearby scene-handler control.

### 2. Reduce response candidates by wire shape

Starting from current 7.1 protocol types matching a one-field `int32 field 6` message, 40 structural candidates survived. Protected method-parameter metadata recovery reduced those to three real scene-controller handler parameters:

```text
36641 / NCBEHBOCBJJ
20290 / MAFFAFNMEBM
2666  / special-handler candidate
```

Comparison against the known 7.0 `UnlockTransPointRsp` handler removed `2666`. The remaining pair both match the generic ACK template.

### 3. Identify the current unlock sender

The current scene sender is:

```text
KLLNGCPBLMM.OIFANGMCKNJ @ 0xF0452B0
```

Near the submit call it constructs and fills `DMMJNICDOHM`, then passes it as the request object:

```text
0xF0453D0  write request field
0xF0453EE  write request field
0xF045415  mov rdx, rdi
0xF045418  xor r8d, r8d
0xF04541B  call EDKMMIPJHJA.DMLCLHCBOBJ @ 0x7246860
```

The generic submitter has 491 direct callers. The unlock call site contains no obvious response-type or response-handler argument. Chasing ordinary callers of the generic submitter therefore does not close the pair.

### 4. Recover exact candidate handler parameter types

The protected parameter decoder gives the local owner band:

```text
0xF0452B0  OIFANGMCKNJ      confirmed unlock sender
0xF045640  CHOHMONDPNJ      helper
0xF045710  HBLEMPNBAAO      helper
0xF045720  CJJIJIHCAHM      HAKKLGNCKJM / CmdId 26552
0xF045790  GDILHLIGMPI      NCBEHBOCBJJ / CmdId 36641
0xF045800  GJHPOFKNMEB      helper/other
...
0xF0460C0  HMICLHMGNCB      BFGEIFDEOKH handler
0xF0462A0  OAEILOAJOML      MAFFAFNMEBM / CmdId 20290
0xF046310  LHDHFIHDFNM      helper/other
0xF046780  GCDHLNLACDK      DKJCMHENKAI / GetSceneAreaRsp 23366
```

This method neighborhood still favors `36641`: it is the first surviving retcode-only ACK candidate directly after the unlock sender/helper cluster. This remains a heuristic until the neighboring methods are semantically mapped.

### 5. Cross-version sender fingerprint

The 7.1 sender has a strong 7.0 native match:

```text
7.1  KLLNGCPBLMM.OIFANGMCKNJ @ 0xF0452B0
7.0  KGCKOFPFBLA.ECEGLMADOOM @ 0xB6EA6B0
size                  0x390 in both builds
mnemonic similarity   97.27%
token similarity      81.39%
```

Known 7.0 response:

```text
UnlockTransPointRsp
  CmdId      1776
  type       CPKAHGFBBIH
  handler    KGCKOFPFBLA.NDKDCLAKKIG @ 0xB6F18D0
```

The sender mapping is strong. The response handler cannot be transferred by local position because the generic ACK template is repeated and the scene owner layout drifted.

### 6. Recover the canonical 7.1 numeric/type identities

The repository's published 4,896-row canonical registry already closes CmdId ↔ obfuscated protobuf type identity independently of semantic naming.

Relevant rows:

```text
36641
  type_name              NCBEHBOCBJJ
  type_definition_index  70557
  type_slot_rva          0x57F9080
  get_cmd_id_rva         0x13BEF180
  get_cmd_id_method      AEGNNPENLNM
  load/store             0x7F8E358 / 0x7F8E35F
  status                 static-verified-identity

20290
  type_name              MAFFAFNMEBM
  type_definition_index  76295
  type_slot_rva          0x57F63D0
  get_cmd_id_rva         0x114767D0
  get_cmd_id_method      AEGNNPENLNM
  load/store             0x7F85F70 / 0x7F85F77
  status                 static-verified-identity
```

The unresolved layer is semantic naming only: which of these two numeric/type identities is `UnlockTransPointRsp`.

### 7. Verify why ACK handler code cannot close semantics

Both candidates have the same success/error behavior:

```text
read response retcode at +0x18
if non-zero -> common error handling
if zero     -> return
hotfix branch -> per-method ILFix slot
```

There is no success-specific waypoint behavior in either handler. That makes native body similarity a handler-class classifier, not a semantic discriminator.

Likewise, the request submit path carries no explicit response callback/type argument. For this flow, searching for a direct request -> response callback edge is low-value unless a new registration layer is identified.

### 8. External same-version cross-check

`capyb2222/LunaGC_7.1.0` provides a useful independent control surface:

```text
ScenePointUnlockNotify = 25567
GetSceneAreaRsp         = 23366
```

Those agree with the current-client recovery. However that same project leaves:

```text
UnlockTransPointReq = -119
UnlockTransPointRsp = -120
```

as unresolved placeholders, while its `UnlockTransPointRsp.proto` still has the expected `int32 retcode = 6` schema. `invoker-bot/LunaGC` carries the same unresolved placeholders.

Conclusion: current public 7.1 server forks confirm the semantic schema and useful controls, but do **not** independently identify `36641` or `20290` as the response. Do not treat the placeholders or their absence as positive evidence.

## Candidate evidence matrix

| Evidence | 36641 | 20290 | Decision value |
| --- | --- | --- | --- |
| expected `int32 field 6` parser | yes | yes | tie |
| 112-byte ACK handler template | yes | yes | tie |
| exact scene handler parameter type | `NCBEHBOCBJJ` | `MAFFAFNMEBM` | tie |
| canonical CmdId/type identity | closed | closed | semantic tie |
| same current scene owner | yes | yes | tie |
| local method neighborhood | stronger | weaker | supports 36641 |
| native-neighborhood score | 0.4076 | 0.3223 | weak support for 36641 |
| `0x4B2Axx` hotfix-slot proximity | derived from method order | derived from method order | **no independent value** |
| independent external 7.1 semantic mapping | none | none | unresolved |

Current verdict: keep `36641` preferred, keep `20290` alive, confirm neither.

## 🕳️ Dead ends, traps, and corrections

### 🕳️ Mistaking ILFix hotfix slots for protocol dispatch slots

This was the major correction. `0x4B2A70`, `0x4B2A78`, `0x4B2A80`, ... advance exactly with method index, including non-protocol helpers. They are per-method hotfix storage. Slot distance is just method distance in disguise.

### 🕳️ Scanning the hotfix slot range for writers

Exact candidate scans and a wider `0x4B0000..0x4B7fff` scan found reads but no direct writes. After the hotfix-slot correction this result is expected and says nothing about protocol request/response registration. Do not extend this scan as an opcode-recovery strategy.

### 🕳️ Generic RPC submitter caller explosion

`EDKMMIPJHJA.DMLCLHCBOBJ @ 0x7246860` has 491 direct callers. Following them creates a huge graph and does not encode response identity at the unlock call site.

### 🕳️ ACK-handler machine code looks semantic but is template-generated

Both surviving candidates and multiple unrelated scene ACKs share the same tiny retcode-check/error-dispatch body. Exact machine-code similarity proves handler shape only.

### 🕳️ Direct response-handler function-pointer xrefs

Useful direct code xrefs to the handlers are absent. Re-running ordinary direct-call/direct-pointer searches is low value without a new registration anchor.

### 🕳️ Treating cross-version local position as identity

The scene owner method layout drifts between 7.0 and 7.1. The strong sender match does not imply a fixed method-distance to its response handler.

### 🕳️ Registry / TypeDefinition ordering interpolation

Global registry order and TypeDefinition order were tested against controls and are unstable across 7.0 -> 7.1. Ordering cannot decide the final semantic name.

### 🕳️ Shared-owner inference from type-slot xrefs

Req/Rsp types do not reliably expose a shared external type-slot owner even for known control pairs. Absence of a shared owner is not negative evidence.

### 🕳️ Looking for a contiguous native CmdId/flags table

The expected simple native array layout is not present in the protected current build. The canonical registry is reconstructed from verified constructor/type identities and xrefs.

### 🕳️ Metadata-usage anchor shortcuts

Protected metadata-usage recovery did not yield a unique response semantic anchor. Published/fallback usage mappings were also insufficient.

### 🕳️ Successful response payload capture can be empty

For `retcode = 0`, the response normally serializes to an empty protobuf body. Runtime validation must observe the packet header/CmdId, not only protobuf payload bytes.

### 🕳️ Static constructor as a registration list

`KLLNGCPBLMM..cctor @ 0xF074540` does not enumerate the response identities. Treating it as a simple handler-registration list did not work.

### 🕳️ Assuming a same-version private-server fork has every current opcode

LunaGC 7.1 agrees on several controls but explicitly leaves this pair unresolved. A project being version-labelled `7.1` is not evidence that every semantic opcode is solved.

### 🕳️ Re-running CI when a valid artifact already exists

Several later workflows failed after tooling changed while earlier successful artifacts still match the same pinned client hashes. Recover the older artifact first.

### 🕳️ GitHub connector workflow-runs endpoint quirk

The workflow-file runs endpoint can fail while repository-level runs remain readable. Reliable recovery path:

```text
workflow file -> commits touching file -> head SHA
             -> repository Actions runs filtered by head_sha
             -> successful run -> artifact
```

### 🕳️ Large checked-in metadata files through the connector

Large `methods.csv`, `fields.csv`, `type-methods.json`, and `registry.csv` files can exceed connector fetch limits. Prefer `genshinre query-*`, narrow research scripts, small derived artifacts, or already-produced Actions artifacts.

## Reused successful artifacts

```text
unlock-trans-point-rpc-lifecycle
  run       36874705860
  artifact  11168019318
  use       request submit edge; generic sender fan-out

trans-point-method-context
  run       36887732493
  artifact  11174923824
  use       exact candidate parameters and current owner method band

unlock-sender-fingerprint-70-71
  run       36957449474
  artifact  11206785178
  use       strong 7.0/7.1 sender fingerprint

response-neighborhood-70-71
  run       36957244143
  artifact  11205354947
  use       neighborhood heuristic; demonstrates duplicated ACK templates

scene-delegate-slot-xrefs
  run       36978637970
  artifact  11214118342
  corrected use
            evidence that 0x4B2Axx accesses are method hotfix reads, not protocol registration

scene-static-layout-71
  run       36979394339
  artifact  11215245557
  corrected use
            exposed exact 8-byte method-index progression and triggered the hotfix-slot correction

kllngcpblmm-cctor
  run       36980959091
  artifact  11214369782
  use       rules out a simple class-.cctor semantic registration list

protocol-dispatch-root-71
  run       36981016005
  artifact  11215945062
  corrected interpretation
            the scanned 0x4Bxxxx storage belongs to the ILFix/hotfix runtime path; it is not the canonical protocol registry

trans-point-xrefs
  artifact  11166782212
  use       canonical candidate registry rows and external type-slot xrefs
```

## Next decisive probes

Do not spend another iteration ranking the two retcode-only handlers by byte similarity or hotfix-slot distance. Seek a new semantic edge:

1. **Semantic elimination by neighboring rich messages.** Identify `BFGEIFDEOKH` and other richer protocol parameters in the same current scene-owner cluster. If the neighborhood around `20290` maps to a different known RPC family, eliminate `20290`; do the symmetric test around `36641`.
2. **Reflection/descriptor evidence.** Search current-client protobuf reflection, descriptor holders, string/registration objects, or other metadata that can connect an obfuscated type to a semantic message name.
3. **Real registry semantic consumers.** Use the canonical `type_slot_rva` / type identity, not `0x4B2Axx`, and look for current-client business consumers whose semantics can be independently named.
4. **Minimal runtime header probe if static recovery remains ambiguous.** Observe the response packet CmdId/header. An empty successful protobuf body alone is insufficient.

The response is closed only when one candidate gains a unique current-client semantic binding or the other is independently identified as a different message.