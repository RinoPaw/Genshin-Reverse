# Analysis contract

Focused investigations under `versions/<sample>/analyses/<topic>/` should preserve enough state for another researcher to continue without reconstructing the investigation from chat history or the executable.

The narrative `README.md` remains the human entry point. Add `evidence.json` when an investigation contains claims that should be queried, compared or promoted later. Extra CSV/JSON artifacts are encouraged when they preserve candidate sets, runtime traces, xrefs or rejected paths.

## Separate workflow state from evidence confidence

`state` describes the investigation itself:

- `ACTIVE`: useful work remains and the next step is known;
- `BLOCKED`: progress depends on a missing sample, runtime capture or other explicit dependency;
- `COMPLETE`: the scoped questions have been answered to the required evidence level.

Each claim carries its own evidence status:

- `CONFIRMED`
- `HIGH_CONFIDENCE`
- `CANDIDATE`
- `REJECTED`
- `UNRESOLVED`

Do not use investigation state as evidence strength. An active investigation may already contain confirmed claims, and a complete investigation may intentionally end with a rejected hypothesis.

## `evidence.json`

Use `schemas/analysis-evidence.schema.json`. At minimum record:

- a stable topic id;
- the exact version/region/platform and a reference to the sample hashes;
- the questions being investigated;
- claim-specific status, statement and evidence references;
- rejected paths when preserving them prevents repeated work;
- produced artifacts;
- concrete next steps while the investigation remains active.

Evidence references should identify the source strongly enough to recover it later. Repository sources should include a commit/revision and path when possible. Runtime evidence should identify the trace/capture artifact and experiment context. Historical or cross-project evidence must stay labeled as such.

## Promotion rule

`analyses/` is allowed to contain partial and competing hypotheses. Canonical datasets such as `registry/registry.csv`, `proto/message-shapes.json` and `xrefs/*.csv` keep their own publication gates. A candidate in an analysis never becomes canonical merely because it is the best remaining candidate.

When a claim is promoted, preserve the stable client identity that led to it: obfuscated type, typeDefinitionIndex, method index/RVA, CmdId, resource path or another sample-bound anchor as applicable.

## Rejected paths

Keep a rejected path when it saves meaningful future work. Record what was tested, why it was rejected and the evidence that ruled it out. Deleting failed hypotheses makes reverse engineering unnecessarily repetitive.

## Adoption

New investigations should use this contract. Existing investigations can be migrated when they are next touched; there is no need for a repository-wide formatting-only rewrite.
