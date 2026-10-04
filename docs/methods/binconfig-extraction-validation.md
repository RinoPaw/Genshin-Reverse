# BinConfig extraction validation

Use this method when a published `BinOutput` / `ExcelBinOutput` table looks semantically wrong and we need to distinguish game data from extraction damage.

The goal is to recover the table directly from the exact client sample with enough structural checks that a plausible JSON shape is not mistaken for a correct decode.

## Evidence layers

Keep these layers separate:

1. **Exact client serialized table** — the bytes stored in the supported build.
2. **Recovered row schema** — how the client deserializer reads those bytes.
3. **Direct decoded rows** — output produced from 1 + 2 without semantic patching.
4. **Published resource JSON** — AnimeGameData / resource-pack output.
5. **Post-processing / flattening** — mergers, converters, compatibility transforms.
6. **Historical references** — useful correctness/navigation evidence, never a substitute for the current client.

A mismatch between layers 3 and 4 points at extraction/publication. A mismatch already present between layers 1/3 and a source-form table may be genuine current data or a different representation and needs further proof.

## Recovery path

For a target table such as `Data/_ExcelBinOutput/QuestExcelConfigData`:

1. Find the exact path literal or another exact table identity anchor in the supported executable.
2. Follow xrefs into the owning loader/container code.
3. Recover the row type and row-deserializer method from current IL2CPP metadata/native relations.
4. Reconstruct field order, optional/presence masks, container lengths, nested row readers and value transforms from the deserializer.
5. Locate the exact serialized table blob in the local client assets.
6. Decode without inserting semantic defaults, guessed enum values, compatibility conditions or hand-written quest logic.

Do not start from the published JSON and reverse-fit a schema that merely reproduces it.

## Structural acceptance checks

A decode is stronger when it satisfies independent invariants:

- the declared row count is plausible and fully consumed;
- every row parses without switching to a fallback interpretation;
- the decoder consumes the complete table payload with no unexplained trailing bytes;
- nested container counts and presence masks stay within bounds;
- independently recovered field types/offsets agree with the row deserializer;
- a second path such as another serializer/parser/consumer agrees where available.

Exact byte consumption is especially useful because many wrong schemas can produce plausible early rows while drifting later in the blob.

## Schema repair discipline

If the first recovered schema fails, classify the failure before changing it. Candidate corrections may include field width, optionality/presence polarity, container-length width, scalar/container classification or a missed nested deserializer.

A schema mutation is accepted only if it improves the exact-client structural proof. Do not choose a mutation because it restores the gameplay value we expected.

When several schemas consume the blob successfully, preserve the ambiguity and seek another independent invariant. Successful parsing alone does not establish semantics.

## Quest-specific rule

For Quest prerequisite work, preserve these fields independently:

- condition multiplicity and ordering;
- condition type and full parameter payload;
- `acceptCondComb` / finish/fail combiners;
- genuine absence versus explicit sentinel-like values;
- source `BinOutput/Quest` identity versus flattened `QuestExcelConfigData` identity.

Never globally reinterpret `QUEST_COND_STATE_EQUAL [0,3]`. Existing 7.1 evidence contains both corrupted flattened rows and legitimate source roots.

Representative validation should include a simple predecessor, a legitimate root, a compound OR case, a compound AND case and a state-drift case.

## External method leads

Historical Grasscutter resource tools demonstrate that post-processing layers have sometimes inserted synthetic conditions or coerced condition combiners. That history is a warning, not current-version proof.

A modern public 7.0 research toolkit independently demonstrates a useful general pattern: recover `Data/_ExcelBinOutput/*` loaders/deserializers from client metadata/native xrefs, decode candidate blobs, and reject candidates that do not consume the payload exactly. Reproduce the underlying method independently and bind all published results to our exact Global target.

## Publication

When the method closes an investigation:

- record executable/metadata hashes and resource revision;
- publish machine-readable schema/evidence, not raw proprietary blobs;
- state which layer introduced each confirmed mismatch;
- keep rejected transforms when they prevent the same bad fix from returning;
- promote reusable extraction logic into `genshinre/` only after it works beyond the one target table.

Tracking consumer: issue #8 for the 7.1 Quest prerequisite extraction root cause.
