# Protocol artifacts

Protocol-oriented derived data for the exact 7.1 target client belongs here. Keep semantic claims separate from the canonical numeric/type identity registry unless they have passed the target-client evidence gate.

## Current committed artifacts

### `known-opcodes.csv`

Evidence-gated current-client semantic mappings. This is intentionally a small partial set, not a complete opcode table.

Every row must:

- have a unique CmdId;
- identify a concrete semantic message name;
- have a confirmed `C2S` or `S2C` direction;
- carry `status = CONFIRMED`;
- record the evidence supporting promotion.

`genshinre.registryxrefpublish` uses these rows only as supplemental semantic/direction enrichment for the already-closed canonical registry identity map. The publisher and version validator reject weaker statuses or semantic drift between this file and `registry/registry.csv`.

Keep `CANDIDATE`, `HIGH_CONFIDENCE`, competing identities and unresolved names in the relevant `analyses/<topic>/` evidence until they satisfy the promotion gate. Historical opcode equality and external-project mappings remain supporting evidence only.

### `message-shapes.json`

Parser-derived protobuf fields and wire types keyed by original message identity. It supports structural queries such as “one varint at field 6”, “string + uint32”, “repeated message field 12” or “empty message”. Structural parser recovery does not by itself assign a semantic message name.

## Future protocol artifacts

`name-translation.csv` and `unknown-opcodes.csv` may be added when there is durable data that benefits from those separate views. Do not create empty placeholder datasets merely to match an early directory plan.
