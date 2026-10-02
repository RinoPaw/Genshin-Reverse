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

Structural protobuf evidence keyed by the current working message identity. Entries may come from current-client parser/static recovery or from narrower runtime wire observations; `status` and `evidence` keep those evidence levels distinct.

Each message records a CmdId, direction, evidence status and a field list. Field entries minimally preserve protobuf field number and wire type, with optional likely type, semantic label or observed runtime bytes. This supports structural queries such as “one varint at field 6”, “string + uint32”, “repeated message field 12” or “empty message” without forcing an unresolved message to receive a semantic name.

The machine-readable contract is `schemas/message-shapes.schema.json`; `genshinre validate` enforces the core structure with no extra runtime dependency. A structurally confirmed shape does not by itself promote a semantic message name into `known-opcodes.csv`.

## Future protocol artifacts

`name-translation.csv` and `unknown-opcodes.csv` may be added when there is durable data that benefits from those separate views. Do not create empty placeholder datasets merely to match an early directory plan.
