# Protocol artifacts

Protocol-oriented derived data belongs here.

Preferred outputs:

- `name-translation.csv`
- `known-opcodes.csv`
- `unknown-opcodes.csv`
- `message-shapes.json`

`message-shapes.json` should record parser-derived protobuf fields and wire types keyed by original message identity. This allows structural queries such as “one varint at field 6”, “string + uint32”, “repeated message field 12” or “empty message”.
