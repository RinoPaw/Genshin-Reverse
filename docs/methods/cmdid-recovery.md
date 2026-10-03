# Recovering an unknown CmdId from client logic

This workflow is distilled from the 7.1 born-protocol work originally documented on `RinoPaw/AstaPS` branch `play/rino`. It is intended for cases where local proto names, old mappings and server implementations are incomplete.

The most productive direction is usually:

```text
observable successful client behavior
→ UI / state transition
→ consumer or producer function
→ network handler / sender
→ obfuscated message type
→ GetCmdId
→ protobuf parser / serializer
→ minimal runtime validation
```

## 1. Define the success behavior first

Start from what the correct packet should cause. Examples include closing a page, clearing a pending flag, changing a map point state, entering a scene or advancing a state machine. This gives static analysis a concrete consumer to find.

## 2. Build reliable anchors

Use already-confirmed packet types, UI classes, managers, known request senders and handlers as graph anchors. Obfuscated names are still valuable if metadata binds them consistently to type/method definitions.

## 3. Trace consumers and producers broadly

Do not restrict xrefs to direct `call rel32`. IL2CPP-heavy code frequently uses:

- tail `jmp`;
- virtual/interface dispatch;
- delegate/event registration;
- generic trampolines;
- lifecycle dispatchers;
- CmdId switch/case dispatch.

The 7.1 `SetPlayerBornDataRsp` recovery required following a tail-jump chain into a dispatcher; a direct-call-only search would have missed the relevant caller.

## 4. Bind the handler to its message type

Once a network handler or request sender is found, identify its obfuscated packet type. Then locate that type's protocol interface methods, especially:

```text
GetCmdId
Parser / MergeFrom
Serialize
```

A small method that returns a constant from the protocol interface slot is among the strongest static CmdId signals.

## 5. Recover protobuf shape from the parser

Prefer parser logic over assumptions from an old/local proto. Look for `readTag`, comparisons against tag constants, typed reads and stores into the message object.

```text
tag = field_number << 3 | wire_type
```

Common wire types: `0` varint, `1` fixed64, `2` length-delimited, `5` fixed32.

Examples: `0x38` means field 7 / wire 0; `0x62` means field 12 / wire 2.

Record recovered shapes in `proto/message-shapes.json` so future investigations can query by structure rather than repeat parser analysis.

## 6. Use minimal runtime probes

One experiment should change one variable. If a response appears to contain only a success retcode whose default is zero, testing the candidate CmdId with an empty protobuf payload cleanly separates opcode/handler correctness from a possibly wrong field number.

Avoid invoking a large login/world lifecycle as a protocol probe: it sends many packets and creates unrelated state changes that destroy causal clarity.

## 7. Preserve failures

Keep tested candidates and the evidence that rejected them in the focused analysis record or Git history. Negative runtime experiments and mismatching parser tags can save hours later; they do not require a second live implementation path.

## 8. Final confirmation

A strong closure looks like:

```text
matching sample hashes
+ canonical registry identity
+ parser shape
+ handler or sender context
+ isolated runtime behavior
= CONFIRMED mapping
```

## Registry-first fast path

For the current 7.1 target, begin with the closed canonical registry instead of rebuilding identity from exploratory metadata-usage or candidate-convergence probes.

A current registry row contains the exact slot/type/CmdId identity and its provenance:

```csv
index,cmd_id,type_name,type_definition_index,direction,direction_status,semantic_name,type_slot_rva,get_cmd_id_rva,get_cmd_id_method,load_rva,store_rva,xref_count,xref_method_count,status,evidence
48,186,NLOMEGMJDGJ,61556,...,...,...,0x057F3858,0x09ED2160,AEGNNPENLNM,...,...,...,...,static-verified-identity,...
```

Routine lookup:

```bash
genshinre query-registry \
  versions/7.1.0-global/windows-x64/registry/registry.csv \
  --cmd-id 186
```

The maintained identity chain is:

```text
verified constructor/type slots
+ current GetCmdId candidates
+ dominant registry-slot xrefs
→ strict 4,896-row canonical registry
```

From the registry row, use metadata indexes, signature references, handler/sender evidence and focused analysis records to answer the semantic question. Do not restart the retired metadata-usage/type convergence path merely to rediscover an identity already present in `registry.csv`.
