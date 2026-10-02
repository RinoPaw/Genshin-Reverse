# CmdId observation summary

`observations.csv` is the version-level semantic observation summary for the exact 7.1 target. It is not a raw packet trace.

Current columns:

```text
name,cmd_id,direction,status,evidence
```

Use it to preserve compact investigation state such as:

- a semantic message whose current 7.1 CmdId is confirmed;
- an observed unknown CmdId with a stable working identity such as `UNKNOWN_186`;
- an unresolved semantic target whose current CmdId is still blank;
- candidate mappings that should remain visibly below the canonical promotion gate.

A row must have a non-empty name, valid direction/status and non-empty evidence. `cmd_id` may be blank only when the current numeric mapping is still unresolved. Ordinary CI validates the committed table through `genshinre.cmdobservations`.

Raw server traces belong in `work/` or focused analysis artifacts. `genshinre import-trace` emits a separate packet-by-packet CSV contract:

```text
timestamp,offset_ms,direction,cmd_id,name,length,payload_hex,source
```

Do not append raw trace rows to `cmdids/observations.csv`, and do not treat this summary table as a replacement for `proto/known-opcodes.csv`. Confirmed semantic promotion still follows the protocol evidence gate.
