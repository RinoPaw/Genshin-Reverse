# Protocol dump audit workflow

This is adapted from the AstaPS `play/rino` protocol-compiler workflow into a repository-neutral process.

A client update can independently change semantic names, CmdIds, protobuf fields and UnionCmd ids. Treat a proto dump as static evidence and compare it with runtime and client-static evidence before publishing a final mapping.

Recommended pipeline:

```text
raw proto/name translation
→ static extraction
→ conflict/duplicate audit
→ proposed semantic name ↔ CmdId map
→ client registry / GetCmdId cross-check
→ runtime observation
→ confirmed versioned mapping
```

Static audits should explicitly report duplicate CmdIds, one semantic name mapping to multiple ids, unresolved names, server/project mismatches and entries missing from either side. Unknown obfuscated identities should remain unknown until evidence supports a semantic translation.

Keep raw inputs under ignored local directories. Commit the compact machine-readable audit output and the generating tool.
