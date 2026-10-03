# Tools

`tools/` contains narrow research helpers that intentionally do not belong on the primary `genshinre` CLI surface.

Reusable repository functionality belongs in `genshinre/`. Maintained multi-step target workflows belong in `scripts/`. Keep a tool here only when its value depends on an exact sample, fixed native boundary, independent decoder, or focused research operation.

Current helpers:

- `decode_protocol_handler_parameters_71.py` independently decodes exact-7.1 parameter records and checks known handler controls. It stays separate from the normal decoded metadata path so it remains an independent evidence layer.
- `disassemble_rva.py` is the small generic exact-sample RVA disassembler used by the opt-in disassembly workflow and focused investigations.
- `locate_game_packet_framing_71.py` reproduces the exact-client packet-framing boundary used by the maintained runtime capture evidence.
- `parse_decrypted_game_packet.py` validates and parses already-decrypted `0x4567 ... 0x89AB` game frames without requiring a protobuf schema.
- `trace_native_call_edges.py` traces focused native direct-call edges with metadata ownership.
- `runtime/` contains build-bound runtime capture helpers; reusable correlation logic lives in `genshinre.capture` / `genshinre correlate-capture`.

Pinned sample acquisition has one maintained route:

```text
scripts/fetch-7.1-samples.sh
scripts/fetch-7.1-samples.ps1
    → genshinre.samplefetch
```

Do not add a second fetch wrapper or duplicate package functionality under `tools/`.

A focused helper should be retired once its durable evidence is committed and its reusable logic is covered by a maintained package/tool entry point. Git history preserves the retired experiment; the working tree keeps only current paths.

A tool completing successfully is not sufficient evidence for semantic promotion. Promotion still follows `docs/analysis-contract.md` and the focused investigation's evidence gate.
