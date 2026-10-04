# Tools

`tools/` contains narrow research helpers that intentionally do not belong on the primary `genshinre` CLI surface.

Reusable repository functionality belongs in `genshinre/`. Maintained multi-step target workflows belong in `scripts/`. Keep a tool here only when its value depends on an exact sample, fixed native boundary, independent decoder, optional research dependency, or focused research operation.

Current helpers:

- `decode_protocol_handler_parameters_71.py` independently decodes exact-7.1 parameter records and checks known handler controls. It stays separate from the normal decoded metadata path so it remains an independent evidence layer.
- `disassemble_rva.py` is the small generic exact-sample RVA disassembler used by the opt-in disassembly workflow and focused investigations. It stays outside the base package because it depends on Capstone.
- `locate_game_packet_framing_71.py` reproduces the exact-client packet-framing boundary used by the maintained runtime capture evidence and depends on Capstone.
- `trace_native_call_edges.py` traces focused native direct-call edges with metadata ownership. It stays outside the base package because it depends on Capstone.
- `runtime/` contains build-bound runtime capture helpers; reusable correlation logic lives in `genshinre.capture` / `genshinre correlate-capture`. The Python launcher reports an explicit install hint when the optional Frida bindings are missing.

Optional research dependencies are deliberately kept out of the base package. Install only what the selected helper needs:

```bash
python -m pip install capstone   # disassembly / framing / native-call helpers
python -m pip install frida      # runtime capture launcher
python -m pip install zstandard  # pinned sample acquisition
```

Already-decrypted game-frame parsing is reusable standard-library functionality and therefore lives in the package:

```text
python -m genshinre.packetframe --file decrypted-frames.bin
python -m genshinre.packetframe --hex 4567...
```

Pinned sample acquisition has one maintained route:

```text
scripts/fetch-7.1-samples.sh
scripts/fetch-7.1-samples.ps1
    → genshinre.samplefetch
```

Do not add a second fetch wrapper or duplicate package functionality under `tools/`.

A focused helper should be retired once its durable evidence is committed and its reusable logic is covered by a maintained package/tool entry point. Git history preserves the retired experiment; the working tree keeps only current paths.

A tool completing successfully is not sufficient evidence for semantic promotion. Promotion still follows `docs/analysis-contract.md` and the focused investigation's evidence gate.
