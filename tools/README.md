# Tools

`tools/` contains narrow research helpers that intentionally do not belong on the primary `genshinre` CLI surface.

Reusable repository functionality belongs in `genshinre/`. Maintained multi-step target workflows belong in `scripts/`. Keep a tool here only when its value depends on an exact sample, fixed native boundary, independent decoder, optional research dependency, or focused research operation.

Current helpers:

- `decode_protocol_handler_parameters_71.py` independently decodes exact-7.1 parameter records and checks known handler controls. It stays separate from the normal decoded metadata path so it remains an independent evidence layer.
- `disassemble_rva.py` is the small generic exact-sample RVA disassembler used by the opt-in disassembly workflow and focused investigations. It stays outside the base package because it depends on Capstone.
- `locate_game_packet_framing_71.py` reproduces the exact-client packet-framing boundary used by the maintained runtime capture evidence and depends on Capstone.
- `trace_native_call_edges.py` traces focused native direct-call edges with metadata ownership. It stays outside the base package because it depends on Capstone.
- `scan_field_displacements.py` scans methods owned by one selected IL2CPP type for x86-64 memory operands using requested object displacements. It records register/addressing details and surrounding instructions so a researcher can narrow producer/consumer paths without pretending that displacement equality alone establishes field identity. The opt-in `Scan 7.1 Field Displacements` workflow runs it against the pinned exact Global 7.1 sample.
- `runtime/` contains build-bound runtime capture helpers; reusable correlation logic lives in `genshinre.capture` / `genshinre correlate-capture`. The Python launcher reports an explicit install hint when the optional Frida bindings are missing.

Optional research dependencies are deliberately kept out of the base package. Install only what the selected helper needs:

```bash
python -m pip install capstone   # disassembly / framing / native-call / field-displacement helpers
python -m pip install frida      # runtime capture launcher
python -m pip install zstandard  # pinned sample acquisition
```

Example focused field scan after fetching the pinned sample:

```bash
python tools/scan_field_displacements.py \
  inputs/7.1.0-global/GenshinImpact.exe \
  versions/7.1.0-global/windows-x64/metadata/methods.csv \
  field-displacements.json \
  --type-name JKFCCMCAMGA \
  --offset 0x108 \
  --expected-sha256 08a3086d5f3fe695f01dab61efa42e442006b18e5e475b2520df356f6a073b7d
```

A displacement hit is a research candidate. Trace the memory operand's base register back to the relevant object instance before assigning field semantics, and never transfer offsets between unrelated types/builds as semantic evidence.

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
