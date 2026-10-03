# Scene handler dispatch slots — 7.1 exact sample

This analysis preserves the 7.1 side of the cross-version scene-handler slot investigation that originally lived only in GitHub Actions artifact `scene-handler-slot-neighborhoods-70-71`.

The exact 7.1 owner type is `KLLNGCPBLMM`. The preserved scan found 68 one-parameter owner methods whose parameter type is present in the canonical registry and whose method body loads a delegate/table entry from the investigated slot window. Those 68 rows contain 73 instruction hits and 72 unique slots.

All 73 recorded loads use the same consumer shape: `mov rcx, qword ptr [base + disp32]`. The base register is `rax` for 52 hits and `rcx` for 21 hits. This exact-sample observation is why the maintained zero-dependency extractor in `genshinre.scenehandlers` intentionally recognizes only that instruction family.

`scene-handler-slots.csv` is a compact method-level projection of the source artifact. `evidence.json` binds it to the exact executable hash, workflow run, artifact ID and artifact digest. Numeric/type relations are static evidence; unresolved semantic names still require independent protocol evidence.

Reproduce the 7.1 scan with the pinned executable and canonical metadata/registry:

```text
genshinre scene-handler-slots \
  GenshinImpact.exe \
  versions/7.1.0-global/windows-x64/metadata/methods.csv \
  versions/7.1.0-global/windows-x64/registry/registry.csv \
  KLLNGCPBLMM \
  0x4B1A90 0x4B3AB8 \
  --output scene-handler-slots.json
```

The maintained extractor uses a half-open slot range. The original Capstone workflow used an inclusive range ending at `0x4B3AB0`; with 8-byte slot alignment, `[0x4B1A90, 0x4B3AB8)` is the equivalent maintained range.
