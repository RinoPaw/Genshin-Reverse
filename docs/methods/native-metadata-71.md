# Native 7.1 MHY metadata decoder

`genshinre.mhy71` reconstructs the build-specific metadata decoder used during the earlier successful Genshin 7.1 client audit. It is pinned to the exact Global/Windows x64 sample hashes in `versions/7.1.0-global/windows-x64/hashes.json`.

Run:

```bash
genshinre decode-metadata-71 \
  inputs/GenshinImpact.exe \
  inputs/global-metadata.dat \
  versions/7.1.0-global/windows-x64/metadata
```

The decoder refuses different samples by default. `--allow-unknown-sample` exists for research while deriving a new build recipe; output from that mode carries warnings and must not be published as a 7.1 canonical artifact without independent validation.

## Preserved 7.1 layout

- metadata file body begins at file offset `0x210`;
- the 528-byte effective metadata header is embedded in the executable at RVA `0x027D4BD0`;
- type definitions are 70-byte records;
- fields are 8-byte records;
- methods are 26-byte records;
- parameters are 8-byte records;
- IL2CPP type-array pointer is read at RVA `0x02870A88 + 0x48`;
- method pointers are read from RVA `0x02870B90 + methodIndex*8`.

The preserved decoder recovered 88,904 type definitions, 440,172 fields and 733,442 methods. These counts are strict regression checks for the exact sample.

The restored formulas cover type names/namespaces, field/method ranges, field name/type indices, method name/declaring type/parameter range, parameter type indices and native method RVAs. String tokens are decoded directly from the protected metadata body.

## Parameter records

The 7.1 parameter-record formula is integrated into the primary native decoder. `genshinre decode-metadata-71` now writes populated `parameter_types` and `parameter_type_indices` directly into `metadata/methods.csv`; a second enrichment step is no longer required.

The reusable record primitive remains in `genshinre.param71`. `genshinre.mhy71` consumes it while traversing each method's decoded `parameter_start` / `parameter_count` span and resolves each recovered IL2CPP type index through the same native runtime type table used for field types.

The formula is locked by synthetic tests and three independent confirmed handler anchors:

```text
LLCGIEDMIIG.MACAMCMOKOL @ 0x0C227790 -> ONKOPMILDMF
handler @ 0x0C23BA20                   -> PGAMFBPNNIC
handler @ 0x0C2513A0                   -> OBOADLPIEPL
```

`native-decoder-summary.json` records the decoded parameter count, parameter base file offset, 8-byte record size and `parameter_records_decoded: true`.

The standalone scripts under `tools/` that decode parameter records remain useful for focused reverse-engineering diagnostics and independent comparisons. They are no longer part of the canonical regeneration path.

## Anchor validation

A fresh primary native decode should be validated with the full anchor set:

```bash
genshinre verify-metadata \
  versions/7.1.0-global/windows-x64/metadata \
  versions/7.1.0-global/windows-x64/metadata/anchors.json
```

`anchors.json` includes parameter-type relationships such as the confirmed born notify handler, so it exercises the integrated parameter path in addition to the type/field/method identities.

`anchors-native.json` is retained as a narrower lower-layer regression set. It is useful when isolating failures in type, field, method or RVA recovery before parameter resolution is involved.

## Current boundary

Method parameter types are recovered by the primary native path. Method return-type decoding is still not claimed; keep `return_type` empty until its exact 7.1 record source/formula is independently recovered.

The external `mhydump` adapter remains useful as a second implementation. Agreement between both paths is strong validation; disagreement should be investigated at the artifact layer before protocol conclusions are published.
