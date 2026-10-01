# Native 7.1 MHY metadata decoder

`genshinre.mhy71` reconstructs the build-specific metadata decoder that was used during the earlier successful Genshin 7.1 client audit. It is deliberately pinned to the exact Global/Windows x64 sample hashes in `versions/7.1.0-global/windows-x64/hashes.json`.

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
- IL2CPP type-array pointer is read at RVA `0x02870A88 + 0x48`;
- method pointers are read from RVA `0x02870B90 + methodIndex*8`.

The preserved decoder recovered 88,904 type definitions, 440,172 fields and 733,442 methods. These counts are strict regression checks for the exact sample.

The restored formulas include type names/namespaces, field/method ranges, field name/type indices, method name/declaring type/parameter range and native method RVAs. String tokens are decoded directly from the protected metadata body.

## Current boundary

The historical parameter-record decoding formula was not preserved in the retrievable notes. Therefore this implementation records `parameter_start` and `parameter_count` but leaves `parameter_types` and `return_type` empty. This gap is explicit in `native-decoder-summary.json` and must stay visible until independently recovered.

The external `mhydump` adapter remains useful as a second implementation. Agreement between both paths is strong validation; disagreement should be investigated at the artifact layer before protocol conclusions are published.
