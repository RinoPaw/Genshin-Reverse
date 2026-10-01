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

The restored formulas cover type names/namespaces, field/method ranges, field name/type indices, method name/declaring type/parameter range and native method RVAs. String tokens are decoded directly from the protected metadata body.

## Parameter records

The 7.1 parameter-record formula has now also been recovered. The reusable implementation lives in `genshinre.param71`, with synthetic/formula tests plus three independent confirmed handler anchors in `tests/test_param71.py`.

For a parameter record at index `i`, the current decoder recovers both the IL2CPP type index and protected name token. `tools/decode_method_parameters_71.py` joins those records to `metadata/methods.csv` and resolves the type indices through the recovered runtime type table.

The three current handler controls are:

```text
LLCGIEDMIIG.MACAMCMOKOL @ 0x0C227790 -> ONKOPMILDMF
handler @ 0x0C23BA20                   -> PGAMFBPNNIC
handler @ 0x0C2513A0                   -> OBOADLPIEPL
```

This closes the old "parameter formula unknown" gap. The remaining cleanup is architectural: fold the parameter-record pass into the primary `decode-metadata-71` pipeline so a fresh native decode produces populated `parameter_types` without a second enrichment step.

## Two anchor levels

The primary native decoder can always be checked with:

```bash
genshinre verify-metadata \
  versions/7.1.0-global/windows-x64/metadata \
  versions/7.1.0-global/windows-x64/metadata/anchors-native.json
```

`anchors-native.json` exercises the layers currently emitted directly by `genshinre.mhy71`. It includes `DMMJNICDOHM` typeDefinition 84249, both known uint32 fields at 417613/417614, its parser/GetCmdId/constructor RVAs, born-flow types, and the `HJDNCHODGOL` GetCmdId RVA.

After parameter enrichment, use the stronger full check:

```bash
genshinre verify-metadata \
  versions/7.1.0-global/windows-x64/metadata \
  versions/7.1.0-global/windows-x64/metadata/anchors.json
```

`anchors.json` includes parameter-type relationships such as the confirmed born notify handler and should become the default native check once parameter decoding is integrated into the primary pass.

## Current boundary

Parameter types are recovered; method return-type decoding is still not claimed by the native path. Keep `return_type` empty until its exact 7.1 record source/formula is independently recovered.

The external `mhydump` adapter remains useful as a second implementation. Agreement between both paths is strong validation; disagreement should be investigated at the artifact layer before protocol conclusions are published.
