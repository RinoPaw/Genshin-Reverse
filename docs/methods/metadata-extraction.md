# Metadata extraction pipeline

The shared repository separates **client-specific extraction** from **stable artifact indexing**.

## Stable side: `dump.cs` importer

Any extractor that emits an Il2CppDumper-style `dump.cs` can feed the canonical metadata indexes:

```bash
genshinre import-dump-cs dump.cs \
  versions/7.1.0-global/windows-x64/metadata \
  --source-tool my-extractor \
  --tool-revision <revision>
```

Generated files:

- `types.csv`
- `fields.csv`
- `methods.csv`
- `type-methods.json`
- `summary.json`

`TypeDefIndex`, field offsets and method RVAs come directly from `dump.cs`. A normal `dump.cs` does not expose the original global IL2CPP method/field index, so `method_index` and `field_index` stay blank. `method_ordinal` / `field_ordinal` are explicitly dump-order identifiers and must never be cited as IL2CPP metadata indices.

## MHY metadata backend

`Mar7thLover/GI-StaticParser` is supported as an **external** backend because it statically reads `GenshinImpact.exe` plus the `MHY\0` `global-metadata.dat` and emits an Il2CppDumper-style `dump.cs`.

The inspected upstream revision is recorded in `docs/external-extractors.json`. Its own README explicitly warns that extraction constants are build-specific. Therefore a successful process exit is insufficient evidence that the output belongs to the target client.

After building an appropriate `mhydump` binary:

```bash
genshinre extract-metadata \
  GenshinImpact.exe global-metadata.dat \
  versions/7.1.0-global/windows-x64/metadata \
  --tool /path/to/mhydump \
  --tool-revision <extractor-revision>
```

Then verify the target-client anchors:

```bash
genshinre verify-metadata \
  versions/7.1.0-global/windows-x64/metadata \
  versions/7.1.0-global/windows-x64/metadata/anchors.json
```

For the current 7.1 sample the verifier checks independently preserved identities such as typeDefinition 87483 `ONKOPMILDMF`, handler `LLCGIEDMIIG.MACAMCMOKOL @ 0x0C227790`, and the `HJDNCHODGOL` method at `0x10587260`. A backend/output that misses an anchor is rejected for this version until investigated.

## Provenance

`extract-metadata` fingerprints both raw inputs and writes `extractor.json`; `import-dump-cs` records the dump hash and tool revision in `summary.json`. Raw game binaries remain outside Git history.

## Why the adapter boundary matters

MHY metadata protection and extractor recipes can change between game builds. The CSV/JSON query layer should remain stable even when the binary recovery backend is replaced. New extractors only need to produce `dump.cs` or add another importer with equivalent provenance and anchor checks.
