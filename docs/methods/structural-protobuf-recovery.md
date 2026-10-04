# Structural protobuf recovery under obfuscation

This note records a method family worth evaluating for the maintained 7.1 Global target. It does not assert that historical assembly-layout assumptions still hold.

## Motivation

`proto/message-shapes.json` currently stores focused, evidence-backed wire/parser shapes for a small number of messages. For broader protocol work, field numbers alone are often insufficient: useful schema recovery also needs scalar/message/container classification, repeated/map structure and oneof relations while preserving uncertainty.

Historical Genshin tooling shows that substantial protobuf structure can survive identifier obfuscation.

## Historical lead

`partypooperarchive/ObfProtoDecoder` (2022, AGPL-3.0) parsed partially obfuscated generated assemblies with Mono.Cecil. Its useful methodological observations include:

- protobuf field-number constants remain structurally adjacent to backing/generated fields;
- generated property ordering can help associate a field-number constant with its logical property;
- generic generated fields expose clues for repeated/container fields;
- a generated `oneof` can leave a recognizable object backing field plus discriminator enum;
- referenced protobuf message/enum types can be traversed recursively once a packet root is identified.

The historical implementation contains version-specific assumptions and hacks, so it must not be copied into or treated as evidence for 7.1. Its AGPL-3.0 license is also incompatible with directly incorporating its code into this Apache-2.0 repository.

`partypooperarchive/TokenRecovery` is another historical lead: it indexed protobuf packet classes by metadata token and CmdId. Token identity itself must not be assumed stable across modern versions, but the broader idea is useful — preserve multiple structural identities so mappings can be compared across builds without relying only on obfuscated names.

## 7.1 evaluation questions

For the exact Global 7.1 sample, determine which generated-protobuf invariants remain observable through the canonical metadata/native artifacts:

1. Can each protobuf type's field-number constants be associated with field/property types mechanically?
2. Can repeated/map/message/scalar categories be recovered with useful confidence?
3. Can `oneof` discriminator/value relationships be detected without semantic names?
4. Can parser/write/size methods independently validate the reconstructed field tags and wire types?
5. Can a stable structural fingerprint be produced for cross-version or cross-region matching without assuming metadata-token stability?

Candidate fingerprint inputs include field-number/wire-type multiset, referenced message graph, method signatures, parser-tag sequence, field count, oneof/container structure and selected native call relationships. No single component should be treated as a semantic identity by itself.

## Evidence policy

- Historical tooling is METHOD/NAVIGATION evidence only.
- Current 7.1 schema rows require current-sample metadata/native evidence.
- A structural match across versions or regions is a candidate/cross-check, never automatic semantic promotion.
- Preserve ambiguous candidates instead of forcing a one-to-one name.
- Reusable recovery should emit machine-readable artifacts and provenance, not only generated `.proto` text.

## Desired maintained output

If the method proves robust, extend the protocol artifact layer with records such as:

```json
{
  "type": "OBFUSCATED_TYPE",
  "fields": [
    {
      "number": 14,
      "wire_type": 2,
      "container": "repeated",
      "element_type": "uint32",
      "confidence": "CONFIRMED",
      "evidence": ["parser", "field-codec"]
    }
  ],
  "oneofs": [],
  "structural_fingerprint": "..."
}
```

The artifact should keep structural facts separate from semantic message/field names.

## Practical value

This can reduce the cost of unknown-packet work such as CmdId 186 and future version migrations. The objective is not bulk auto-naming; it is to turn obfuscated generated-code structure into reusable, independently verifiable schema evidence.
