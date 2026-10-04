# External reverse-engineering intelligence

This document records external Genshin/IL2CPP/protocol work that is useful to Genshin-Reverse. It is a maintainer reconnaissance log, not a source of canonical truth.

External projects are used to discover methods, candidate semantics and independent cross-checks. A third-party mapping never becomes current Global canonical data without satisfying the local evidence gate.

## Triage rules

For every external lead, classify it as one or more of:

- **METHOD** — reusable analysis technique worth independently reproducing.
- **CROSS-CHECK** — independent evidence that strengthens or rejects a local hypothesis.
- **NAVIGATION** — useful names/paths/older semantics that help locate current evidence.
- **DATA SOURCE** — current extracted resource data whose exact revision/path must be recorded.
- **DO NOT PROMOTE** — useful context but insufficient for a current Global semantic claim.

Before importing code, check its license. An unlicensed public repository may be studied as a methodological reference, but its code should not be copied into this Apache-2.0 repository. AGPL/GPL code likewise requires a deliberate compatibility decision; prefer independent reimplementation of the underlying method for maintained Apache-2.0 tooling.

## Current watch list

### invoker-bot/LunaGC

Status: **high-value CROSS-CHECK + METHOD**

Current repository target is CN 7.1.0 and therefore does not replace exact-Global evidence. It is unusually valuable because it includes recent protocol tests and native-derived field/tag notes rather than only historical Grasscutter mappings.

Useful patterns observed:

- protocol claims are encoded as tests that round-trip exact protobuf bytes;
- unknown opcodes can remain explicitly unnamed/no-op instead of receiving guessed semantics;
- current-client native codec tags are used to verify protobuf field numbers;
- exact-sample client extractors are SHA-256 gated and reject mismatched builds;
- semantic assignments can be cross-checked against server behavior while retaining region boundaries.

Example: commit `1b363fac36d218ecfce3452a3c1893fe0fac6b31` includes `ActivityDisplayProtocolTest`, which fixes `GetActivityInfoReq` at CmdId 186 for that CN sample and verifies packed field 14 through exact bytes. This is strong independent evidence for our Global CmdId 186 investigation, but remains a cross-region semantic edge rather than exact-Global proof.

Example: commit `848b8a0697c1a3c701dfaffa6bd6629e3a4f6992` added an exact-sample type-name extractor. Its useful maintenance lesson is the combination of pinned hashes, hard failure on mismatch and explicit separation between recovered type names and protobuf semantics.

### kuma-dayo/gi-stringliteral

Status: **promising METHOD; licensing caution**

The project describes static recovery of string literals from MHY-obfuscated `global-metadata.dat`. Its interesting idea is to reduce per-version constants by extracting decryption arithmetic from the executable and locating metadata sections by signatures.

This is worth independently evaluating because string literals can provide semantic anchors when message/type names remain obfuscated. Tracking task: #6.

The repository currently has no declared license. Do not copy implementation code into Genshin-Reverse. Reproduce the technique independently if adopted.

### partypooperarchive reverse-engineering toolchain

Status: **high-value historical METHOD + NAVIGATION; DO NOT PROMOTE**

The archived tool family includes `ObfProtoDecoder`, `TokenRecovery`, `BinDumper`, `DataDumper`, `StringLurker`, `ProtobufDecoder`, `KSysha` and a Genshin-aware Il2CppDumper fork. The concrete implementations are old and several are AGPL-3.0, so they are not current 7.1 dependencies.

The most useful methodological lead is `ObfProtoDecoder`: it recovered protobuf structure from partially obfuscated generated assemblies using field-number constants, backing/generated field and property ordering, generic container clues and generated `oneof` object+enum patterns. This suggests a current-version structural schema recovery path even when semantic names are unavailable. Tracking task: #7; method note: `docs/methods/structural-protobuf-recovery.md`.

`TokenRecovery` historically paired packet CmdIds with metadata tokens. Token equality itself is too weak for current cross-version promotion, but the idea motivates preserving composite structural fingerprints so builds can be compared mechanically without relying on obfuscated names alone.

`KSysha` is a reminder that stable binary/resource layouts should eventually be captured as declarative schemas or parser contracts once understood, rather than living only in prose notes.

### DimbreathBot/AnimeGameData

Status: **primary current DATA SOURCE for resource/config semantics**

Use current-version `BinOutput`, `ExcelBinOutput`, `Readable` and related data before opening a native reverse task. Resource evidence is often sufficient for Ability, Quest, item, skill and gameplay configuration questions.

Always pin the exact source revision/path in an analysis. Generated/extracted data may contain conversion defects; the current quest prerequisite repair work is a concrete example of why flattened Excel output must sometimes be checked against source BinOutput and historical references.

### Project-x64/genshin-luadec and historical Lua tooling

Status: **NAVIGATION + METHOD history**

Historical Genshin Lua tooling documents modified bytecode headers/opcode ordering. This matters mainly when current activity/Scene/Quest behavior depends on compiled script semantics that are not already available through extracted resources. Do not reopen Lua-format reversing merely because the tool exists; wait for a concrete current-version consumer.

### Grasscutters/Grasscutter and forks

Status: **NAVIGATION + historical CROSS-CHECK; usually DO NOT PROMOTE**

Grasscutter remains useful for message names, old handlers, gameplay architecture and historical protobuf relationships. Its mainline server is documented as targeting much older game versions, so numeric CmdIds and field layouts must not be treated as current evidence.

A useful historical lesson is to keep generated protobuf structures separate from semantic confidence: an obfuscated generated class can still preserve CmdId/field-shape evidence even when the name is unknown.

### Genshin-specific Il2CppDumper forks

Examples: `R0xdeadc0de/Il2CppDumper-Genshin`, `line-bear/Il2CppDumper`.

Status: **NAVIGATION + METHOD history**

These projects document the long-running requirement to deal with MHY-obfuscated/encrypted metadata and can provide clues about metadata layout evolution, dummy DLL generation and IDA/Ghidra integration. They are useful when diagnosing a new client version, but old parser assumptions should not be transplanted into the maintained pipeline without current-sample verification.

### Il2CppInspector + miHoYo plugin lineage

Status: **general METHOD reference**

Il2CppInspector's loader/plugin architecture is useful as a design reference for separating binary/metadata deobfuscation from higher-level type/method analysis. Its support for differential analysis and machine-readable address maps also reinforces two useful ideas: use structural comparisons when names are unstable, and make recovered metadata easy to query from IDA/Ghidra or automation rather than depending on giant text dumps.

Its Genshin support is historical, so it is a methodology source rather than a current decoder dependency.

### Recent generic IL2CPP dumpers

Status: **UX/format METHOD only**

Recent general-purpose dumpers increasingly expose JSON indexes, method RVAs, per-type files and analysis-friendly output. They do not establish Genshin 7.1 correctness. Genshin-Reverse already publishes machine-queryable metadata, so only borrow an output idea when it closes a concrete query gap; do not create another parallel dump format for novelty.

## Maintainer conclusions

1. **Keep fail-closed exact-sample profiles.** External tools that auto-discover offsets are useful, but automatic discovery should improve bring-up rather than silently make an unsupported sample look supported.
2. **Turn semantic claims into executable fixtures.** When a packet mapping is sufficiently known, preserve representative protobuf bytes and round-trip/unknown-field tests. This catches accidental field renumbering and guessed schemas more effectively than prose alone.
3. **Unknown is a valid durable state.** An observed CmdId does not need a guessed name or response. Preserve the observation and its context until a semantic gate is satisfied.
4. **Use current resources before native reversing.** BinOutput/Excel data can close many gameplay questions cheaply; native/protocol work should target the remaining uncertainty.
5. **Treat CN/current or historical/current projects as independent edges.** Same-version cross-region agreement is strong evidence, but the maintained Global target still requires a Global promotion edge for canonical semantic claims.
6. **Prefer automatic discovery for version bring-up, exact hashes for publication.** A future extractor may locate metadata/string tables automatically, but published artifacts still bind to exact executable/metadata hashes.
7. **Do not import incompatible or unlicensed reverse-engineering code.** Record the method and reimplement from the underlying idea when licensing is absent or incompatible.
8. **Exploit generated-code invariants under obfuscation.** Field-number constants, parser tags, codec construction, container types, oneof discriminators and referenced-type graphs may survive name scrambling and can be combined into stronger schema evidence.
9. **Use composite fingerprints for cross-build matching.** Metadata token, type index, field count or method order alone is too weak. A candidate fingerprint should combine protobuf shape, referenced types, parser/write behavior and native relationships, while preserving ambiguity.
10. **Capture stable formats declaratively after they are understood.** A machine-readable schema/parser contract is better than repeating low-level reverse work, but only when the format has a real consumer and enough evidence to call stable.

## Active follow-ups created from reconnaissance

- #6 — evaluate a version-independent MHY string-literal recovery method while preserving exact-sample validation.
- #7 — evaluate richer structural protobuf recovery from obfuscated 7.1 metadata/native artifacts.
- Continue using LunaGC CN 7.1 tests/native notes as independent cross-checks for #1 and future 7.1 protocol investigations.
- For #5 artifact weighting, search current resource tables first and use server projects/community tables only as search hints until a current source/consumer establishes interpretation.

## Reconnaissance notes

- `docs/recon-pass-2026-10-04-2.md` records the second focused pass covering structural protobuf recovery, token-based historical matching, Kaitai/Lua leads and modern IL2CPP output-design ideas.

## Update policy

Add an entry when an external project contributes a genuinely reusable technique, current-version evidence, or a useful rejected path. Do not turn this file into a link dump. If a lead creates actionable work, open or update a focused issue and link it here.
