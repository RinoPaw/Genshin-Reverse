# Native target profiles

`genshinre.nativeprofile` is the explicit home for exact-client constants that describe a target sample rather than an algorithm.

The current profile key is:

```text
7.1.0-global/windows-x64
```

A profile binds reusable generators and validators to one exact client identity. It is not a compatibility layer and there is no profile inheritance or nearest-version lookup.

## What belongs in a profile

Store values that may legitimately change when the client version/sample changes:

- executable and metadata SHA-256 identities;
- expected metadata row counts;
- embedded metadata/header RVAs and sizes;
- runtime type-array and method-pointer table RVAs;
- exact runtime type count/boundary and preserved anchors;
- preserved GetCmdId controls;
- registry row count, constructor-code corridor and preserved registry-slot anchors.

Keep implementation mechanics in their owning modules:

- record/entry sizes defined by a decoded structure;
- instruction decoders and byte-pattern logic;
- CSV schemas and generic query behavior;
- protobuf wire decoding;
- relationship/evidence rules that apply across targets.

## Fail-closed rule

Target selection is exact.

```text
requested version/region/platform
→ exact NativeProfile exists
→ exact sample hashes match
→ target-specific anchors/counts pass
→ run the generator
```

If any step fails, stop. Do not:

- reuse the previous version profile;
- copy a nearby RVA because the surrounding code looks similar;
- weaken an anchor until another sample passes;
- add an `allow unknown sample` switch;
- silently fall back to a historical dump or generated proto.

Cross-version artifacts are research evidence only until the new target independently satisfies its own gates.

## Current 7.1 bridge

`PROFILE_71` owns the maintained exact target contract. Some older 7.1 decoder modules still expose implementation-local constant names because they predate the profile. CI crosschecks those names against `PROFILE_71`; new target-specific constants should be added to the profile first rather than creating another independent source.

Current exact-sample profile evidence includes:

- 88,904 type definitions;
- 440,172 fields;
- 733,442 methods / method pointers;
- 683,574 runtime Il2CppType entries with boundary RVA `0x388CD80`;
- 4,896 registry constructor/type slots;
- preserved runtime-type, GetCmdId and registry-slot controls.

## Bringing up a new client version

For a future target such as 7.2:

1. create the version tree with `genshinre scaffold`;
2. fingerprint the exact executable and metadata sample;
3. recover target counts/RVAs/anchors as explicit research evidence;
4. add a new `NativeProfile` only after those values are independently justified;
5. make maintained generators consume that exact profile;
6. run exact-sample regeneration and version validation;
7. publish only after all target gates close.

Do not create `mhy72.py` by copying 7.1 constants first and fixing failures afterward. The new profile should describe recovered 7.2 facts, while reusable decoding algorithms stay shared wherever the formats genuinely remain the same.

## Changing an existing profile

Treat a committed profile change as a sample-contract change. The same commit or immediate validation chain should include:

- regression tests for the changed target values;
- exact-sample workflow validation when a maintained generator consumes the value;
- regenerated committed artifacts when the new value changes publication output.

If an experiment disproves a proposed target structure, retire the hypothesis instead of adding a permissive fallback. Git history preserves the experiment without keeping a broken maintained path alive.
