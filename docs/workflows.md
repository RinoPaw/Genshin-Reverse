# Workflow map and maintenance policy

GitHub Actions in this repository have a deliberately small persistent surface. Ordinary maintenance must stay fast, and exact-client reverse work must use a single maintained generation path. Temporary research workflows may exist while an active investigation depends on their hosted orchestration, but they are not part of the permanent workflow surface.

Pinned 7.1 sample acquisition is centralized in:

```text
scripts/fetch-7.1-samples.sh
scripts/fetch-7.1-samples.ps1
```

## `ci.yml`

This is the only general push/PR workflow.

Unit tests cover the supported Python range at its minimum and current stable boundary, Python 3.11 and 3.14. The Python 3.12 validation job also runs the full unit suite, committed-version validation, small wire/CLI/protocol-query smoke tests, a syntax-only compile pass over `genshinre/` and `tools/`, and cheap Bash/PowerShell syntax checks so repository-level maintenance checks are not repeated across the whole Python matrix.

The Python compile pass intentionally does not import optional research dependencies such as Capstone or Frida. It catches syntax regressions across retained helpers while keeping normal CI lightweight.

Markdown-only and issue-template-only changes skip this workflow. CI has read-only repository contents permission, uses per-ref concurrency with `cancel-in-progress: true`, and must not download the full game client, decode full metadata, scan the executable, or run packet-specific investigations.

`tests/test_workflow_policy.py` keeps the workflow surface fail-closed: every retained workflow must be listed in this document, every workflow must declare explicit top-level permissions, push-triggered workflows must cancel stale runs, and `generate-7.1-data.yml` is the only workflow allowed to request repository contents write permission. This is a cheap repository-structure test and does not invoke GitHub Actions or exact-client work itself.

## `generate-7.1-data.yml`

This is the only canonical exact-sample generation workflow for the current 7.1 Global Windows x64 target.

It performs one fail-closed chain:

1. fetch the pinned exact sample;
2. regenerate metadata/runtime/GetCmdId evidence;
3. recover the exact 4,896 registry constructor/type slots;
4. recover dominant registry-slot xrefs from the regenerated method/GetCmdId data;
5. publish the strict 4,896-row slot/type/CmdId registry;
6. publish the validated metadata/GetCmdId artifacts;
7. validate the complete committed version tree;
8. commit all canonical changes together.

The registry stages used to be split across three write-capable workflows. Those shells were retired after the registry identity path stabilized. The underlying package modules remain the implementation and can still be invoked directly for focused debugging.

The workflow is narrowly path-triggered, uses same-ref stale-run cancellation, and never runs exploratory packet investigations.

## `disassemble-7.1-rva.yml`

This is the retained generic opt-in exact-sample research workflow. It accepts an RVA and size, fetches the pinned client, validates the executable identity, and preserves the requested disassembly as a short-lived artifact.

Packet-specific Actions are not retained after their useful evidence has been committed. CmdId 186, waypoint response recovery, packet framing, scene-handler work, candidate-graph experiments and similar investigations now rely on committed evidence plus reusable package/tools entry points rather than dedicated Actions shells.

## Temporary research orchestration

The temporary class-registration pointer scan for issue #31 completed successfully on the exact SHA-256-pinned Global 7.1 client ([run 39548584709](https://github.com/RinoPaw/Genshin-Reverse/actions/runs/39548584709)). Its negative scope and source-control details are retained in `versions/7.1.0-global/analyses/progression/economy/7.1-chest-scene-row-class-pointer-registration.json`, reproducible with `scripts/probe-7.1-scene-class-pointer-registration.py --check`. That workflow was retired. Separate original-client keywriter and metadata-neighbor artifacts are compared by `scripts/audit-7.1-scene-reader-candidate-intersection.py`; vtable slot `+0xF0` remains unverified. None of these results authenticates server chest loot.

There is currently no topic-specific workflow on the maintained branch. Issue #31's temporary original Global 7.1 SceneTag/SceneExcel row-class studies have completed: [class static xrefs, run 39543986621](https://github.com/RinoPaw/Genshin-Reverse/actions/runs/39543986621), [metadata neighbors and native disassembly, run 39544622842](https://github.com/RinoPaw/Genshin-Reverse/actions/runs/39544622842), and [wrapped-key field stores, run 39545346441](https://github.com/RinoPaw/Genshin-Reverse/actions/runs/39545346441). Their permanent source-scoped evidence and reusable scripts live under `versions/7.1.0-global/analyses/progression/economy/` and `scripts/`. The two one-shot workflows are retired. The original virtual row reader at +0xF0 remains unverified; no original asset bytes or server reward claims were committed.



The exact-7.1 SceneTag/SceneExcel generic field research is complete and its one-shot workflow has been retired. The verified original executable [source run 39544944169](https://github.com/RinoPaw/Genshin-Reverse/actions/runs/39544944169) established distinct genericinst field type indices 666588 and 545412, the matching raw Il2CppType entries, and a shared bool type index 439094. The low 32-bit generic type payloads cannot be treated as file-backed virtual addresses. Permanent research code and evidence remain in `scripts/probe-7.1-scene-manager-genericinst.py` and `versions/7.1.0-global/analyses/progression/economy/7.1-chest-scene-manager-generic-type-evidence.json`. Concrete row classes and virtual method +0xF0 remain unknown.




The former QuestExcel table-assets probe reached its retirement condition after the exact asset, complete row framing and ordinary Quest ownership boundary became durable. Git history preserves the orchestration.

New topic-specific workflows must follow `docs/governance.md`: one concrete owner, a stated hosted-orchestration need, a named output and an explicit retirement condition.

## Retirement rule

Retire a workflow when all of the following are true:

1. its reusable algorithm lives in `genshinre/` or a retained `tools/` command;
2. its exact sample/parameters are documented or represented in committed evidence;
3. unique results are durable under `versions/` or a maintained case study;
4. no active investigation depends on the workflow shell itself.

Git history preserves retired orchestration. Do not keep old workflow files as documentation.

## Adding a workflow

A new workflow needs a distinct ongoing orchestration need. Before adding one:

1. put reusable logic in `genshinre/` or `tools/`;
2. reuse the canonical generation workflow for canonical artifacts;
3. keep exact sample hashes and provenance explicit;
4. keep full-client work off ordinary CI;
5. plan to retire packet-specific orchestration once its evidence is durable.

A workflow is orchestration, not the canonical implementation of a reverse-engineering method.

## Validation boundary

Exploratory research may iterate with cheap local checks and opt-in exact-sample jobs. Full validation must not be skipped before asking the user to test a promoted change, before preparing an upstream submission, or before publishing/regenerating canonical target artifacts.


## Retired exact-7.1 chest Lv3 source checks (issue #31)

The retired one-shot Lv3 asset-index workflow completed its
source-acquisition gate in [run 39581235509](https://github.com/RinoPaw/Genshin-Reverse/actions/runs/39581235509)
and its original binary fingerprint gate in [run 39581806527](https://github.com/RinoPaw/Genshin-Reverse/actions/runs/39581806527).
The original Global 7.1 audio/handbook table paths both uniquely resolved
to native block 25539185, and their 484 / 31,016-byte Raw exports passed
original-client source/control/framing checks. Complete fingerprints and
strict reproduction are retained in
`versions/7.1.0-global/analyses/progression/economy/7.1-chest-lv3-original-index.md`
and `scripts/probe-7.1-chest-lv3-native-index.py`. The temporary hosted
workflow was removed after the provenance results became durable.

No original row deserializer or server payout was authenticated by this job.
No special extra CI workflow remains active for the chest table path study.


## Retired original 7.1 chest audio native reconstruction (issue #31)

The temporary hosted chest count-header/row-reader orchestration is complete
and retired. Original Global 7.1 executable and asset hashes were guarded in
the [native header scan 39585071475](https://github.com/RinoPaw/Genshin-Reverse/actions/runs/39585071475),
[aligned loader/row disassembly 39586029162](https://github.com/RinoPaw/Genshin-Reverse/actions/runs/39586029162),
[full 56-row Audio source decode 39586611284](https://github.com/RinoPaw/Genshin-Reverse/actions/runs/39586611284),
and [56-key original-to-public label join 39587278416](https://github.com/RinoPaw/Genshin-Reverse/actions/runs/39587278416).
All runs succeeded, and the normal Python matrix CI passed on the final
source-backed run.

Reusable algorithms remain in
`scripts/probe-7.1-chest-lv3-native-header-counts.py`,
`scripts/probe-7.1-chest-audio-native-metadata.py`,
`scripts/audit-7.1-chest-native-loaders.py`,
`scripts/audit-7.1-chest-audio-native-rows.py` and
`scripts/audit-7.1-chest-audio-public-association.py`.
The durable source- and scope-pinned results live in
`versions/7.1.0-global/analyses/progression/economy/7.1-chest-native-audio-complete-rows.md`
and its JSON companion. The short-lived research workflow was removed;
no original game binaries are vendored. Original investigation row fields,
audio symbolic enum authority, runtime vtable registration and server
rewards remain unverified.

## Retired original Gadget auxiliary native loaders probe (issue #31)

The one-shot read-only original Global 7.1 Gadget auxiliary probe was completed and removed after [source-verified Actions run 39621473822](https://github.com/RinoPaw/Genshin-Reverse/actions/runs/39621473822). The pinned client executable, official Sophon exports, and metadata confirmed the original 326-row GadgetProp and 363-row GadgetInteract loaders, exact row class static pointer slots and vtable +0xF0 call sites. [Reproducible native loader verification](../scripts/audit-7.1-gadget-aux-native-loaders.py), [bounded native header candidate scan](../scripts/probe-7.1-gadget-aux-loaders.py) and the [source-backed proof](../versions/7.1.0-global/analyses/progression/economy/7.1-gadget-aux-native-table-loaders.json) remain maintained. The concrete row reader classes, serialized fields and LootCSS grade/level semantics remain unresolved. No proprietary raw asset bytes were committed.

## Retired original Gadget auxiliary row-reader filter (issue #31)

The one-off read-only original Global 7.1 row-reader screen was completed in [Actions run 39624413563](https://github.com/RinoPaw/Genshin-Reverse/actions/runs/39624413563). Source-gated native key-writer call sites and TypeInfo static slot xrefs are preserved in [candidate report](../versions/7.1.0-global/analyses/progression/economy/7.1-gadget-aux-native-row-reader-candidates.json); the full raw candidate summary is SHA-256-pinned to the run's artifact. Two nearest native methods were independently disassembled, but the actual vtable +0xF0 binding and schema remain unverified. Reproduction uses `scripts/probe-7.1-gadget-aux-row-readers.py`; no temporary workflow remains active.

## Retired original GadgetProp candidate reader first-row falsification (issue #31)

The source-verified Global 7.1 [run 39626629098](https://github.com/RinoPaw/Genshin-Reverse/actions/runs/39626629098) tested the nearest metadata candidate (method 225165, RVA `0x9EB86F0`) against the exact SHA-256-pinned GadgetProp Raw export. If invoked directly immediately after the native four-byte table header, its first mask `0xB9DA` forces a string length of 30,606 bytes with only 9,376 bytes remaining. This proves **direct-at-first-record use impossible**, not the absence of inherited or nested parsing. The [bounded negative evidence](../versions/7.1.0-global/analyses/progression/economy/7.1-gadget-prop-nearest-reader-first-row-falsification.json), [reproducer](../scripts/audit-7.1-gadget-prop-candidate-rows.py) and regression tests remain; the one-shot workflow is retired. The concrete loader vtable +0xF0 method and any LootCSS semantics remain unknown.

## Retired Gadget auxiliary manager native field probe (issue #31)

The one-off original-client [run 39640202512](https://github.com/RinoPaw/Genshin-Reverse/actions/runs/39640202512) independently decoded original GadgetProp and GadgetInteract manager fields and native Il2CppType array entries. Both managers have exactly two fields, a genericinst field (type indices 528024 / 526324, data low words 0x2B581 / 0x2A6A4), and the same native boolean type index 439094. Their row class static slots have no readable file-backed bytes. The [source-backed report](../versions/7.1.0-global/analyses/progression/economy/7.1-gadget-aux-manager-native-types.json) and [reproducer](../scripts/probe-7.1-gadget-aux-manager-native-types.py) are retained. The one-shot Actions shell was removed.

## Retired original generic metadata registration probe (issue #31)

The original Global 7.1 [run 39641127241](https://github.com/RinoPaw/Genshin-Reverse/actions/runs/39641127241) tested four independently native-verified GadgetProp/GadgetInteract/SceneTag/SceneExcel genericinst data low-words against the standard Il2CppMetadataRegistration count/pointer pair layout. The required fieldOffsetsCount/typeDefinitionsSizesCount pair had **zero** exact-file candidates. A bounded alternate aligned-QWORD count scan found one 88,904 occurrence with a non-file-backed following value and zero 683,574 occurrences. This rules out direct use of that **specific standard static registration signature** in the file-backed original executable. It does not establish absence of runtime metadata, generic classes, or valid class identities. [Bounded negative evidence](../versions/7.1.0-global/analyses/progression/economy/7.1-gadget-aux-generic-registration-boundary.json) and [reproducer](../scripts/probe-7.1-gadget-generic-class-registration.py) are retained; the temporary workflow has been removed. Recover a source-grounded protected registration layout or a runtime TypeInfo/vtable witness before mapping row classes.

## Retired original GadgetInteract candidate first-record branch probe (issue #31)

The one-shot read-only source run [39643045058](https://github.com/RinoPaw/Genshin-Reverse/actions/runs/39643045058) verified the original 363-row `GadgetInteractExcelConfigData` Raw export, its first byte `0x36`, and the native candidate `HFMNIBLLOGG.GMENPOPMKAA` first branch; independent original EXE disassemblies verified the candidate's nested reader (`0xFF7AE70`), conditional array-like reader (`0x9EA9CB0`) and tail helper (`0xD95D180`). Exact SHA-256 checks and byte-level native anchors are preserved in [the proof](../versions/7.1.0-global/analyses/progression/economy/7.1-gadget-interact-native-first-branch-chain.json) and [reproducer](../scripts/audit-7.1-gadget-interact-native-chain.py). The original source native `vtable+0xF0` row binding and the record end remain unverified. The temporary workflow was retired. No source game assets or reward values were committed.

## Retired pinned AstaPS chest-level ownership verification (issue #31)

The short-lived [source audit run 39701296454](https://github.com/RinoPaw/Genshin-Reverse/actions/runs/39701296454) fetched and checked the Git blob SHA-1 of every required AstaPS source file from **immutable commits** of upstream main and the reward experiment. Both emit `PROP_LEVEL (4001) = 1` for Gadget `SceneEntityInfo`; the experimental LootCSS backend separately uses `SceneGadget`'s Lua-script-origin `SceneObject.level`. See [machine-readable evidence](../versions/7.1.0-global/analyses/progression/economy/7.1-chest-level-source-ownership.json) and [reproducer](../scripts/audit-7.1-chest-level-source-ownership.py). The script checks the fork's source contract only. **No original Global 7.1 native scene-instance level semantic or server-side reward level is established.** No periodic workflow remains.

## Retired original 7.1 CmdId 27685 owner and consumer audits (issue #31)

The original source-controlled [native owner run 39702524539](https://github.com/RinoPaw/Genshin-Reverse/actions/runs/39702524539) verified CmdId 27685 -> original class KIIKIELOHOG, type index 65670, four exact original fields, fourteen methods and a machine-code GetCmdId return 0x6C25. [Parameter control run 39702953229](https://github.com/RinoPaw/Genshin-Reverse/actions/runs/39702953229) scanned all 548,400 original IL2CPP method parameter records and passed three independent native known-handler controls. Five method references were found: two on LCMBPJMEHMF, two on JLDCJCKHJEM, and own CopyFrom; zero in the limited known handler owner LLCGIEDMIIG. [Original consumer run 39703359133](https://github.com/RinoPaw/Genshin-Reverse/actions/runs/39703359133) disassembled four external native consumers and identified the exact method 190172 -> OnAccept method 190174 direct call. Their byte-scoped instructions and the verified negative conclusion are retained in [this report](../versions/7.1.0-global/analyses/progression/economy/7.1-cmd27685-original-native-consumers.json); [reproducible original type scan](../scripts/probe-7.1-scene-entity-protocol-owner.py), [parameter type decoder](../tools/decode_protocol_handler_parameters_71.py), and [native consumer scanner](../scripts/probe-7.1-cmd27685-native-consumers.py). Both single-run hosted workflows have been retired.

The original current-client registry still has **unknown semantic name and packet direction** for CmdId 27685, even though the AstaPS fork assigns its SceneEntityAppearNotify label. A native scene-instance level, client PROP_LEVEL=4001 consumer, and LootCSS grade/level semantics remain unverified. No game assets are committed.

## Original 7.1 CmdId 27685 object-offset provenance (issue #31)

The exact-client original method reports from [run 39702524539](https://github.com/RinoPaw/Genshin-Reverse/actions/runs/39702524539) and [run 39703359133](https://github.com/RinoPaw/Genshin-Reverse/actions/runs/39703359133) are input-SHA-256 checked and opcode-RVA checked by [the element-traversal audit](../scripts/audit-7.1-cmd27685-native-element-traversal.py). The original message constructor initializes an object at +0x18. Original typed OnAccept traverses that collection and reads +0x98 on the indexed **element object**, not the root message. A literal 0x42 in the original static initializer is only tag-shaped until its codec identity is proven. [Small source-bound evidence](../versions/7.1.0-global/analyses/progression/economy/7.1-cmd27685-native-element-traversal.json) and normal-CI regression tests are retained. No extra Actions shell was needed or kept.

## Retired original CmdId27685 element class and field2 native probes (issue #31)

Two read-only jobs are complete and retired: [original constructor TypeInfo xrefs, run 39707120407](https://github.com/RinoPaw/Genshin-Reverse/actions/runs/39707120407) and [native element writer/CopyFrom/consumer disassembly, run 39707594991](https://github.com/RinoPaw/Genshin-Reverse/actions/runs/39707594991). Their exact SHA-256 source-bound evidence is preserved in [the class/field2 report](../versions/7.1.0-global/analyses/progression/economy/7.1-cmd27685-kfoll-element-wire-field2.json) and reproduced with [the verifier](../scripts/audit-7.1-cmd27685-kfoll-element.py). A typed original message container `CEOGMKOJDBL` has the sole field `KFOLLNPEMHH`; its original CopyFrom branches directly to the `KFOLLNPEMHH.CopyFrom` method while loading the candidate element class TypeInfo slot. The same native element class's reader assigns object `+0x98` in the wire-key 0x10 branch (field 2 / varint), and original typed Cmd27685 OnAccept reads `+0x98` from a packet-collection element. Original Vision* enum field names are confirmed.

The original native element class linkage is significantly narrower, but direct dynamic generic registration, original semantic name of field 2, official scene-instance `level`, and LootCSS `grade/level/type` remain unproven. Original client assets and full disassembly were not committed. The two temporary workflow files were removed.

## Retired original Cmd27685 field 2 keyed-container native call probes (issue #31)

[Original Global 7.1 client run 39710073036](https://github.com/RinoPaw/Genshin-Reverse/actions/runs/39710073036) independently pinned `JLDCJCKHJEM.OnAccept` calling native RVA `0x184EE960` with key from `KFOLLNPEMHH+0x98`; `JLDCJCKHJEM.Handle(int32)` selects an indexed element of the same packet collection, retrieves the same `+0x98` key, and calls native lookup RVA `0x184EE680` with the same `JLDCJCKHJEM+0x28` object. The lookup disassembly contains bucket and entry-array indexing, key comparison, chain-following and a -1 sentinel. Both native helper addresses are absent from exact method-level metadata entries and cannot be named from a nearby unrelated RVA. [Curated source-bound evidence](../versions/7.1.0-global/analyses/progression/economy/7.1-cmd27685-field2-keyed-container-native-flow.json) and [SHA-256 + opcode verifier](../scripts/audit-7.1-cmd27685-field2-keyed-container.py) are preserved; read-only temporary workflow retired. The key is an original indexed-container key; its original gameplay name and chest level semantics are unknown.

## Retired original Cmd27685 genericinst native type-array probe (issue #31)

The [SHA-pinned original Global 7.1 client run 39711696844](https://github.com/RinoPaw/Genshin-Reverse/actions/runs/39711696844) independently verified the native Il2CppType array entry of collector field AFGKAIPDLOH (type index 484299) is `72830000000000000100150000000000`, genericinst data low word `0x8372`. The message repeated-container field GEPFILACKKP (type index 547328) is `15570200000000002100150000000000`, data low word `0x25715`. Neither raw data value is a readable source file pointer. The numbers are not promoted to generic class indices without runtime registration evidence. [Native boundary report](../versions/7.1.0-global/analyses/progression/economy/7.1-cmd27685-native-collector-genericinst.json) and [verifier](../scripts/probe-7.1-cmd27685-native-genericinst.py) are maintained; the one-shot hosted workflow was removed.

## Retired pinned historical scene chest level census (issue #31)

The one-shot [source scan 39716548372](https://github.com/RinoPaw/Genshin-Reverse/actions/runs/39716548372) checked out exact `MeChen618/AstaPS-Resource@85b81a6` as a sparse clone, verified the AstaPS scanner source Git blob `6ed19ab`, and parsed **41,110 historical Lua files**. It counted **14,084** non-boss, historically labelled Chest gadgets, confirming the previous 43 boss exclusions. **11,401** entries explicitly declare nonzero top-level `level`; **2,683** omit it, all in the `no_metadata` group, with **zero** explicit `level=0` instances. The common explicit levels were 1, 6, 11, 16, 21, and 26; high special values include 75, 88, 92. [Bounded source result](../versions/7.1.0-global/analyses/progression/economy/7.1-historical-scene-chest-level-coverage.json) and [full original Actions artifact SHA-256](../versions/7.1.0-global/analyses/progression/economy/7.1-historical-scene-chest-level-coverage.json) preserve provenance; [reproducer](../scripts/audit-7.1-historical-scene-chest-levels.py) and unit tests remain. Temporary hosted workflow removed.

**This is server/fork history, not source-authenticated original Global 7.1 client scene instance data.** It validates where the **fork** Java `SceneObject.level` may become zero, and it cannot prove official level/grade mappings or whether the 2,683 no-metadata objects should reward. Reuse earlier original-client [805-path scenario probe](../versions/7.1.0-global/analyses/progression/economy/7.1-chest-native-scene-index-hypotheses.json) for separate origin constraints rather than re-promoting community Lua into native data.

## Retired current upstream AstaPS-Resource level coverage comparison (issue #31)

The one-shot [source-pinned upstream main census 39717247980](https://github.com/RinoPaw/Genshin-Reverse/actions/runs/39717247980) rechecked `MeChen618/AstaPS-Resource@c0213668889ed05cbeb86660f424c3daf18bfacd` using the same source-pinned chest scanner as the [historical census 39716548372](https://github.com/RinoPaw/Genshin-Reverse/actions/runs/39716548372). The two snapshots share the exact GadgetExcel JSON Git blob `9b32db00`, while `Scripts/Scene` tree changed (`82f16e4f` → `2017db1e`). Lua files grew **41,110 → 41,113**; the 14,084 historical Chest candidates, all direct `level` counts, source categories and per-scene counts stayed **exactly the same**. The **2,683** omitted `level` entries remain restricted to no-metadata gadgets. Compare [the SHA-256 authenticated snapshots report](../versions/7.1.0-global/analyses/progression/economy/7.1-current-upstream-scene-chest-level-coverage.json) and the [reproducible scanner](../scripts/audit-7.1-historical-scene-chest-levels.py). The one-shot workflow was removed.

This is source-authenticated **private-server Lua**, strictly separate from source-verified **original Global 7.1 client** bytes and any official-server entity level. Do not promote large scene `level` values to chest `grade`, or automatically reward the 2,683 no-metadata entries.

## Retired original client asset manifest + one scene-area Unity block inventory (issue #31)

Two source-authenticated original Global 7.1 read-only hosted probes have completed. [Sophon manifest + design index](https://github.com/RinoPaw/Genshin-Reverse/actions/runs/39717968684) verified the pinned original compressed manifest SHA-256 `3383e77a832d0076e84b4bd441867c293ccb2eff13e4380a2ef0df5b4d087d66`, **2,744** official files, **1,987** .blk files, **zero** standalone Lua and scene-named manifest filenames, and **247,073** original design-index hashed names with an empty paired type-string table. The manifest path inventory is a file-level finding only: it never proves the absence of embedded source scene objects. [Machine-readable source report](../versions/7.1.0-global/analyses/progression/economy/7.1-original-client-manifest-asset-container-inventory.json).

The second original [WorldArea Unity-class source run](https://github.com/RinoPaw/Genshin-Reverse/actions/runs/39718574430) reconstructed pinned 134MB client block `00/24230448.blk` from **113** source-verified chunks and independently authenticated the original scene3 WorldArea raw object `0c934d1c.dat`. Separate CLI class filters exported **167,673** `MiHoYoBinData` objects (**415,672,040** Raw bytes), **zero** `TextAsset`, and **zero** `MonoBehaviour` for this **one** block. [Machine-readable exact source report](../versions/7.1.0-global/analyses/progression/economy/7.1-original-worldarea-unity-classes.json). These class counts are scoped strictly to one original block; a chest instance or official level field remains unproven. Scripts [manifest/index](../scripts/probe-7.1-client-scene-asset-container.py) and [Unity block](../scripts/probe-7.1-world-area-bundle-object-types.py) are retained with unit tests. Both one-shot research workflows were removed. Normal CI does not download any game resources.

## Retired original 7.1 WorldArea native Gadget byte search plus known-positive decoder control (issue #31)

The [original WorldArea source run 39720593590](https://github.com/RinoPaw/Genshin-Reverse/actions/runs/39720593590) verified the exact source block `00/24230448.blk` and scanned all **167,673** original `MiHoYoBinData` raw objects for 20 precisely original-native Gadget prefab IDs represented as direct little-endian u32 values; **zero** matches occurred. To calibrate this negative, the [independently verified original GadgetExcel known-positive control 39720913286](https://github.com/RinoPaw/Genshin-Reverse/actions/runs/39720913286) decoded **30,599** original GadgetExcel rows from the source-authenticated Gadget raw table and found all **20** exact Gadget definitions, yet **zero** direct u32 byte occurrences in that same original raw data. The byte-grep hypothesis thus **fails even on known-positive original data**, so it cannot be used to infer missing official scene instances or Gadget IDs. The [source-bounded summary report](../versions/7.1.0-global/analyses/progression/economy/7.1-original-client-gadget-id-byte-search-boundary.json), [strict artifact SHA-256 cross-verifier](../scripts/audit-7.1-native-gadget-byte-search-boundary.py), [WorldArea original scan](../scripts/probe-7.1-worldarea-native-gadget-id-contacts.py), and [Gadget native table control](../scripts/control-7.1-gadget-raw-id-byte-scan.py) are retained. Both topic-specific hosted workflows retired; original game binaries were not committed.

## Retired original 7.1 WorldArea design-index-to-export coverage (issue #31)

[Exact original Global 7.1 source run 39723102117](https://github.com/RinoPaw/Genshin-Reverse/actions/runs/39723102117) cross-checked independently authenticated original design index (247,073 full 40-bit asset hash records), the exact source block `00/24230448.blk`, an independently SHA-256-verified scene 3 WorldArea Raw positive control and **167,673** `MiHoYoBinData` Raw exports. Exactly **167,673** source-index records point at that block, and every exported 32-bit filename stem belongs to at least one of those index records. **167,667** filenames are unique across the design index; **six** are truncated-hash collisions with another index record and retain separate 40-bit identities. Total bytes: **415,672,040**. [Machine-readable verified source report](../versions/7.1.0-global/analyses/progression/economy/7.1-original-worldarea-design-index-export-coverage.json), [retained reproducer](../scripts/audit-7.1-original-worldarea-index-coverage.py), and [placement-authority boundary](../versions/7.1.0-global/analyses/progression/economy/7.1-original-world-chest-placement-authority.md). The source-only workflow ran successfully and was removed, so routine CI stays independent of downloaded game assets. Hash membership does **not** decode instance schemas or determine whether official chest placement is client- or server-authored. No original scene instance `level` or reward semantics were proven.

## Retired original 7.1 Cmd27685 native element field census (issue #31)

The one-shot [source-authenticated original Global 7.1 run 39724766898](https://github.com/RinoPaw/Genshin-Reverse/actions/runs/39724766898) reconstructed the SHA-256-pinned client executable, verified the exact derived metadata CSV Git blobs and disassembled native element reader `KFOLLNPEMHH.NLGBJEEJDLG` at `0xB43A2A0`. Its [original field/report artifact](../versions/7.1.0-global/analyses/progression/economy/7.1-original-cmd27685-element-metadata-reader-census.json) records 27 IL2CPP class field rows, 17 method rows, 30 native scalar comparisons and 23 candidate protobuf field numbers. **Only field 2 / wire 0** has independently verified native wire-read/store evidence. No other field semantics, packet direction, actual scene-Gadget placement, `level` or reward origin was promoted. The reproducer `scripts/probe-7.1-cmd27685-element-field-census.py` and regression tests are retained; the temporary one-shot research workflow was removed. Routine CI does not download original game samples.

## Retired original 7.1 scene-entity nested-type source probe (issue #31)

[Source-authenticated exact Global 7.1 run 39726041813](https://github.com/RinoPaw/Genshin-Reverse/actions/runs/39726041813) verified the original native client sample and metadata indexes, and traced direct nested IL2CPP field classes in the original `KFOLLNPEMHH` entity element. The repeated `HCDGGIDOEFA` class (5 element fields) has integer and runtime-class-handle members without direct float fields. The separate `ABOOLMJBDKE` class has 3 declared float32 fields, and its original native reader writes three distinct `movss` destination offsets. [Machine-readable evidence](../versions/7.1.0-global/analyses/progression/economy/7.1-original-scene-entity-nested-native-type-evidence.json) and the retained `scripts/probe-7.1-cmd27685-nested-native-types.py` audit preserve exact source metadata, hashes and bounded native instructions. The one-shot source workflow was removed; routine CI remains read-only, lightweight and independent of client sample downloads. Neither chest location nor official server ownership has been proven.

## Active one-shot original 7.1 entity float-parent native trace

`one-shot-7.1-entity-float-parent.yml` is a temporary PR-only exact-Global-7.1 original-client investigation. It SHA-256 verifies native reader windows `KFOLLNPEMHH.NLGBJEEJDLG` at `0xB43A2A0` and `ABOOLMJBDKE.NLGBJEEJDLG` at `0x11B25D70`, binds the original metadata field `DLOEKFLGJCG`, and records parent pointer accesses/calls and child native float writes. Pointer offsets and nearby calls remain candidate leads until native class/field identity is proven. Do not infer coordinates, scene instances or server authority from these opcodes. The source-fetch workflow will be removed once source evidence is committed; normal CI remains download-free.
