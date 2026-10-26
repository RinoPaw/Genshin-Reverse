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

## Retired original 7.1 entity float-parent native trace

[Original Global 7.1 client source run 39727463920](https://github.com/RinoPaw/Genshin-Reverse/actions/runs/39727463920) validated independently hashed native `KFOLLNPEMHH` parser, `KFOLLNPEMHH.CopyFrom`, static initializer, and `ABOOLMJBDKE` reader and CopyFrom windows. This retained [structured source and native call-edge evidence](../versions/7.1.0-global/analyses/progression/economy/7.1-original-scene-entity-float-parent-native-chain.json) confirms a typed metadata reference but does not resolve the actual runtime child field offset, indirect dispatch, float spatial meaning or chest placement source. The reusable audit is `scripts/probe-7.1-entity-float-parent.py`; regression tests pin the original evidence. The short-lived one-shot original-client workflow was retired after success, leaving CI lightweight and without downloadable client samples.

## Retired original 7.1 native tagged-variant and exact-RVA callee owner probe

[Source-authenticated original Global 7.1 run 39728673910](https://github.com/RinoPaw/Genshin-Reverse/actions/runs/39728673910) verified the exact original native executable reader/CopyFrom/static-initializer byte hashes and original method-index Git blob. [The source evidence](../versions/7.1.0-global/analyses/progression/economy/7.1-original-entity-variant-native-call-owners.json) records four tag-shaped comparisons, the tagged-variant discriminator object offset, and exact method-RVA owners for direct calls and jumps without inventing semantic field labels. The retained reproducer is `scripts/probe-7.1-entity-oneof-call-owners.py`; unit tests pin the evidence. The temporary original-client download workflow has been retired, leaving ordinary PR CI lightweight. This audit does not assign source ownership of official chest instances or original float position semantics.

## Retired original Global 7.1 Scene Point client asset audit

[Exact original Global 7.1 source run 39730630642](https://github.com/RinoPaw/Genshin-Reverse/actions/runs/39730630642) validated SHA-256-pinned original design index, manifest, original source block and Raw exporter. It independently matched `scene3_worldArea` as the original-source positive control and verified **13 Scene/Point resource path hashes and binary payload frames**, one for each already verified WorldArea scene ID. All resolve to original Unity block `00/24230448.blk`; source raw payloads total **183,172 bytes** and all 13 are distinct. [Original per-scene source evidence](../versions/7.1.0-global/analyses/progression/world/7.1-original-scene-point-source-payload-census.json) retains hashes, source identity, byte counts and a preserved workflow artifact digest. [Reusable source audit](../scripts/audit-7.1-original-scene-point-assets.py) and regression tests remain; the one-shot download workflow has been retired so normal CI does not fetch game resources. This demonstrates source-original client Scene Point asset **presence**, with **unknown internal spatial/Gadget instance schema and no official chest authority conclusion**.

## Retired original 7.1 Scene Point native XOR array-reader source probe

The [source-verified original Global 7.1 client run 39734845897](https://github.com/RinoPaw/Genshin-Reverse/actions/runs/39734845897) scanned exact native executable machine instructions against byte-derived count-transform leads from all 13 independently SHA-authenticated Scene Point assets. A single original native aligned immediate `0xC14B813C` matched in `NLDEPJEOJGC.GMENPOPMKAA` at RVA `0xAD23066`; the subsequent original instructions independently confirm a four-byte stream read, XOR, cursor advance and an element-count loop. [Retained evidence](../versions/7.1.0-global/analyses/progression/world/7.1-original-scene-point-native-xor-reader-evidence.json), the reproducer `scripts/probe-7.1-scene-point-native-header-transform.py` and regression tests preserve original hashes, instruction RVAs and the 13 tentative counts. Original Scene Point loader association, the stream's prefix offset, full row consumption and all chest-instance meanings remain unproven. The one-shot original-client download workflow was retired after successful source verification; regular CI needs no proprietary client binaries.

## Retired original Global 7.1 Scene Point-compatible native array-reader caller trace

[Original SHA-pinned native source verification run 39737316657](https://github.com/RinoPaw/Genshin-Reverse/actions/runs/39737316657) found exactly one independently aligned source-native E8 direct call to `NLDEPJEOJGC.GMENPOPMKAA` at RVA `0xAD23000`, in `IJNOFJEOMBD.GMENPOPMKAA` at `0xEE66BF1`. It traced a 16-bit outer mask `(sourceU16 + 0xF077) mod 2^16`, matched 13 independently source-verified original Scene Point byte prefixes to its branch flags and inspected the intervening `CCPCOHEPGHC.GMENPOPMKAA` initial one-byte input read. The loader-to-resource identity, complete helper consumption for byte `0xCB`, and scene Point/Gadget/chest coordinates are still unproven. [The machine-readable source evidence](../versions/7.1.0-global/analyses/progression/world/7.1-original-scene-point-parent-mask-native-callchain.json), reproducible script `scripts/probe-7.1-scene-point-native-caller-chain.py` and pinned regression tests are retained. The original-client-fetch workflow has been retired, so ordinary CI requires no client binaries.

## Retired original 7.1 native 0xCB helper single-byte source trace

The [official Global 7.1 original executable verification run 39740640976](https://github.com/RinoPaw/Genshin-Reverse/actions/runs/39740640976) authenticated a **1,984-byte native method** `CCPCOHEPGHC.GMENPOPMKAA` and fully verified 6 contiguous instruction blocks, 5 conditional jumps, exactly 1 input byte read, 1 cursor writeback, 0 nested calls and return for input `0xCB`. [Source-native proof](../versions/7.1.0-global/analyses/progression/world/7.1-original-scene-point-cb-one-byte-native-proof.json) and the reusable `scripts/probe-7.1-scene-point-cb-native-branch.py` preserve original hashes, branch addresses and tests. All 13 independently SHA-verified Scene/Point assets have candidate byte `0xCB` at payload position two, but no official asset-loader-to-parent connection, original scene point row semantics or original Gadget/chest placement ownership is yet authenticated. The temporary source-fetch workflow was retired before merging. Ordinary CI remains client-download-free.

## Retired original 7.1 Scene Point-compatible array element factory native audit

The [source-authenticated exact original Global 7.1 job 39742839841](https://github.com/RinoPaw/Genshin-Reverse/actions/runs/39742839841) verified the original executable and methods/fields Git blobs. It traced `NLDEPJEOJGC.GMENPOPMKAA` array element byte transformation, a direct factory call into `NLLGJBBHHAN.JIEAILFJKNA`, its SHA-256-pinned original **31-case jump table**, and the element object virtual reader invocation at vtable offset `+0xF8`. [Source evidence](../versions/7.1.0-global/analyses/progression/world/7.1-original-scene-point-array-element-factory-native-evidence.json) records all 31 native branch RVAs and candidate runtime class slots; [reproducer](../scripts/probe-7.1-scene-point-array-element-native.py) and tests check original class/method identity and unresolved chest coordinates. The Scene Point file-loader-to-reader relation and concrete subtype class/field meaning remain unproven. The one-shot source fetch is retired; normal CI does not download the original client.

## Retired original Global 7.1 Scene Point native length-aware first-element source audit

[Original SHA-pinned native source job 39745021277](https://github.com/RinoPaw/Genshin-Reverse/actions/runs/39745021277) linked the verified 7.1 native generic array reader U16 length prefix (`sourceU16 + 0x189A`), an existing source-verified stream cursor helper (`0xFD53090`), and the 31-case native element byte decoder. Its 13 exact source-original Scene/Point prefixes exclude an immediate subtype at byte +7 and exhibit 12 candidate spans of length 1 and one span of length 2 (Scene 7). Conditional candidate first subtype offsets are +10 in 12 scenes and +11 in Scene 7; numeric candidate IDs 14 for Scene 3 and 1 for 12 others. [Archived source report](../versions/7.1.0-global/analyses/progression/world/7.1-original-scene-point-first-element-native-length-prefix.json), reproducible probe `scripts/probe-7.1-scene-point-first-element-prefix.py`, and tests retain original native bytes and SHA. The original client Scene/Point loader binding, full row consumption and all chest Gadget/level meanings are still unverified. The one-shot original binary download workflow was retired before merging.

## Retired original Global 7.1 Scene Point-compatible factory class-slot xref audit

The [source-authenticated original Global 7.1 run 39746971148](https://github.com/RinoPaw/Genshin-Reverse/actions/runs/39746971148) verified the 31-case native factory class slots and exact original executable x64 RIP-relative class-slot references aligned against the original generated method index. The retained [69 native witness instructions for cases 1 and 14](../versions/7.1.0-global/analyses/progression/world/7.1-original-scene-point-factory-1-14-native-class-slot-xrefs.json) show 21 aligned references for original case 1 (`0x57C37B0`) and 48 for original case 14 (`0x57C1970`), with source method names, instruction bytes and archive provenance. The full original 31-case source scan is captured in the retained run artifact, and the reproducer `scripts/probe-7.1-point-factory-class-slot-xrefs.py` plus regression test remain.

A method that references an original runtime class slot is not necessarily a method declared on the class instantiated by that slot. Concrete source IL2CPP type identity, native virtual reader `+0xF8`, exact Scene/Point file consumer and all chest instance meanings remain unproven. The one-shot original-client download workflow was retired after collecting evidence. Normal CI remains client-binary-free.

## Retired original Global 7.1 Scene Point-compatible factory type-check source probe

The [source-pinned original Global 7.1 binary verification run 39748788313](https://github.com/RinoPaw/Genshin-Reverse/actions/runs/39748788313) disassembled three `JOBDNGNICNC` native methods on original types `OAGPJFNDNNG`, `BFLGIHGLPBF` and `NDPMDLJEOLG`; they include four independently aligned RIP-native loads of factory class slots case 1 and 14, followed by class-hierarchy checks. Both source-native static class slots `0x57C37B0` and `0x57C1970` live in an unbacked original `.data` region, and no direct 64-bit RIP-relative register-to-class-slot store was found in the bounded native code scan. This does not rule out metadata-use registration or indirect initialization. [Source-native evidence](../versions/7.1.0-global/analyses/progression/world/7.1-original-point-factory-class-slot-runtime-checks.json), [reproducer](../scripts/probe-7.1-point-factory-slot-owner-native-methods.py) and regression tests are retained. Concrete original class identities, element reader method `+0xF8`, Scene Point loader link, chest coordinates and level remain unknown. The temporary original-client fetch workflow was retired; normal CI requires no proprietary client binary.

## Retired original 7.1 factory class-slot metadata usage audit

[Original Global 7.1 EXE and metadata verification run 39754660492](https://github.com/RinoPaw/Genshin-Reverse/actions/runs/39754660492) SHA-verified both original client sources, and used native recovered obfuscated metadata usage-list and usage-pair formulas. The resulting candidate table contains 311,730 list prefixes and 788,058 decoded pair candidates. Original numeric kind 1 reaches exactly runtime type index 683,573 without exceeding the source type-array bounds, and kind 3 respects the original native method count. **Final ten records are anomalous kind-0 candidates** and exact end-of-table / runtime metadata destination-slot mapping remain unverified. Across all 31 source-native factory class slots, no direct file-backed image VA qword holders or aligned raw 32-bit RVA/VA candidates were found; controls were also negative. This supports further runtime initializer research, not a direct mapping of factory numeric case 1/14 to metadata TypeDefinitionIndex or chest semantics.

[Retained original source report](../versions/7.1.0-global/analyses/progression/world/7.1-original-point-factory-metadata-usage-table-boundary.json) and `scripts/probe-7.1-point-factory-metadata-usage-binding.py` preserve the original binary provenance and structured output with regression tests. The one-shot original client/metadata fetch workflow was removed; ordinary CI stays binary-free.

## Retired original Global 7.1 metadata usage initializer and pointer array source verification

[Original Global 7.1 native source verification run 39758780633](https://github.com/RinoPaw/Genshin-Reverse/actions/runs/39758780633) authenticated original runtime helper `0x523400`, recorded its native 8-case switch at `0x5238A4`, and traced the metadata usage pair destination register into pointer arrays under original registration global slot `0x5AD52A8`. In particular original numeric usage kind `1` branches to `0x52362D`, reads registration pointer member `+0x30` and invokes `0x524E80`, then writes the result to `[runtimeArray+destinationIndex*8]` via `0x5234C0`. The first original generated method RVA follows well after the native initializer, so its original function must not be attributed an obfuscated generated-method owner. [Exact source proof](../versions/7.1.0-global/analyses/progression/world/7.1-original-metadata-usage-native-kind-array-writes.json), reproducible original native disassembler `scripts/probe-7.1-usage-initializer-native.py`, and regression tests are retained.

Numeric metadata usage kind `1` is a distinct index namespace from the original Scene Point-compatible 31-case *element factory* subtype `1`. Neither kind of number is assigned a gameplay semantic name. The original runtime array does not yet link a destination index to original static factory class slots `0x57C37B0` / `0x57C1970`; the original Scene/Point loader, chest positions and level remain unverified. The temporary original sample workflow has been retired; normal CI downloads no original client.

## Retired exact Global 7.1 metadata kind-1 type-index resolver source audit

[Source-original Global 7.1 native run 39763864736](https://github.com/RinoPaw/Genshin-Reverse/actions/runs/39763864736) proved exact native `0x524E80` cache/read/write flow linked from source metadata usage kind 1, bounded core SHA-256 `0bf64afba538ed8bf9d3e482c240b5a6bdab2502c200c1cf3af8448a3ad649be`, index*8 cache under `0x5AD52D0`, and native 16-byte metadata record table under `0x5AD52A0+0x48`. Source `0x50D9C0` reads an original record discriminator byte at `+0xA`, then switches over raw numeric 1–30 via a 30-case jump table at `0x50DC50` with all case targets instruction-aligned. Original `0x512DB0` initialization was inspected through a separate partial source-native window. [Archived machine-readable source evidence](../versions/7.1.0-global/analyses/progression/world/7.1-original-metadata-kind1-type-resolver-30-case-native.json), reproducer `scripts/probe-7.1-metadata-kind1-helper-native.py` and regression tests retain the exact SHA, opcode witnesses and all cases.

Metadata usage kind 1, the type-record's numeric kind 1, and the Scene Point-compatible factory's numeric element case 1 must remain distinct. Neither original static factory class slot, native Scene Point resource loader, chest position nor Gadget level is thereby proven. The one-shot exact-original client download workflow has been retired; routine CI never fetches or disassembles the original full executable.

## Retired Global 7.1 post-type-resolution reachable native CFG

The [original SHA-256-verified Global 7.1 client run 39770271022](https://github.com/RinoPaw/Genshin-Reverse/actions/runs/39770271022) reconstructed reachable native x64 branches in the original class initializer `0x512DB0` from a source-verified 0x6000-byte native window. Its result finds **1,279 reachable source instructions**, one original return (`0x513DE0`), **57 direct calls** (four self-recursive, two to native type-record resolver `0x50D9C0`), eight unresolved indirect callee identities, and no undecodable instruction or unresolved branch destination in the bounded source window. Calls are not traversed and this is not runtime path coverage. [Retained source evidence](../versions/7.1.0-global/analyses/progression/world/7.1-original-kind1-post-resolution-init-reachable-cfg.json), reproducer `scripts/probe-7.1-kind1-post-init-cfg.py` and provenance tests preserve the result. The one-shot sample workflow is removed; routine CI still has no native sample download. Concrete Scene Point factory cases 1/14, original scene loader and chest placements remain unverified.

## Retired original Global 7.1 raw type record 17/18 to protected native lookup audit

The [source-original Global 7.1 verification run 39775580124](https://github.com/RinoPaw/Genshin-Reverse/actions/runs/39775580124) verified original native record kinds 17 and 18 converge on native `0x50D9EA`, which loads the record's first dword and tail-jumps to `0x51CD50`. Original `0x51CD50` is a five-byte source-native near-jump thunk targeting file-backed `0x19EAE27C` with obfuscated instruction flow, not an independently decoded final class lookup. Original runtime Il2CppType array positive control index 405772 holds kind `0x12`, source dword `84249`, and original decoded metadata name `DMMJNICDOHM`. [Committed machine evidence](../versions/7.1.0-global/analyses/progression/world/7.1-original-type-record-17-18-native-typedef-thunk.json), [reproducer](../scripts/probe-7.1-original-type-def-kind-17-18-native.py) and tests guard the native byte hashes and unproven joins. The source original client fetch workflow has been removed before merge.

No original 31-case Scene Point element factory class slot has been assigned a concrete TypeDefinitionIndex. Runtime metadata-usage kind, raw Il2CppType record kind and element-factory subtype are separate numerical domains. Original Scene Point loader linkage, chest position and level authority remain unverified.

## Retired original 7.1 factory case 1/14 native constructor paths

The exact Global 7.1 source [run 39778014590](https://github.com/RinoPaw/Genshin-Reverse/actions/runs/39778014590) SHA-verified the original client and native 31-way element factory, then followed direct source-native jumps from cases 1/14 through the source return. Both routes pass the same original native call `0x529A10` and call distinct source metadata `.ctor` method starts with the returned object pointer. The retained [machine evidence](../versions/7.1.0-global/analyses/progression/world/7.1-original-point-factory-case-1-14-local-native-paths.json), [reproducer](../scripts/probe-7.1-point-factory-case-local-native.py) and tests record the original byte addresses and constructor method identities. This establishes constructor call targets, not the source-native helper's allocator semantics or an exact factory class-slot-to-TypeDefinitionIndex mapping. The one-shot source-client workflow was removed after verification; normal CI remains independent of original game downloads. Client Scene/Point loader, chest coordinates and level remain unverified.

## Retired original Global 7.1 factory shared native helper 0x529A10

The one-shot [original EXE verification run 39779432390](https://github.com/RinoPaw/Genshin-Reverse/actions/runs/39779432390) inspected source file-backed native helper `0x529A10` reached by factory numeric cases 1/14. The exact 0x400-byte original window SHA-256 is `efaaef4a2f37f1aa56278c1f8981aa4b05b788ae0cbf42956e5f678a17080868`. Native control-flow and aligned instruction checks establish this is an ordinary non-thunk code entry, includes direct calls to class initialization and type resolution helpers, and has two direct calls to native `0x55A0B0`. Along a source branch, the returned value is copied `rax → rdi` at `0x529B2D` then `rdi → rax` at `0x529B50` before `ret` at `0x529B5A`. This evidence does **not** establish `0x55A0B0` allocator semantics or prove the static runtime class slots' concrete TypeDefinitionIndex. [Retained original source report](../versions/7.1.0-global/analyses/progression/world/7.1-original-point-factory-helper-529a10-native.json), [reproducer](../scripts/probe-7.1-point-factory-helper-529a10.py) and regression tests guard this bounded result. The one-shot original-client fetch workflow was removed. Scene/Point input binding, chest instance coordinates and level remain unresolved.

## Retired Global 7.1 original factory native helper 0x55A0B0 pointer-list audit

[Original Global 7.1 source run 39780489911](https://github.com/RinoPaw/Genshin-Reverse/actions/runs/39780489911) verified the exact client EXE and previous original shared-factory helper evidence, then inspected the source native `0x55A0B0` entry. Its 0x800-byte original SHA-256 is `5d9bca48ad84ed11588c7c14d80e81b92ea0c9424811ebc480caff4d0dd79f1b`. Source instructions authenticate the native `+0x20` pointer-list head read, next-pointer load, head update, and return of the original list node; the original function's `0x55A19E` return and `0x55A1E8` INT3 padding are verified. A separate original `0x55A1F0` function is reached on a fallback tail jump. This is byte-backed list-head/pointer-return behavior, **not** an established complete object allocator, class TypeDefinitionIndex join, Scene/Point resource parser or chest level. [Archived original native report](../versions/7.1.0-global/analyses/progression/world/7.1-original-point-factory-55a0b0-native-freelist.json), [reproducer](../scripts/probe-7.1-factory-helper-55a0b0.py), and tests remain; the single-use sample fetch workflow is retired and normal CI downloads no original client.

## Retired original Global 7.1 native factory fallback 0x55A1F0 CFG

The exact original-client [run 39993435480](https://github.com/RinoPaw/Genshin-Reverse/actions/runs/39993435480) SHA-verified Global 7.1 EXE and independently retained original factory native tail-jump `0x55A1D5 → 0x55A1F0`. The source 0x400-byte native window SHA-256 is `7ecaf3a1e7dc075f775f2925ef497e73428736c9e0ec312b8be94a0a56ae03a9`. Both outcomes of every direct conditional branch were traversed: **222 source reachable instruction starts**, a return at `0x55A573`, 15 direct call sites, two unresolved indirect call target identities, and zero unresolved branch destinations or undecodable instructions within the bounded original source window. Direct callees' bodies were not traversed. [Source-original CFG evidence](../versions/7.1.0-global/analyses/progression/world/7.1-original-factory-fallback-55a1f0-source-cfg.json), [reproducer](../scripts/probe-7.1-point-factory-fallback-55a1f0-cfg.py) and regression tests remain. The single-use original binary fetch workflow was retired after verification. The bounded CFG does not identify an allocator API or runtime factory class, Scene/Point loader, chest instance positions or level.

## Retired original Global 7.1 factory 1/14 constructor-owner native reader declarations

[Original executable and metadata validation run 39994920582](https://github.com/RinoPaw/Genshin-Reverse/actions/runs/39994920582) SHA-verified the exact Global 7.1 EXE and metadata, both original generated methods/fields CSV Git blobs, and previously retained factory case 1/14 native constructor call proof. Case 1 original constructor-owner class `BHJILFMHGEE` (TypeDefinitionIndex 54542) declares 13 fields and four methods, including source method `GMENPOPMKAA` (index 436910, RVA `0x138B9390`); case 14 class `NKJPPNFAEEF` (TypeDefinitionIndex 65289) declares 16 fields and four methods, including its own `GMENPOPMKAA` (index 527284, RVA `0x8613440`). Original native code at **`0x8613469`** directly calls **`0x138B9390`**, independently establishing an exact reader-to-reader native call.

[Machine-readable original metadata/native observations](../versions/7.1.0-global/analyses/progression/world/7.1-original-point-factory-case-1-14-ctor-owner-reader-native.json), [reproducer](../scripts/probe-7.1-point-factory-ctor-type-declarations.py) and tests preserve source 3568/4944-byte reader windows, hashes and original native call opcodes. This direct code relationship does not establish an inherited vtable slot `+0xF8`, class-slot registration or any Scene/Point asset reader or chest position/level. The one-shot source binary fetch workflow was retired after evidence capture; ordinary CI remains client-download-free.

## Retired original Global 7.1 factory 14 → 1 → NLDEP one-argument reader native trace

[Original EXE run 39995836590](https://github.com/RinoPaw/Genshin-Reverse/actions/runs/39995836590) verified the original factory numeric case 14 reader directly calls case 1 reader at `0x8613469`, and the case 1 reader directly calls one-argument `NLDEPJEOJGC.GMENPOPMKAA` at `0x138B93B9 → 0xAD22310`. Original metadata distinguishes that method (index 514422, one `FNIAHJGHFAK` parameter) from its same-name two-argument array reader (index 514423, `0xAD23000`). The original 0xCF0-byte native source window at `0xAD22310` SHA-256 `07658f6b1e8111e4629b50b6ac8d73721da69208c89d998df5abf58bb5c7a856` contains 59 aligned direct calls, one indirect call and **zero direct calls to `0xAD23000`**. The one indirect target remains unresolved. [Retained machine evidence](../versions/7.1.0-global/analyses/progression/world/7.1-original-point-factory-14-1-nldep-direct-reader-chain.json), [reproducer](../scripts/probe-7.1-point-factory-nldep-overloads-native.py) and tests preserve both positive call paths and the bounded negative overload result. The one-shot client acquisition workflow was retired; no official Scene/Point loader or original chest placement semantics are proved.

## Retired exact original Global 7.1 Scene/Point native lookup constant census

[Original executable validation run 40051744134](https://github.com/RinoPaw/Genshin-Reverse/actions/runs/40051744134) SHA-pinned Global 7.1 EXE, matched all 13 original indexed Scene/Point names and native parent reader machine bytes, and scanned **13 image-backed PE sections totaling 444,246,016 bytes**. No original 40-bit Scene/Point hash bytes, their zero-extended qword forms, their full paths or basenames (ASCII or UTF-16LE), or shared `Data/_BinOutput/Scene/Point/` path substring were present. Of the 13 truncated 32-bit hash candidates, exactly one 4-byte byte pattern occurs: Scene 101 `1b7f05d2` at original `0x67FB5E4` within the **nonexecutable** `.pdata` section. The full five-byte hash does not match there. It has no independently verified lookup meaning.

This is a **bounded negative literal test**, not a proof that a runtime-generated asset lookup, compressed string, indirect hash table, Scene/Point file parser or the original chest data are absent. [Complete source scan](../versions/7.1.0-global/analyses/progression/world/7.1-original-scene-point-client-lookup-literals.json), [reproducer](../scripts/probe-7.1-scene-point-native-lookup-literals.py) and tests are retained; the original-client one-shot workflow was deleted after verification. The next loader investigation should follow runtime path formation or reverse xrefs from authenticated native reader dispatch rather than searching these source-static literal forms again.

## Corrected original Global 7.1 native parent-reader reverse callgraph and consumer

[Original EXE run 40052262087](https://github.com/RinoPaw/Genshin-Reverse/actions/runs/40052262087) independently rescanned original SHA-256-pinned native machine code with method-start instruction alignment and found **two** authentic E8 calls to `IJNOFJEOMBD.GMENPOPMKAA` at `0xEE66B20`: `IJNOFJEOMBD.OHPBNHHCBLB` at `0xEE67087`, and `KLLNGCPBLMM.NPBDNMOKJPE(uint32)` at `0xF04F4B5`. The earlier source probe had a **bug**: it compared parent-call candidates to the nested reader constant `0xAD23000`. It incorrectly rejected both parent calls. The historical source report, script and unit test have been corrected using this independently authenticated run.

[Second native run 40052638324](https://github.com/RinoPaw/Genshin-Reverse/actions/runs/40052638324) inspected the full **608-byte** original `KLLNGCPBLMM.NPBDNMOKJPE` native method (`0xF04F350`, SHA-256 `b8e3420373fd37e3a6e563c803413206093955b27311407199682e0234219b71`) and found **12 separately aligned direct callers**. Among them, original `Miscs.IsUnderSceneHighestPoint` calls it at `0x12E2CF1E`. This is a proven original source call relation involving a scene-related named method, **not an authenticated link to any Scene/Point asset**, a specific runtime class vtable, original chest coordinates or instance level. [Source reader graph](../versions/7.1.0-global/analyses/progression/world/7.1-original-scene-point-parent-reader-reverse-native-callers.json), [external consumer evidence](../versions/7.1.0-global/analyses/progression/world/7.1-original-point-parent-reader-kllng-consumer-native.json), native reproducer scripts and tests persist after retiring the one-shot workflow.

## Retired original Global 7.1 parent native reader input producer and returned buffer chain

[Exact original EXE + generated metadata run 40052988980](https://github.com/RinoPaw/Genshin-Reverse/actions/runs/40052988980) authenticated the two source direct calls in `KLLNGCPBLMM.NPBDNMOKJPE(uint32)` (`0xF04F350`) to its separately original-declared `KLLNGCPBLMM.FGDNHNBPCKA(uint32)` (`0xF06A600`, method index 615966), and two original source direct calls to `PMOALIJHONP.GCJPJCKPGLI(string,int32,int32)` (`0x1016E3F0`, method index 420370). The exact native source `0x1016E4C1` writes a result record length at `+0x1C`, `0x1016E4C4` stores a pointer at `+0x20`, `0x1016E4C8` returns that record object and `0x1016E4D3` returns. At `0xF04F417`, the original parent caller receives that method's return in `rax`, holds it in `r14` at `0xF04F41C`, moves `r14` to argument register `rdx` at `0xF04F4B2`, and directly calls original `IJNOFJEOMBD.GMENPOPMKAA` at `0xF04F4B5`. Thus there is a **source-instruction-authenticated record-return-to-parent-parser argument chain**.

The method producing the `string` input is still obfuscated and the literal path/file/resource identity is unverified. This link to a native buffer-provider does **not** prove any one of the 13 indexed Scene/Point resources supplied those bytes, that the input `uint32` denotes a scene ID, or that the client has chest placements or per-instance `level`. [Machine-readable original native producer windows](../versions/7.1.0-global/analyses/progression/world/7.1-original-scene-parent-native-pre-input-callees.json), [reproducer](../scripts/probe-7.1-point-parent-pre-input-native.py), unit tests and source archive are retained. The one-shot original-client workflow was removed after the research run.

## Original Global 7.1 scene parent ZIP loader and string formatting identities

[Original client run 40292990195](https://github.com/RinoPaw/Genshin-Reverse/actions/runs/40292990195) and its archived [native source report](../versions/7.1.0-global/analyses/progression/world/7.1-original-scene-parent-string-and-zip-loader-native-callees.json) extend the SHA-256-pinned original input handoff to concrete generated metadata declarations. `KLLNGCPBLMM.FGDNHNBPCKA(uint32)` at `0xF06A600` calls original `NumberFormatInfo.get_CurrentInfo` at `0x194AED40`, `NumberFormatter.NumberToString(string,uint32,IFormatProvider)` at `0x195F34B0`, then tail-jumps into `String.Concat(string,string,string)` at `0x194675B0` (or original `ILFixDynamicMethodWrapper.__Gen_Wrap_30` at `0xD8E1CB0`). The original result-record builder `PMOALIJHONP.GCJPJCKPGLI(string,int32,int32)` at `0x1016E3F0` **directly calls `CommonMiscs.LoadBinDataZipFile(uint64,int32,int32,CompressionType,int32)`**, exact original RVA `0x6D8CF60`, method index `79876`, byte-call site `0x1016E4AC` (opcode `e8afeac1f6`). Original ZIP loader source window length **656 bytes**, SHA-256 `af4b34d807feb189c183574127598bdd1a1066d0536f2a199fff05b14807fcbd`.

This is an actual original binary ZIP loader call from the scene-facing reader's data producer. Its `uint64` input comes from an earlier native call `0x1475C1D0`, currently without an exact metadata method declaration. Its resource-path hashing/key transform and the runtime format-string/literal inputs to `FGDNHNBPCKA` remain unverified. **No direct original 7.1 file-backed bridge yet connects the ZIP loader to one of the 13 indexed `Data/_BinOutput/Scene/Point/scene*_point` assets**, and no original chest coordinates, per-instance `level` or official server-authority fields have been authenticated. Reproduction uses original exact EXE/metadata and source-pinned method indices only.
