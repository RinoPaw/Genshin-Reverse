# Quest native-resource research handoff

Checkpoint: 2026-10-05

This file preserves the current resumable state for issues #8 and #9. It records only evidence that was reproduced or independently checked during the current investigation. Do not use it to justify AstaPS-Resource data edits until the promotion gates below are met.

## #8 QuestExcel extraction / prerequisite corruption

Current status: `UNRESOLVED`, active native-resource investigation.

### Confirmed resource-access progress

- The exact 7.1 Global Sophon manifest contains 2744 files.
- 1987 entries are under `AssetBundles/blocks/**/*.blk`.
- The earlier `blocks.xmf` / `.xmf` manifest-path assumption is rejected for this sample; that probe returned no usable `.xmf` candidate.
- `.github/workflows/probe-quest-table-assets.yml` now reconstructs small exact-sample AssetBundle block entries directly through `genshinre.samplefetch.reconstruct` instead of assuming an index filename.
- Workflow run `37225861093` at head `4a6a41774b2a9b34d8fd70c29ad8f1c63d96945a` completed successfully. This proves the small-block reconstruction path works against the pinned manifest/chunk source. Content classification of those reconstructed blocks is still pending.

Do not infer QuestExcel storage from block filename order, block size, or public dump layout. The next proof step is to identify the block/index relationship and the exact table blob or loader path.

### Exact/current quest evidence already useful as controls

Pinned 7.1 published resource evidence for main quest 351 gives a useful semantic control:

- `35101` has a `QUEST_CONTENT_TEAM_DEAD` fail condition.
- That failure executes `QUEST_EXEC_ROLLBACK_QUEST 35100`.
- `Quest/351.json` and `QuestBrief/351.json` agree on this relationship.
- `suggestTrackMainQuestList: [352]` is tracking/navigation metadata and must not be reinterpreted as a prerequisite edge.

This evidence is useful for validating a recovered Quest row schema, but it does not prove where prerequisite corruption is introduced.

### Important boundaries

- Public `BinOutput/Quest/*` and `ExcelBinOutput/QuestExcelConfigData.json` remain separate evidence layers.
- Missing/shifted public fields are not negative evidence for exact-client serialization.
- Field ordinal/name assumptions from older extractors are unsafe. Recover current field reads from the exact 7.1 row deserializer and validate by full-byte consumption or an equivalently strong invariant.
- Chapter 1301 remains an important current-version control because historical 3.7/4.0 prerequisite data degenerates to `QUEST_COND_UNKNOWN [0,0]`; do not restore those old values.
- No new AstaPS-Resource quest prerequisite mutation is justified by the current native-resource work yet.

### Resume here

1. Inspect the artifacts from run `37225861093` and classify the reconstructed small `.blk` files by magic/header/contained strings or tables.
2. Use the block/index relationship from current client tooling or independently reconstructed format knowledge to locate the exact `Data/_ExcelBinOutput/QuestExcelConfigData` payload.
3. Locate the exact 7.1 path literal, loader, and row deserializer in the pinned executable/metadata sample.
4. Recover prerequisite-related row fields (`acceptCond`, payloads, combination mode, ordering/nesting) from native reads.
5. Require full payload consumption or an equally strong structural validation before semantic naming.
6. Compare representative rows across direct exact-client decode, current published Excel JSON, current `BinOutput/Quest`, and historical consensus.
7. Only after that classify the defect as client-table, schema/decoder, post-processing, or unresolved.

## #9 Quest 351 persistent Return-to-quest-point state

Current status: `UNRESOLVED`. Keep this problem separate from the QuestExcel extraction problem.

### Confirmed/current anchors

The exact 7.1 Global client anchor already known for the fresh-born entrypoint is:

```text
DoSetPlayerBornDataNotify
CmdId               22899
client type         ONKOPMILDMF
typeDefinition      87483
handler owner       LLCGIEDMIIG
handler method      MACAMCMOKOL(ONKOPMILDMF)
handler RVA         0x0C227790
method index        322028
```

Historical restored clients show `LoadingManager.OnDoSetPlayerBornData()` calling `QuestModule.ResetTrackingLocalData([351])`, touching a tracking/navigation state cluster. This remains a high-value navigation clue only; it is not current-7.1 proof.

The exact 351 resource relationship `35101 TEAM_DEAD -> rollback 35100` is a separate gameplay rewind mechanism. Do not use it as an explanation for the always-visible return button unless the current client UI/state path explicitly links them.

### Resume here

1. Trace direct callees from `0x0C227790` with the pinned 7.1 executable.
2. Identify current methods that touch quest tracking/navigation/rewind state or carry main-quest id `351`.
3. Map the current state transition against the historical `ResetTrackingLocalData([351])` structural clue.
4. Trace `UI_STC_MAIN_RETURN_TO_QUEST` presentation/state reads back to the enabling flag/state.
5. Build a minimal truth table for fresh born, `35104 -> 35100 -> 35101`, actual rewind, and normal tracking.
6. Only then recommend an AstaPS lifecycle/protocol correction. Do not suppress the UI heuristically.

## Server-side cross-check still open

AstaPS contains an `ExecRollbackQuest` implementation, but this checkpoint has not yet completed the full audit of how `QUEST_CONTENT_TEAM_DEAD` is emitted/consumed in the current server path. Do not conclude that the server-side rollback path is complete or broken from the resource evidence alone.

## Repository hygiene

- Keep exact-sample evidence and durable conclusions in Genshin-Reverse.
- Keep investigation-only probes/workflows temporary and retire them after their outputs become durable artifacts or reusable tools.
- Do not use CI as the normal interactive reverse loop. Cheap focused probes are acceptable during research; full required validation is mandatory before asking the user to test, upstream submission, or canonical artifact publication.
