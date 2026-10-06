# QuestExcel extraction / prerequisite corruption

Status: **HIGH_CONFIDENCE downstream root cause; exact-client row decode still UNRESOLVED**

Issues: #8, with #19 as the ordinary-row schema dependency.

Target: Genshin Impact 7.1.0 Global / Windows x64.

Pinned exact-client sample:

- EXE SHA256: `08a3086d5f3fe695f01dab61efa42e442006b18e5e475b2520df356f6a073b7d`
- global-metadata SHA256: `05ae04d7a91b91cc880217a56b0b01f3e67f845b06e894216654ec5d160e0da0`

## Exact native asset extraction

The exact 7.1 Global asset chain is confirmed:

```text
Data/_ExcelBinOutput/QuestExcelConfigData
  -> MiHoYo 40-bit name hash 0x3B87AE8396
  -> design asset index 31049741.blk
  -> Raw MiHoYoBinData export 0000006f.dat
  -> sub_asset_id 178
  -> block_id 25539185
  -> group_id 0
  -> AssetBundles/blocks/00/25539185.blk
  -> Raw MiHoYoBinData export 3b87ae83.dat
  -> QuestExcel serialized payload
```

Recovered invariants:

- Raw object size: 2,824,192 bytes
- payload after MiHoYoBinData length prefix: 2,824,188 bytes
- leading unsigned varint: 7473

This solves location/extraction of the exact asset. It does not yet solve row framing or the ordinary Quest row schema.

## Focused public-source comparison

Focused run `37411379300`, head
`324f916b0d6caabb1b23e87d632bf01cd0278e81`, completed successfully.

Artifact:

- name: `quest-row-prereq-schema`
- artifact id: `11389790544`
- artifact SHA256: `cb220b0a6def6c20f13daa37e7cf4c5ef61db40d02d59aff283c8181006231a3`

The comparison downloaded:

1. `DimbreathBot/AnimeGameData@792978e5503ecfba73dcb3562ed44a0d35a2abe2`
   - commit title: `CNRELWin7.1.0_R48379043_S48511369_D48533839`
   - QuestExcel JSON size in the run: 7,903,186 bytes
   - top-level rows: 17,814
2. current `RinoPaw/AstaPS-Resource/main`
   - QuestExcel JSON size in the run: 51,009,089 bytes
   - top-level rows: 33,217

## AstaPS-Resource QuestExcel is a mixed synthetic resource

The current AstaPS file must not be treated as an exact 7.1 native ExcelBin dump.

Upstream commit:

`MeChen618/AstaPS-Resource@7465e29b2d58058ab9973187c112abf2717ada03`

is titled:

`Update QuestExcelConfigData from BinOutput/Quest (#9)`

Upstream PR #9 explicitly states:

- the previous QuestExcel file was missing **7,956** subquests that were present in `BinOutput/Quest`;
- those missing rows included the 7.x quest population;
- new rows were appended until the table reached **33,217** rows;
- because BinOutput carried no `acceptCond` / `beginExec`, the PR synthesized:
  - first step: `QUEST_COND_STATE_EQUAL [0,3]`
  - later step: `QUEST_COND_STATE_EQUAL [previous step,3]`
- existing rows kept their order and formatting;
- only selected finish/fail condition/exec fields on existing rows were refreshed from BinOutput.

Therefore the current file combines:

1. a legacy pre-7.x QuestExcel baseline;
2. later BinOutput-derived rows;
3. heuristic prerequisite synthesis for the appended rows.

This is direct repository provenance, not an inference from gameplay.

### Consequence for quest 351

Current AstaPS QuestExcel still contains:

```text
35104 <- [0,3]
35100 <- [35104,3]
35107 <- [35100,3]
35101 <- [35107,3]
35106 <- [35101,3]
35105 <- [35106,3]
35103 <- [35105,3]
35102 <- [35103,3]
```

Those rows are at indices 9019..9026 in the current 33,217-row file.

PR #9 added 7,956 rows by appending them, so the pre-PR table had 25,261 rows. The 351 rows therefore predate that augmentation. PR #9 also says existing rows did not have their `acceptCond` rewritten. The current 351 prerequisite chain is therefore legacy-baseline data, not a current 7.1 native decode and not newly created by PR #9.

Current same-version `BinOutput/Quest/351.json` in both Dimbreath and AstaPS has no `acceptCond` on `35100..35107`.

This classifies the AstaPS 351 prerequisite drift as **legacy resource contamination/materialization drift** with HIGH_CONFIDENCE.

## Published 7.1 Excel field names are also misaligned

The same-version Dimbreath QuestExcel dump cannot be trusted by public field name alone.

Representative exact comparison:

- Dimbreath `35104.acceptCondComb` is a guide-shaped object:
  `{"guideScene":3,"param":["1005",...],"type":"QUEST_GUIDE_NPC"}`
- the corresponding AstaPS row places the same structure under `guide`.
- Dimbreath `35100.failParent = 573649119`;
- AstaPS `35100.descTextMapHash = 573649119`.
- Dimbreath `35104.failCondComb = "QUEST_HIDDEN"`;
- AstaPS `35104.showType = "QUEST_HIDDEN"`.

This is incompatible with exact native type constraints already recovered from the named
`RandomQuestExcelConfig` control: accept/finish/fail combiners share native type
`PCBNKHFKLHI`, so a guide-shaped value cannot be a valid `acceptCondComb`.

Classification: published 7.1 Excel JSON has **schema/field-name misalignment**.

This does not prove what the exact native ordinary Quest row stores. It proves that the
public JSON field labels are not a safe schema oracle.

## Ordinary Quest row direction

Do not continue using `RandomQuestExcelConfig` as the normal/story row.

Research from #19 provides the current high-value exact-sample candidate:

- typeDefinition: `17589`
- type: `LAIMPNDEFCL`
- ordinary binary deserializer candidate/confirmed binary-read method:
  `GMENPOPMKAA(FNIAHJGHFAK) @ 0x9C15DF0`
- unified runtime facade:
  `BEAEOMIOFDE`
- runtime consumer:
  `MoleMole.QuestProxy`

Named `QuestProxy` getter machine code confirms:

- `LAIMPNDEFCL +0x70 = mainId`
- `LAIMPNDEFCL +0x74 = quest config id / subId`
- `LAIMPNDEFCL +0xA8 = order`

The remaining #8 proof step is to bind this ordinary-row deserializer to
`Data/_ExcelBinOutput/QuestExcelConfigData`, recover the prerequisite fields, and decode
the exact 2,824,188-byte payload with full consumption or an equally strong invariant.

## Classification

Current layer-by-layer classification:

| layer | classification |
| --- | --- |
| exact 7.1 QuestExcel asset location/extraction | CONFIRMED |
| AstaPS current QuestExcel provenance | HIGH_CONFIDENCE synthetic/mixed legacy resource |
| AstaPS quest 351 prerequisite graph | HIGH_CONFIDENCE legacy contamination |
| same-version Dimbreath QuestExcel public field labels | HIGH_CONFIDENCE schema/field-name misalignment |
| exact native ordinary Quest prerequisite representation | UNRESOLVED |
| exact source-authority relation between QuestExcel and BinOutput/Quest | UNRESOLVED |

Per issue #8's promotion gate, the overall native root-cause classification is **not
CONFIRMED** until the exact client table is directly decoded with a validated ordinary-row
schema.

## Next steps

1. Reuse #19's `LAIMPNDEFCL` evidence; do not restart literal-name or direct
   `QuestCond[]` searches.
2. Bind `LAIMPNDEFCL.GMENPOPMKAA` to the exact QuestExcel asset loader/table
   registration path.
3. Recover the native field slots for condition arrays and combiners from read sites.
4. Establish table and row framing against the recovered 2,824,188-byte payload.
5. Require complete payload consumption or an equivalently strong structural invariant.
6. Decode representative rows including 35104, 35100, 35102, 35103, 37504, 37603 and
   38805.
7. Compare direct decode against same-version BinOutput and both public Excel layers.
8. Only then promote issue #8 to CONFIRMED and decide the correct AstaPS resource repair.
