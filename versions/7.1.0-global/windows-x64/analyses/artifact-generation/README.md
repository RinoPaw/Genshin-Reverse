# Artifact generation / weight provenance

Status: **UNRESOLVED** for exact Global 7.1 generation probabilities.

This analysis tracks which artifact-generation facts are actually present in current client/resource data, which values are historical continuity evidence, and which dimensions appear server-authoritative.

The integration consumer is `RinoPaw/AstaPS`. Do not promote a familiar probability table merely because it reproduces live-game statistics.

## Exact target

- Game: Genshin Impact 7.1.0 Global
- Platform: Windows x64
- EXE SHA-256: `08a3086d5f3fe695f01dab61efa42e442006b18e5e475b2520df356f6a073b7d`
- metadata SHA-256: `05ae04d7a91b91cc880217a56b0b01f3e67f845b06e894216654ec5d160e0da0`
- tracking issue: [#5](https://github.com/RinoPaw/Genshin-Reverse/issues/5)

## 2026-10-15: complete 7.1 source-row depot topology

The [machine-readable Reliquary topology](7.1-reliquary-depot-topology.json)
now joins **4,352** `ReliquaryExcel` item rows to **66** main-prop rows
and **350** affix-roll rows. **Every** item has a matching main-prop and
append-prop depot. The source files are bound to three exact Git blob hashes
from `RinoPaw/AstaPS-Resource@b0f3a279`; regenerated snapshots fail closed
if any source blob changes.

The collector deliberately **does not serialize** the integrated resource's
`weight` or `upgradeWeight` values: their current 7.1 provenance or
selection semantics are unproven, and the fields were restored historically.
Those historical numbers remain isolated in the candidate CSVs.

Of the **1,614** configured 5-star item rows, the append-prop depots are:

| Append depot | Item rows | Slot relation |
| --- | ---: | --- |
| `501` | 1,025 | all five slots; contains multiple configured `appendPropNum` variants |
| `961` | 102 | `EQUIP_NECKLACE` (plume) |
| `962` | 102 | `EQUIP_BRACER` (flower) |
| `963` | 127 | `EQUIP_SHOES` (sands) |
| `964` | 128 | `EQUIP_RING` (goblet) |
| `965` | 130 | `EQUIP_DRESS` (circlet) |

Thus **589** of the 5-star *configuration rows* use special append-prop
depots, and some also reference nonstandard main-prop depots such as
`1095–1099`, `3093–3099` and `5088–5099`. They **must not** be
given the ordinary `501` roll model by an artifact-generation algorithm.
The topology alone does not prove how the special items are acquired, whether
they can occur in ordinary drops, or whether the server chooses their affixes.

The two separate 5-star IDs `20513`/`20514` carry
`appendPropNum = 3`/`4` with matching main/append depots and enhancement
checkpoints. The existence of both records **does not establish** the 3-vs-4
initial-roll odds. Similarly, source row frequency is not a probability:
**1,025 / 1,614** is a count of configured item rows, not a drop rate.

### Independent-dump cross-check (structural, not independent extraction proof)

The 7.1 CN dump
`DimbreathBot/AnimeGameData@792978e5503ecfba73dcb3562ed44a0d35a2abe2`
(exact Git blob IDs checked by the collector in optional CN comparison mode)
has the same **4,352** Reliquary item IDs and matching rarity, slot, set,
main/append depot, initial-count and upgrade-checkpoint fields; its **66**
main-prop IDs/depots/stat types and **350** affix IDs/depots/stat types
also match the pinned integration source exactly. The affix JSON calls
the group key `groupId` versus `group_id` in AstaPS-Resource.

The comparison deliberately **does not** claim exact equality of restored
numeric weight fields (which are absent from the CN export), nor does it
establish independent extraction lineage. These mirrors support a 7.1
**structural** topology, not an authoritative RNG consumer.

To regenerate from the original unmodified pinned ExcelBinOutput:

```sh
python scripts/collect-7.1-reliquary-topology.py --resources /path/to/AstaPS-Resource/ExcelBinOutput --check
python -m unittest tests.test_reliquary_topology -v

# Optional: separately check a checkout of the pinned DimbreathBot/AnimeGameData CN 7.1 dump
python scripts/collect-7.1-reliquary-topology.py --resources /path/to/AstaPS-Resource/ExcelBinOutput --cn-resources /path/to/AnimeGameData/ExcelBinOutput --check
```

This closes the source-level depot foreign-key and special-pool *enumeration*
step, **not** any of the six probability/authority gates listed below.

## Current conclusions

### CONFIRMED

No current Global 7.1 numeric main-stat/sub-stat probability table has passed the promotion gate yet.

### HIGH-CONFIDENCE structural facts

Current 7.1 resource topology still uses the familiar reliquary depots:

- `ReliquaryExcelConfigData` selects a `mainPropDepotId` and `appendPropDepotId` per item.
- For ordinary 5-star artifacts, current public 7.1 data maps the five slots to main-prop depots `4000`, `2000`, `1000`, `5000`, and `3000` and uses append-prop depot `501`.
- `ReliquaryMainPropExcelConfigData` still enumerates the candidate stat rows inside those depots.
- `ReliquaryAffixExcelConfigData` still enumerates concrete append-prop roll values by depot/stat/group.

Cross-check source:

- `DimbreathBot/AnimeGameData@792978e5503ecfba73dcb3562ed44a0d35a2abe2`
  - `ExcelBinOutput/ReliquaryExcelConfigData.json`
  - `ExcelBinOutput/ReliquaryMainPropExcelConfigData.json`
  - `ExcelBinOutput/ReliquaryAffixExcelConfigData.json`

This source is CN 7.1 rather than the pinned Global sample and its published schema is affected by modern field deobfuscation limits. It is structural cross-check evidence, not the final Global 7.1 probability source.

### Historical continuity: main-prop weights

`RinoPaw/AstaPS-Resource` currently contains restored `weight` fields in `ExcelBinOutput/ReliquaryMainPropExcelConfigData.json`. The restoration was introduced by:

- commit `3278aeebca3c3c11139db3ab8fcc4b04a9c883d0`
- message: `fix: restore reliquary main prop weights`

Important provenance boundary: those values were **added after the 7.1 resource import**. The immediately preceding imported file did not contain them. Therefore the present AstaPS-Resource file is not evidence that the current 7.1 extractor recovered the fields natively.

The restored ordinary pools are:

| Main-prop depot | Role | Non-zero restored weights | Total |
|---|---|---|---:|
| `1000` | sands | HP% `1334`, ATK% `1333`, DEF% `1333`, ER `500`, EM `500` | 5000 |
| `3000` | circlet | HP% `1100`, ATK% `1100`, DEF% `1100`, CR `500`, CD `500`, Healing `500`, EM `200` | 5000 |
| `5000` | goblet | HP% `770`, ATK% `770`, DEF% `760`, EM `100`, seven elemental + physical DMG rows `200` each | 4000 |
| `2000` | plume | ATK `999` | 999 |
| `4000` | flower | HP `999` | 999 |

These normalize to the familiar live-game distributions, but that agreement alone is not a current-source proof.

There is, however, strong historical client continuity. The same sands values already appear in archived closed-beta client data, including:

- `nairieberry/GenshinBetasData@1a195708b99169d4be66a760a91ef0162101ff3c`
  - `[0.9.3] Closed Beta 3/ExcelBinOutput/ReliquaryMainPropExcelConfigData.json`
  - `[0.9.9] Closed Beta 3/ExcelBinOutput/ReliquaryMainPropExcelConfigData.json`

For example, the 0.9.3 table exposes `weightRawNum = 1334` for HP% in depot `1000`, with the same `1333/1333/500/500` family around it. Multiple historical resource mirrors independently carry the same values.

Interpretation: the restored table is a plausible continuation of a real historical client schema, not a newly invented 7.1 community distribution. It remains **CANDIDATE/HISTORICAL** until the exact 7.1 serialized field and consumer are recovered.

### Historical continuity: append-prop weights

`RinoPaw/AstaPS-Resource` currently contains restored `weight` and `upgradeWeight` fields in `ExcelBinOutput/ReliquaryAffixExcelConfigData.json`. They were introduced by:

- commit `55198e8f03903d37b8afce51efef1e2ed1fc540c`
- message: `fix: restore reliquary affix weights [skip ci]`

The maintained restoration used historical 2.4 client tables where direct matches existed. A small set of later/special rows (`947001..947010` and `996008..996010`) required structural reconstruction rather than a direct 7.1 source. Consequently the current AstaPS-Resource table is useful integration data but must not be cited as exact 7.1 native provenance.

Representative restored rows show a per-roll-entry weighting layer, for example:

- flat HP roll entries: `weight = 150`, `upgradeWeight = 1000`;
- HP% roll entries: `weight = 100`, `upgradeWeight = 1000`;
- flat ATK roll entries: `weight = 150`, `upgradeWeight = 1000`;
- ATK% roll entries: `weight = 100`, `upgradeWeight = 1000`.

This is consistent with a class-weight model after accounting for the number of roll-value entries, but exact current semantics still need a 7.1 consumer/xref.

## REJECTED shortcuts

1. **Present AstaPS-Resource restored weights = exact 7.1 extraction.** Rejected. Git history proves the fields were restored after import.
2. **Current AnimeGameData JSON omits `weight`, therefore 7.1 client serialization has no weight.** Rejected. Modern extraction has known field-order/deobfuscation loss; absence from the published JSON is insufficient.
3. **Any historical `weight` field with a familiar name is automatically the desired class probability.** Rejected. Different historical dumps/transforms have exposed uniform placeholder-looking values such as `999`, and an integer array is meaningless until its consumer/selection layer is identified.
4. **Community `ArtifactRollOdds.json` values are native 7.1 evidence.** Rejected as provenance. They remain a useful runtime/cross-project comparison target.

## Server-authoritative boundary

Current 7.1 community protocol recovery gives a useful direction: artifact instances carry selected `main_prop_id` and `append_prop_id_list`; an upgrade request supplies target/materials, while the upgrade response returns old/current append-prop lists. This shape is consistent with the server selecting upgrade RNG results and the client rendering the resulting IDs.

Cross-check:

- `capyb2222/LunaGC_7.1.0@811b224db150982be37c0619e1506d980443cb9b`
  - `src/main/proto/Reliquary.proto`
  - `src/main/proto/ReliquaryUpgradeReq.proto`
  - `src/main/proto/ReliquaryUpgradeRsp.proto`

This supports the server-authoritative hypothesis for generation/upgrade rolls, but it is not yet an independently bound Global 7.1 native/protocol proof in this repository.

## Pinned 7.1 reliquary string-literal evidence

The verified IL2CPP metadata literal identities from the former
`research/reliquary-main-prop` branch are preserved in
[`reliquary-string-literal-anchors.json`](reliquary-string-literal-anchors.json).
The capture identified 86,109 recovered literals and exact configuration-table
path indices. `genshinre/stringxref.py` provides generic PE/raw string xref
helpers; `scripts/research_trace_7_1_literal_usage.py` is bound to the pinned
7.1 client layout. These results confirm **resource path identities only**:
no `weight` field identity, probability distribution or weighted-selection
consumer has been established by them. The issue remains open.

## Current research split

Close these independently:

1. **Main-prop schema:** recover the exact Global 7.1 serialized `ReliquaryMainProp` row schema and determine whether a weight-equivalent field still exists.
2. **Main-prop consumer:** xref the current loader/consumer and prove how a candidate field participates in weighted selection, if it does.
3. **Affix schema:** recover exact current `weight`/`upgradeWeight` equivalents, if present.
4. **Affix consumer:** distinguish initial sub-stat class selection from roll-tier/value selection and upgrade-time selection.
5. **Initial 3/4 sub-stat count:** locate an exact current rule/source. The community `0.2` four-substat-start chance is not provenance-backed yet.
6. **Authority boundary:** independently bind current Global protocol/native handling well enough to classify each generation dimension as client-visible, client-derived, or server-only.

The schema work should follow the same invariant as issue #8: identify the exact table path/loader/deserializer, recover a candidate row layout, and accept it only when decoding satisfies the complete binary layout rather than merely yielding plausible fields.

## Promotion gate

A current probability can be promoted to `CONFIRMED` only when all of the following are present:

1. exact Global 7.1 source/sample provenance;
2. recovered field/table/native location;
3. consumer or selection logic proving interpretation;
4. a machine-readable artifact in this analysis directory;
5. an independent sanity/cross-check where practical.

Historical equality is valuable continuity evidence, but never substitutes for steps 1–3.
