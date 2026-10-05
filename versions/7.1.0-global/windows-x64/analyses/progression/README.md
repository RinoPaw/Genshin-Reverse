# Genshin Impact 7.1 progression baseline

Status: `PARTIAL`

Target:

- Game version: Genshin Impact 7.1.0 Global
- Platform: Windows x64
- Archive date: 2026-10-05
- Scope: original progression data only

This archive records the verified and pending parts of the 7.1 original progression system. It does not contain private-server redesigns, resin-removal proposals, RPG rebalance proposals, or AstaPS implementation changes.

## Evidence levels

- `CONFIRMED`: directly verified from the 7.1 data source used by this investigation or an official HoYoverse source.
- `HIGH_CONFIDENCE`: verified from matching server-side behavior or prior investigation, but not yet fully rechecked against the 7.1 source table.
- `UNRESOLVED`: source/table is known or expected, but the data has not yet been fully extracted and normalized.

## Source provenance

Primary progression source currently used by this investigation:

- Repository: `RinoPaw/AstaPS-Resource`
- Branch: `main`
- Data family: `ExcelBinOutput`

Confirmed source files so far:

- `ExcelBinOutput/AvatarCurveExcelConfigData.json`
- `ExcelBinOutput/AvatarPromoteExcelConfigData.json`

Expected next source files:

- `ExcelBinOutput/WeaponCurveExcelConfigData.json`
- `ExcelBinOutput/WeaponPromoteExcelConfigData.json`
- `ExcelBinOutput/ProudSkillExcelConfigData.json`
- Reliquary/artifact level, main-property and affix tables
- Reward/drop tables used by ley lines, bosses and domains

No executable-derived claim is made by this document, so executable and `global-metadata.dat` hashes are not used as provenance for the entries below.

## Character progression

### Character growth curves

Status: `CONFIRMED`

`AvatarCurveExcelConfigData.json` stores level-indexed growth multipliers. Confirmed curve identifiers include:

- `GROW_CURVE_HP_S4`
- `GROW_CURVE_ATTACK_S4`
- `GROW_CURVE_HP_S5`
- `GROW_CURVE_ATTACK_S5`

Observed values include:

| Level | S4 HP | S4 ATK | S5 HP | S5 ATK |
| ---: | ---: | ---: | ---: | ---: |
| 1 | 1 | 1 | 1 | 1 |
| 10 | ~1.743 | ~1.743 | ~1.751 | ~1.751 |
| 100 | ~9.174 | ~11.392 | ~9.652 | ~11.629 |

Pending work:

- normalize the full level range;
- verify the remaining growth-curve types, including DEF-related curves;
- map each avatar to its curve types;
- generate per-character base-stat progression tables.

### Character ascension

Status: `CONFIRMED`

`AvatarPromoteExcelConfigData.json` contains at least:

- `avatarPromoteId`
- `promoteLevel`
- `requiredPlayerLevel`
- `unlockMaxLevel`
- `scoinCost`
- `costItems`
- `addProps`

These fields encode ascension-stage level caps, Adventure Rank requirements, Mora costs, material IDs/counts, and ascension stat additions.

Observed example for `avatarPromoteId = 2`:

- initial level cap: 20;
- ascension 1: Adventure Rank 15, 20,000 Mora, new cap 40;
- ascension 2: Adventure Rank 25, 40,000 Mora, new cap 50.

This example only establishes the table structure. It must not be treated as a universal material/stat profile for every character.

Pending work:

- enumerate all `avatarPromoteId` groups;
- map characters to promotion groups;
- normalize 4-star/5-star and exceptional groups;
- compute complete 1→90 ascension material and Mora totals;
- archive the character EXP curve itself.

## Artifact progression

### Five-star enhancement EXP

Status: `HIGH_CONFIDENCE`

Current recorded result:

- 5-star artifact +0→+20 cumulative enhancement EXP: **270,475 EXP**.

This value still needs a fresh 7.1 table-level provenance pass before promotion to `CONFIRMED` in this archive.

### Artifact enhancement Mora

Status: `HIGH_CONFIDENCE`

Current investigation result indicates enhancement Mora tracks consumed enhancement EXP at approximately 1 Mora per 1 EXP. Exact overflow, bonus-multiplier, and inherited-EXP behavior still needs direct 7.1 verification.

### Enhancement bonus multipliers

Status: `HIGH_CONFIDENCE`

Current recorded probabilities:

- ×1: ~90%
- ×2: ~9%
- ×5: ~1%

The exact 7.1 source table and field still need to be archived.

### Artifact substats

Status: `HIGH_CONFIDENCE`

Current mechanism findings:

- substats are selected by weight;
- selection is without replacement;
- duplicate substat types are not allowed;
- the main-stat type excludes the conflicting same-stat substat group.

Pending work:

- complete substat weights;
- four roll tiers for each substat;
- initial 3/4-substat probabilities for 5-star artifacts and lower rarities;
- +4 add/upgrade rules;
- main-stat candidate sets by slot;
- main-stat level curves;
- set/drop-source mappings.

## Weapon progression

Status: `UNRESOLVED`

Target tables include:

- `WeaponCurveExcelConfigData.json`
- `WeaponPromoteExcelConfigData.json`

Pending archive items:

- 1-star through 5-star weapon growth curves;
- weapon EXP 1→90;
- weapon enhancement-material EXP values;
- ascension materials and Mora per stage;
- total costs by rarity;
- refinement-related resource rules where applicable.

## Talent progression

Status: `UNRESOLVED`

Primary expected table:

- `ProudSkillExcelConfigData.json`

Pending archive items:

- normal attack / elemental skill / elemental burst costs by level;
- Mora per level;
- talent-book counts;
- common-enemy material counts;
- weekly-boss material counts;
- Crown of Insight requirements;
- total 1/1/1→10/10/10 cost;
- character- or skill-specific exceptions.

## Character EXP and Mora

Status: `UNRESOLVED`

Pending archive items:

- character EXP required for every level 1→90;
- cumulative EXP per ascension interval;
- EXP values for character EXP items;
- Mora conversion/cost rules when consuming EXP items;
- total 1→90 EXP and Mora;
- overflow behavior.

## Drop and resource economy

Status: `UNRESOLVED`

Pending archive items:

- Mora and character-EXP ley lines;
- normal-boss ascension drops;
- weekly-boss talent drops and auxiliary drops;
- weapon-material domains;
- talent-material domains;
- artifact domains;
- normal and elite enemy materials;
- World Level / domain level drop brackets;
- minimum, maximum and expected quantities where the source data allows calculation.

## Current coverage estimate

This estimate describes normalized and reusable archive coverage, not whether a raw source file exists somewhere in the resource repository.

- character progression: ~40%
- artifacts: ~25%
- weapons: ~5%
- talents: ~5%
- drop economy: ~5%
- final cross-checks and aggregate calculations: 0%
- overall: ~18%

## Next extraction order

1. Character EXP 1→90 and complete ascension totals.
2. Weapon EXP/ascension totals 1→90.
3. Talent 1→10 and 10/10/10 totals.
4. Complete 5-star artifact main-stat/substat/enhancement tables.
5. Boss, ley-line and domain drop quantities.
6. Aggregate per-character and per-weapon original progression cost tables.

## Archive rule

Every promoted value should record:

- source file;
- relevant field(s);
- game version;
- whether it comes directly from the 7.1 data source;
- whether the value is raw or calculated;
- calculation method when derived;
- known rarity/character/weapon exceptions.

Unverified values must remain explicitly marked and must not be silently mixed into the confirmed 7.1 baseline.
