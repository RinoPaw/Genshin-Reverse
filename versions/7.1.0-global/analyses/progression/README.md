# Genshin Impact 7.1 progression baseline

Status: `PARTIAL`

Target:

- Game version: Genshin Impact 7.1.0 Global
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

- `ExcelBinOutput/AvatarExcelConfigData.json`
- `ExcelBinOutput/AvatarCurveExcelConfigData.json`
- `ExcelBinOutput/AvatarLevelExcelConfigData.json`
- `ExcelBinOutput/AvatarPromoteExcelConfigData.json`

Expected next source files:

- `ExcelBinOutput/WeaponCurveExcelConfigData.json`
- `ExcelBinOutput/WeaponPromoteExcelConfigData.json`
- `ExcelBinOutput/ProudSkillExcelConfigData.json`
- Reliquary/artifact level, main-property and affix tables
- Reward/drop tables used by ley lines, bosses and domains

## Character progression

### Character identity and growth mapping

Status: `CONFIRMED`

`AvatarExcelConfigData.json` maps each avatar to its base attributes and progression families. Relevant fields include:

- `id`
- `qualityType`
- `hpBase`
- `attackBase`
- `defenseBase`
- `avatarPromoteId`
- `propGrowCurves`
- `skillDepotId`
- `weaponType`

Observed examples confirm that five-star characters normally use the S5 HP/ATK curves and four-star characters normally use the S4 HP/ATK curves. The Traveler is a special case: its entry is `QUALITY_ORANGE` but uses S4 HP/ATK growth curves and its own promote group.

### Character level EXP

Status: `CONFIRMED`

Source: `AvatarLevelExcelConfigData.json`.

The table stores the EXP associated with each character level. Summing levels 1 through `target_level - 1` gives the raw character EXP required to reach the target level.

Cumulative raw EXP:

| Target level | Total EXP from Lv.1 |
| ---: | ---: |
| 20 | 120,175 |
| 40 | 698,500 |
| 50 | 1,277,600 |
| 60 | 2,131,725 |
| 70 | 3,327,650 |
| 80 | 4,939,525 |
| 90 | 8,362,650 |

`AvatarLevelExcelConfigData.json` also contains a Lv.90 row with `exp = 613,950`. This value is not included in the Lv.1→90 total because reaching Lv.90 sums Lv.1 through Lv.89.

### Ascension schedule

Status: `CONFIRMED`

Source: `AvatarPromoteExcelConfigData.json`.

The normal six ascensions use this schedule:

| Ascension | Required AR | New level cap | Mora |
| ---: | ---: | ---: | ---: |
| 1 | 15 | 40 | 20,000 |
| 2 | 25 | 50 | 40,000 |
| 3 | 30 | 60 | 60,000 |
| 4 | 35 | 70 | 80,000 |
| 5 | 40 | 80 | 100,000 |
| 6 | 50 | 90 | 120,000 |

Total ascension Mora: **420,000**.

Across ordinary character promote groups checked so far, the quantity pattern is stable while the material IDs vary by character:

| Material family | Ascension-stage quantities | Total |
| --- | --- | ---: |
| Elemental gem tiers | 1 / 3+6 / 3+6 / 6 by tier | 1 / 9 / 9 / 6 |
| Boss ascension material | 0 / 2 / 4 / 8 / 12 / 20 | 46 |
| Local specialty | 3 / 10 / 20 / 30 / 45 / 60 | 168 |
| Common enemy material | 3+15 / 12+18 / 12+24 by tier | 18 / 30 / 36 |

The checked four-star and five-star promote groups use the same quantity schedule; their material IDs and ascension-stat growth differ.

### Traveler exception

Status: `CONFIRMED`

The Traveler uses `avatarPromoteId = 12` in the inspected avatar entry. Its six ascensions keep the same Mora, level-cap, local-specialty and common-enemy quantity schedule, but the boss-material slot has no item ID. The Traveler therefore does not consume the normal 46-character-boss-material sequence for ascension.

### Ascension stat growth

Status: `CONFIRMED`

`AvatarPromoteExcelConfigData.json` stores `addProps` for every promote group and stage. These values include base HP/ATK/DEF additions and the character's ascension stat, for example CRIT DMG, Healing Bonus, ATK%, HP%, Energy Recharge or Elemental Mastery depending on the character.

These values must remain keyed by `avatarPromoteId`; they cannot be collapsed into one universal four-star or five-star stat template.

### Still unresolved for characters

- Full normalized mapping of every playable 7.1 character ID to `avatarPromoteId`, curve types and ascension stat.
- Full per-character material-ID map.
- Character EXP-item values and the exact Mora charging rule for EXP-item consumption from the 7.1 data source.
- Final total Mora for Lv.1→90 including both leveling and ascension, pending direct confirmation of the leveling-Mora rule.
- Any special cases besides the Traveler that diverge from the ordinary material schedule.
