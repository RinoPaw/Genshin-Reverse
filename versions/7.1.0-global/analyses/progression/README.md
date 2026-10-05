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

- `ExcelBinOutput/AvatarCurveExcelConfigData.json`
- `ExcelBinOutput/AvatarPromoteExcelConfigData.json`

Expected next source files:

- `ExcelBinOutput/WeaponCurveExcelConfigData.json`
- `ExcelBinOutput/WeaponPromoteExcelConfigData.json`
- `ExcelBinOutput/ProudSkillExcelConfigData.json`
- Reliquary/artifact level, main-property and affix tables
- Reward/drop tables used by ley lines, bosses and domains
