# Genshin Impact 7.1 progression and resource-economy research

Status: `PARTIAL / ACTIVE`

Target:

- Game version: Genshin Impact 7.1.0 Global
- Version release date: 2026-09-23
- Scope: native progression, native reward economy, real-time gates, and a separate RPG redesign proposal

This directory is the canonical archive for the 7.1 progression/economy investigation. Research conclusions should be written here instead of existing only in chat history.

## Evidence levels

- `A`: current 7.1 ExcelBin or HoYoverse official material.
- `B`: AstaPS/Grasscutter or matching simulator implementation consistent with native behavior.
- `C`: Wiki, KQM, community material, or inference.

An unresolved or partially bound result must not be promoted to `A`.

## Files

- [7.1-native-progression-baseline.md](7.1-native-progression-baseline.md)
  - character EXP curve;
  - character EXP materials;
  - ascension schedule and material quantities;
  - concrete ordinary 5-star example;
  - Traveler exception;
  - current artifact findings;
  - talent mapping progress.

- [7.1-native-drop-economy.md](7.1-native-drop-economy.md)
  - canonical location for Ley Line, Domain, Boss, Weekly Boss and artifact reward yields;
  - currently records extraction targets and the hard progression inputs already available.

- [7.1-time-gates.md](7.1-time-gates.md)
  - Original Resin;
  - Condensed Resin and multi-claim behavior;
  - Weekly Boss, weekday Domain, respawn and reset gates;
  - unresolved current-rule items are explicitly marked.

- [rpg-progression-proposal.md](rpg-progression-proposal.md)
  - separate non-native design;
  - preserve progression costs first;
  - remove real-time gates independently;
  - use one battle -> one native base reward as the first conservative baseline.

## Primary progression provenance

Current native-data source:

- Repository: `RinoPaw/AstaPS-Resource`
- Branch: `main`
- Data family: `ExcelBinOutput`

Tables already used:

- `AvatarExcelConfigData.json`
- `AvatarLevelExcelConfigData.json`
- `AvatarCurveExcelConfigData.json`
- `AvatarPromoteExcelConfigData.json`
- `MaterialExcelConfigData.json`
- `AvatarSkillDepotExcelConfigData.json`
- `AvatarSkillExcelConfigData.json`

Known next tables:

- `ProudSkillExcelConfigData.json`
- `WeaponCurveExcelConfigData.json`
- `WeaponPromoteExcelConfigData.json`
- `ReliquaryLevelExcelConfigData.json`
- `ReliquaryAffixExcelConfigData.json`
- `ReliquaryMainPropExcelConfigData.json`
- reward/drop tables for Ley Lines, Domains and Bosses;
- world-level and Domain reward-tier tables.

## Current headline values

These are documented with their evidence levels in the detailed files:

- Character Lv.1 -> 90 raw EXP: **8,362,650** (`A`).
- Character ascension Mora: **420,000** (`A`).
- Character EXP items: **1,000 / 5,000 / 20,000 EXP** (`A`).
- Ordinary character boss material total: **46** (`A`).
- Local specialty total: **168** (`A`).
- Common enemy material totals: **18 / 30 / 36** by tier (`A`).
- Character leveling raw Mora-equivalent: **1,672,530** from the exact EXP curve using the matching 1 Mora / 5 supplied EXP rule (`B` pending direct 7.1-native binding).
- Combined raw theoretical character 1 -> 90 Mora: **2,092,530** (`A+B`; not yet the final exact UI/book-feed payment total).
- 5-star artifact +0 -> +20 base enhancement EXP: **270,475** (`B`, pending direct Reliquary-table binding).
- Original Resin cap: **200** (`A`, official).
- Newer Condensed Resin baseline recorded by the investigation: **60 Original Resin** to craft and up-to-3x reward claiming (`A`, official rule update already reviewed).

## Research rule

Do not let old Wiki values overwrite current 7.1 ExcelBin.

For current service rules, preserve version order: later HoYoverse rule changes override older documentation only when their applicability to the 7.1 ruleset has been checked.

Private-server behavior belongs here only as `B` evidence or in the RPG proposal. It must not silently redefine the native baseline.
