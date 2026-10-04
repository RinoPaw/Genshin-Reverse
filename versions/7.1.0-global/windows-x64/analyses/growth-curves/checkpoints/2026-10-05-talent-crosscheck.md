# Talent progression cross-project checkpoint

Date: 2026-10-05

## Finding

The pinned AstaPS-Resource commit has an empty `ProudSkillExcelConfigData.json`, but 7.1-era LunaGC server code still models talent levels through `ProudSkillData` and consumes `proudSkillGroupId`/level-derived IDs.

Cross-project source:

- `capyb2222/LunaGC_7.1.0@811b224db150982be37c0619e1506d980443cb9b`
- `src/main/java/emu/grasscutter/data/excels/ProudSkillData.java`
- `src/main/java/emu/grasscutter/game/avatar/Avatar.java`
- `src/main/java/emu/grasscutter/game/ability/Ability.java`
- `src/main/java/emu/grasscutter/game/ability/AbilityManager.java`

Observed server assumptions:

- `ProudSkillData` is still declared as resource type `ProudSkillExcelConfigData.json`.
- The model contains at least `proudSkillId`, `proudSkillGroupId`, `level`, `coinCost`, and `breakLevel`.
- Avatar upgrade logic derives a proud-skill ID as `proudSkillGroupId * 100 + newLevel` and looks it up in `GameData.getProudSkillDataMap()`.
- Ability evaluation also resolves the same group/level map and reads the proud-skill parameter list.

## Interpretation

This does **not** prove that exact Global 7.1 client resources still serialize a populated `ProudSkillExcelConfigData.json`. It proves that a contemporary private-server implementation still expects the legacy logical model and therefore gives us a concrete schema/consumer target for recovery.

The empty table in AstaPS-Resource should be treated as an extraction/migration gap until the exact 7.1 Global source is recovered.

## Next recovery step

1. recover the current 7.1 talent level/cost serialized source or equivalent;
2. verify whether the old `group * 100 + level` keying remains valid against target data;
3. bind `coinCost`, material cost lists, parameter lists and break-level requirements to an exact 7.1 source;
4. only then promote talent progression costs into the main growth baseline.
