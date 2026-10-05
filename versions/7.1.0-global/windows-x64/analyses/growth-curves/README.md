# Growth curves / progression baseline

Status: **IN PROGRESS**. This analysis inventories progression data relevant to private-server pacing and separates exact current-resource observations from restored/historical or external evidence.

## Target

- Game: Genshin Impact 7.1.0 Global
- Platform: Windows x64
- Primary integration resource: `RinoPaw/AstaPS-Resource@b0f3a2791607cab2a4c24cb9ef249dd2d94d7ffd`
- Native/reverse target: the pinned 7.1 Global client under this version directory
- Consumer: `RinoPaw/AstaPS`
- Original-data archive: `../../../gameplay/original/`

Do not treat a value as exact 7.1 native provenance merely because it is present in AstaPS-Resource. Some resource fields were restored after import. The original-data archive preserves that distinction explicitly.

## Scope

The baseline covers:

1. character level EXP and stat growth;
2. character ascension gates/costs;
3. Lv.90 -> 95 -> 100 limit raising;
4. weapon level EXP/stat growth/ascension;
5. artifact enhancement curves, main-stat pools and 5-star append-stat roll tables;
6. talents/skills/constellations and their data-source availability;
7. friendship EXP;
8. Adventure Rank;
9. World Level;
10. monster level/stat growth;
11. time-gated/resource-gated progression when a source can be bound separately.

`tools/extract_growth_curves.py` copies source tables and emits compact CSV projections from a checkout of the pinned AstaPS-Resource commit. The durable original-data identity is recorded under `versions/7.1.0-global/gameplay/original/source-index.json`.

## Current exact-resource observations

### Character levels

`AvatarLevelExcelConfigData.json` contains rows through level 90. The exact archived level-90 row still contains `exp: 613950`; therefore it is incorrect to describe the raw row itself as zero EXP. Ordinary character leveling still terminates at the normal level-90 cap in the live system, so this field must not be interpreted as proof of an enabled ordinary 90 -> 91 EXP step.

`AvatarCurveExcelConfigData.json` continues stat-growth multipliers through level 100. Representative values for the standard S4/S5 HP/ATK curves are approximately:

| level | multiplier |
|---:|---:|
| 1 | 1.00 |
| 20 | 2.50 |
| 40 | 4.00 |
| 60 | 5.50 |
| 80 | 7.00 |
| 90 | 7.75 |
| 95 | 8.15 |
| 100 | 8.55 |

This establishes a structural split between the ordinary 1..90 leveling table and the stat curve extending to 100. Do not model 90 -> 100 by extrapolating the ordinary EXP curve.

External continuity evidence for the live 6.0+ rule says post-90 limit raising uses Masterless Stella Fortuna: 90 -> 95 costs one and 95 -> 100 costs two, without ordinary Character EXP Material or Mora. This still needs target-native/server-authoritative binding before it can be promoted from external continuity evidence.

### Adventure Rank

`PlayerLevelExcelConfigData.json` caps Adventure Rank at 60. Current high-level `exp` rows are:

- AR55: 232350
- AR56: 258950
- AR57: 285750
- AR58: 312825
- AR59: 340125
- AR60: no `exp` field

The same table binds World Level unlocks at AR20/25/30/35/40/45/50/55/58 for WL1..9.

### World Level

The pinned `WorldLevelExcelConfigData.json` raw table contains WL1..9, not a WL0 row. Its exact `monsterLevel` values are:

| WL | monsterLevel |
|---:|---:|
| 1 | 26 |
| 2 | 34 |
| 3 | 47 |
| 4 | 59 |
| 5 | 69 |
| 6 | 80 |
| 7 | 88 |
| 8 | 90 |
| 9 | 100 |

WL9 also carries an unresolved obfuscated field `IDLGNALCKNN: -10`. Do not assign semantics to that field without a consumer/native binding.

Earlier local projections that listed WL0 or alternate base monster levels were derived/incorrectly conflated and are superseded by the archived raw table for source-level claims.

### Friendship

`AvatarFettersLevelExcelConfigData.json` is intact and archived. `need_exp` by friendship level is:

`1:1000, 2:1550, 3:2050, 4:2600, 5:3175, 6:3750, 7:4350, 8:4975, 9:5650, 10:6325`.

### Artifact main-stat pools

The current AstaPS-Resource table contains the familiar ordinary main-stat depots:

- sands `1000`: HP% 1334, ATK% 1333, DEF% 1333, ER 500, EM 500 (total 5000);
- circlet `3000`: HP%/ATK%/DEF% 1100 each, CR/CD/Healing 500 each, EM 200 (total 5000);
- goblet `5000`: HP% 770, ATK% 770, DEF% 760, EM 100, each of seven elemental damage types plus Physical DMG 200 (total 4000);
- plume `2000`: flat ATK 999;
- flower `4000`: flat HP 999.

Normalized candidate distributions are therefore sands 26.68/26.66/26.66/10/10%, circlet 22/22/22/10/10/10/4%, and goblet 19.25/19.25/19/2.5% plus 5% for each damage-bonus row.

**Provenance warning:** these `weight` fields were restored after the 7.1 resource import. They are historical-continuity/integration values, not yet exact current Global 7.1 native-field proof.

### Artifact 5-star append-stat rolls

The current restored `ReliquaryAffixExcelConfigData.json`, depot `501`, has four concrete roll rows per ordinary append stat. Candidate class weights in the integration table are obtained by summing equal per-roll weights:

| stat class | per-roll weight | class weight | relative |
|---|---:|---:|---:|
| flat HP / ATK / DEF | 150 | 600 | 6 |
| HP% / ATK% / DEF% / ER / EM | 100 | 400 | 4 |
| Crit Rate / Crit DMG | 75 | 300 | 3 |

All four ordinary 5-star roll tiers carry `upgradeWeight = 1000` in the restored table. Concrete values are:

- flat HP: 209.13 / 239.00 / 268.88 / 298.75
- flat ATK: 13.62 / 15.56 / 17.51 / 19.45
- flat DEF: 16.20 / 18.52 / 20.83 / 23.15
- HP% and ATK%: 4.08 / 4.66 / 5.25 / 5.83%
- DEF%: 5.10 / 5.83 / 6.56 / 7.29%
- Crit Rate: 2.72 / 3.11 / 3.50 / 3.89%
- Crit DMG: 5.44 / 6.22 / 6.99 / 7.77%
- Energy Recharge: 4.53 / 5.18 / 5.83 / 6.48%
- Elemental Mastery: 16.32 / 18.65 / 20.98 / 23.31

The same provenance warning applies to the weight fields. Concrete roll-value rows remain useful exact current-resource integration data.

### Talents and skills

`AvatarSkillExcelConfigData.json`, `AvatarSkillDepotExcelConfigData.json` and `AvatarTalentExcelConfigData.json` are populated. Skill depots still reference `proudSkillGroupId` for passive/talent groups.

`ProudSkillExcelConfigData.json` exists at the pinned resource commit but is empty. The old ProudSkill table therefore cannot be used as the 7.1 authority for talent level multipliers/costs. Current storage/authority remains to be recovered.

### Empty/moved legacy tables

At the pinned resource commit:

- `ProudSkillExcelConfigData.json` is empty;
- `WeaponPromoteExcelConfigData.json` is empty;
- `ReliquaryExcelConfigData.json` is empty.

These are migration/extraction gaps, not evidence that the gameplay systems disappeared. Do not silently synthesize current data from old schema assumptions.

## Evidence classes

- **raw-snapshot**: exact Git-blob-identical copy preserved under `gameplay/original/raw/`;
- **observed-resource**: directly present at the pinned AstaPS-Resource commit;
- **restored-historical**: present in the integration resource but Git history proves restoration from older evidence;
- **external-continuity**: live-game/official/community evidence useful as a cross-check, not target-native proof;
- **unresolved-native**: needs exact 7.1 Global schema/consumer/server binding.

## Open recovery work

1. copy the remaining clean source tables into the original-data archive where practical;
2. recover the current talent-level/cost authority replacing the empty ProudSkill table;
3. recover weapon promotion authority replacing the empty WeaponPromote table;
4. bind the 90 -> 100 limit-raise rule to target-native/protocol/server evidence;
5. normalize artifact enhancement EXP/main-stat progression variants in ReliquaryLevel;
6. recover the initial 3-vs-4 append-stat count rule and upgrade selection consumer rather than importing the familiar 20% rule as provenance;
7. bind Resin/reward/time gates separately; those are pacing inputs but should not be conflated with stat-growth curves.
