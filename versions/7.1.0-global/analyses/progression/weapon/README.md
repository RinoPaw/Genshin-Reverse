# Weapon progression

The [source-pinned weapon map](7.1-weapon-promote-map.json) joins **all 287**
`WeaponExcelConfigData` rows with their promotion IDs and the **262**
`WeaponPromoteExcelConfigData` groups (1,814 raw rows). It keeps all configured
stage costs, item slots, nonzero stat additions, caps, rank, weapon type and
source weapon-property curves.

Rebuild from the **unaltered** `ExcelBinOutput` at
`RinoPaw/AstaPS-Resource@b0f3a2791607cab2a4c24cb9ef249dd2d94d7ffd`:

```sh
python scripts/collect-7.1-weapon-growth.py --resources /path/to/AstaPS-Resource/ExcelBinOutput --check
python -m unittest tests.test_weapon_progression_snapshot -v
```

Both input files are checked against pinned Git blob SHAs. `--check` compares
the regenerated snapshot with this committed artifact; no unverified item IDs
are filled in.

## Coverage and unresolved source fields

- 287 weapon rows: 15 one-star, 5 two-star, 28 three-star, 149 four-star and
  90 five-star. **These are source rows, not a released/playable weapon roster.**
- Every weapon's promotion ID resolves. **260** of the **262** promotion groups
  are referenced. Groups `14411` and `14503` are present but unreferenced.
- Group `11101` is reused across rarities **1, 4 and 5**. A weapon's rarity
  cannot determine its actual promotion group or level cap.
- Ten low-rarity-style groups have only stages 0–4, not 0–6.
- **Nine** groups have **162** positive-count material slots whose `id` is
  *absent in the pinned source*: `11419, 11420, 11421, 11429, 12304, 13304,
  14306, 14411, 15306`. These are represented as `itemId: null`, with their
  original slot and count preserved. Do not call these empty costs, assign
  likely IDs, or charge them without runtime verification.
- Group `11521` really has no item counts or promotion Mora in its six
  configured upgrade stages. This does not establish whether the weapon can
  be acquired or upgraded in the live client.

The [native weapon baseline](../7.1-native-progression-baseline.md#weapon-progression)
documents EXP requirements, enhancement ores, observed normal ascension
templates and the B-level enhancement-Mora ratio. The
[pinned growth observations](../7.1-resource-growth-observations.json) retain
selected representative values.

This mapping is **7.1 integration-resource evidence**, not proof of client
claim, payment, or inventory behavior. Remaining gates include playable
roster identification, missing material-ID recovery, and native 7.1 weapon
enhancement/payment validation.
