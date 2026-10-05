# Genshin Impact 7.1 gameplay original archive

This directory preserves the **original progression inputs** used by the 7.1 progression research. It is intentionally separate from any reduced-live-service design profile.

## Source pin

- Game target: Genshin Impact 7.1.0 Global
- Primary integration resource: `RinoPaw/AstaPS-Resource`
- Pinned resource commit: `b0f3a2791607cab2a4c24cb9ef249dd2d94d7ffd`
- Source table identity: repository commit + path + Git blob SHA in `source-index.json`

The source pin is authoritative for this archive. Do not silently refresh these files from a newer resource commit.

## Layout

- `raw/`: exact textual snapshots copied from the pinned resource commit.
- `source-index.json`: inventory of all progression tables currently used or under investigation. Every entry carries its source path and Git blob SHA.
- Future normalized projections should live outside `raw/` and state their transformation explicitly.

`indexed_only` entries are still reproducible from the immutable source commit and blob identity, but have not yet been duplicated into this repository. They remain distinct from `raw_snapshot` entries.

## Provenance classes

A file being present in AstaPS-Resource does not automatically prove that every field is a native 7.1 client field.

Known boundaries:

- `ReliquaryMainPropExcelConfigData.json`: ordinary main-stat values are useful integration data, but `weight` fields were restored after import from historical evidence.
- `ReliquaryAffixExcelConfigData.json`: concrete affix rows are useful integration data, but `weight` and `upgradeWeight` include restored historical fields.
- `WeaponPromoteExcelConfigData.json` is empty at the pinned resource commit.
- `ProudSkillExcelConfigData.json` is empty at the pinned resource commit.

These gaps must stay visible. Do not fill them with familiar historical values and relabel those values as exact 7.1 native evidence.

## Current raw snapshots

The archive currently contains exact snapshots for:

- `AvatarLevelExcelConfigData.json`
- `PlayerLevelExcelConfigData.json`
- `WorldLevelExcelConfigData.json`

More source tables can be copied into `raw/` without changing the meaning of the archive. Their identity must match `source-index.json`.

## Design separation

Reduced-live-service changes belong in a separate design/profile directory. They must never overwrite this archive.

Examples of design-layer changes that must stay outside `original/`:

- removing weekday material-domain rotation;
- removing daily or weekly claim limits;
- replacing real-time respawn gates;
- changing Resin behavior;
- adding artifact RNG convergence;
- replacing the acquisition path for post-90 limit raising.

The original data remains available for reproduction, comparison and other private-server or research work.
