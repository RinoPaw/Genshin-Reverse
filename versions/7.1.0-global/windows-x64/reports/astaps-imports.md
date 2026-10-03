# AstaPS reverse-history migration index

This report tracks reverse-engineering experience that previously lived primarily in AstaPS branches, PRs, commit messages, or test branches and has been migrated into Genshin-Reverse.

This is a provenance index, not an evidence promotion mechanism. Imported claims retain the validation state of their source. Current canonical datasets keep their existing publication gates.

## Migrated or already represented

| AstaPS source | Durable Genshin-Reverse destination | Migration status |
| --- | --- | --- |
| `RinoPaw/AstaPS:reverse` — `docs/reverse-workflow.md` | `docs/research-workflow.md` | reusable workflow discipline migrated and adapted to Genshin-Reverse ownership |
| `RinoPaw/AstaPS:play/rino`, born investigation/test branches, and the born-flow integration history | `docs/case-studies/born-7.1.md`, `docs/methods/cmdid-recovery.md` | already represented; no duplicate analysis created |
| `RinoPaw/AstaPS:test/unlock-trans-point-*` and corresponding AstaPS integration work | `docs/case-studies/unlock-trans-point-7.1.md`, `versions/7.1.0-global/windows-x64/analyses/unlock-trans-point/` | already represented; current analysis remains source of truth |
| `MeChen618/AstaPS` PR #42 / `fix/special-energy` | `versions/7.1.0-global/windows-x64/analyses/special-energy/README.md` | historical resource findings and source validation state migrated |
| `MeChen618/AstaPS` PR #37 / `ccr-53468249-3vfc4l` | `docs/case-studies/tps-7.1.md` | matching methodology, imported identities, validation boundaries, and unresolved questions migrated |

## Deliberately not copied

Server implementation details that do not preserve reverse-engineering evidence remain in AstaPS history. Build/CI cleanup, gameplay fixes, commands, persistence changes, and server-only work should not be duplicated here merely because they were developed alongside an investigation.

Likewise, the AstaPS `reverse` branch's `docs/reverse-status.md` is not copied as a second live status page. Genshin-Reverse focused analyses and version reports already own investigation state; maintaining two status sources would allow them to drift.

## Migration rule for remaining branches

When another AstaPS branch contains useful reverse-engineering history:

1. identify the durable conclusion, rejected paths, method, validation state, and unresolved questions;
2. place version-specific evidence under `versions/<sample>/analyses/<topic>/` and reusable method material under `docs/methods/` or `docs/case-studies/`;
3. record source repo + branch/PR/commit;
4. preserve limitations exactly — especially “not tested in game”, historical-version-only evidence, inferred names, and unresolved fields;
5. avoid copying server-only implementation noise;
6. do not promote imported claims into canonical protocol/registry/xref datasets without satisfying their normal evidence gate.

The goal is that deleting an old experimental AstaPS branch would no longer erase the only discoverable record of why a conclusion was reached.
