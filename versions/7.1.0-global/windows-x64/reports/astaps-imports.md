# AstaPS reverse-history migration index

This report tracks reverse-engineering experience that previously lived primarily in AstaPS branches, PRs, commit messages, or test branches and has been migrated into Genshin-Reverse.

This is a provenance index, not an evidence promotion mechanism. Imported claims retain the validation state of their source. Current canonical datasets keep their existing publication gates.

## Migrated or already represented

| AstaPS source | Durable Genshin-Reverse destination | Migration status |
| --- | --- | --- |
| `RinoPaw/AstaPS:reverse` — `docs/reverse-workflow.md` | `docs/research-workflow.md` | reusable workflow discipline migrated and adapted to Genshin-Reverse ownership; branch can be retired after AstaPS-only maintenance rules are preserved there |
| `RinoPaw/AstaPS:test/born-starlight-order` | `docs/case-studies/born-7.1.md`, `docs/methods/cmdid-recovery.md` | isolated BornRsp / nickname / first-login experiments and the resulting method are already represented; no duplicate analysis created |
| `RinoPaw/AstaPS:test/born-starlight-quest351` | `docs/case-studies/born-7.1.md`, `docs/methods/cmdid-recovery.md` | later born/Quest 351 integration probes belong to the same investigation lineage; durable protocol findings are already represented |
| `RinoPaw/AstaPS:test/quest-351-352-trace` | `docs/case-studies/born-7.1.md` plus AstaPS server history | branch is runtime quest/integration tracing after the born protocol result; no additional canonical protocol claim is promoted from it |
| `RinoPaw/AstaPS:test/unlock-trans-point-*` and corresponding AstaPS integration work | `docs/case-studies/unlock-trans-point-7.1.md`, `versions/7.1.0-global/windows-x64/analyses/unlock-trans-point/` | already represented; current analysis remains source of truth |
| `RinoPaw/AstaPS:test/statue-native-unlock` | `versions/7.1.0-global/windows-x64/analyses/statue-unlock/FINDINGS_2026-10-03_QUEST_TALK_CHAIN.md` | durable quest/talk-chain conclusion is preserved; temporary probes and EnterTrans fallbacks remain server-history only |
| `RinoPaw/AstaPS:test/statue-quest303-native` | `versions/7.1.0-global/windows-x64/analyses/statue-unlock/FINDINGS_2026-10-03_QUEST303_7_1_RESOURCE_GAP.md` | Quest 303 ownership and 7.1 resource-gap conclusion are preserved; experimental implementation is not copied |
| `MeChen618/AstaPS` PR #42 / `fix/special-energy` | `versions/7.1.0-global/windows-x64/analyses/special-energy/README.md` | historical resource findings and source validation state migrated |
| `MeChen618/AstaPS` PR #37 / `ccr-53468249-3vfc4l` | `docs/case-studies/tps-7.1.md` | matching methodology, imported identities, validation boundaries, and unresolved questions migrated |

## Deliberately not copied

Server implementation details that do not preserve reverse-engineering evidence remain in AstaPS history. Build/CI cleanup, gameplay fixes, commands, persistence changes, configuration refactors, and server-only work should not be duplicated here merely because they were developed alongside an investigation.

That includes `RinoPaw/AstaPS:pr/fresh-intro-game-config`: its surviving value is AstaPS configuration/lifecycle implementation history, while the born protocol evidence it builds on is already represented above.

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
