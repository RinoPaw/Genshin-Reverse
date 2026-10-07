# Quest native-resource research handoff

Checkpoint: 2026-10-07

This handoff contains resume context only. Durable conclusions live in the target analyses and tracking issues; see `docs/governance.md`.

## #8 extraction / ownership

**Closed.** The exact 7.1 QuestExcel wire and ordinary full-Quest ownership boundary are now durable under:

`versions/7.1.0-global/windows-x64/analyses/quest-extraction/README.md`

Do not resume #8 by searching QuestExcel tails or attempting to recover ordinary 7.1 `acceptCond` / `beginExec` as client-native fields.

Key closed facts:

- exact QuestExcel asset: `MiHoYoBinData/3b87ae83.dat`;
- 33,214 rows, full row consumption, no hidden prerequisite arrays;
- ordinary full-Quest row owns `failExec`, `failCond`, `finishCond`, `finishExec`;
- ordinary `acceptCond` / `beginExec` ownership was removed between exact 2.8 and 3.0;
- Asta previous-row prerequisite chains are downstream synthetic compatibility policy.

## #20 compatibility restoration

Current remaining gaps:

- `acceptCond`: 4,901 unresolved;
- `beginExec`: 112 unresolved.

The latest recovery checkpoint also has:

- 15,400 compatibility `acceptCond` values;
- 12,913 compatibility/historical-empty `acceptCond` classifications;
- 4,838 compatibility `beginExec` values;
- 28,264 compatibility/historical-empty `beginExec` classifications.

Resume from **new evidence classes** only:

1. MainQuest topology and branch/convergence structure;
2. talks/dialog/script relations;
3. Lua/source-side quest configuration;
4. independently sourced historical design/server tables;
5. explicit structural inference kept as `inferred`.

Do not spend more time searching known Luna/Asta siblings that share resource ancestry. Never silently turn inferred or synthetic data into compatibility evidence.

## #9 Quest 351 persistent Return-to-quest-point state

Status: `UNRESOLVED`.

Current exact anchor:

```text
DoSetPlayerBornDataNotify
CmdId               22899
client type         ONKOPMILDMF
typeDefinition      87483
handler owner       LLCGIEDMIIG
handler method      MACAMCMOKOL(ONKOPMILDMF)
handler RVA         0x0C227790
method index        322028
```

Historical `LoadingManager.OnDoSetPlayerBornData() -> QuestModule.ResetTrackingLocalData([351])` remains navigation evidence only.

Resume by tracing the current 7.1 UI/state path for `UI_STC_MAIN_RETURN_TO_QUEST` back to the enabling state and its clearing transition. Keep this separate from prerequisite compatibility recovery.

## Maintenance rules

- Start new work from current `rino`.
- One issue owns one active research question.
- Confirmed conclusions must be promoted to the target analysis, not left branch-only.
- Handoffs must not become competing status sources.
- Temporary workflows need an active owner and retirement condition.
- Full required CI is mandatory before user testing, upstream submission, or canonical publication.
