# Research workflow

This document preserves the reusable working discipline that accumulated on AstaPS reverse-engineering branches. It defines how investigations should be stored in Genshin-Reverse; it does not add or promote any technical reverse-engineering conclusion by itself.

## Start from existing evidence

Do not begin an investigation from a blank slate. Before probing anything:

1. read `docs/analysis-contract.md`, the relevant method/case-study documents, and the target version reports;
2. search this repository for the same feature, packet, symbol, CmdId, field, resource name, or subsystem;
3. inspect relevant history and rejected/candidate conclusions, not only the latest file;
4. search AstaPS history and comparable projects when they provide implementation context;
5. write down the exact target: client version, region, platform, subsystem, and the question being answered.

Existing work is part of the evidence base. Repeating an already documented experiment without a reason wastes time and can create conflicting conclusions.

## Repository boundaries

Use each repository for its own job:

- `RinoPaw/Genshin-Reverse` stores reverse-engineering evidence, scripts, indexes, xrefs, protocol work, hypotheses, case studies, and investigation state.
- `RinoPaw/AstaPS` stores server implementation, integration behavior, runtime probes used to validate server behavior, tests, and deployable changes.
- `RinoPaw/AstaPS-Resource` stores version-bound resource data used by the server.

Temporary dumps, exploratory analysis scripts, decompiler notes, and uncertain mappings belong here or in ignored local work areas, not in AstaPS production code.

## Save progress as recoverable artifacts

Create a checkpoint whenever a meaningful unit of work has been completed, for example after:

- identifying or rejecting a candidate;
- extracting a useful xref or call chain;
- finishing a packet/message-shape probe;
- producing a reusable script or index;
- reaching a result that would take meaningful time to reproduce.

Use small commits on investigation branches. Checkpoint before risky bulk edits, long-running scripts, large rebases, or any step that could destroy local state. Important progress must not exist only in chat history, terminal scrollback, an unsaved decompiler database, or an untracked local file.

## Leave resumable state

An unfinished investigation should leave enough state for another person to continue without rediscovering the whole path. Record at least:

- **Target** — what is being investigated and for which sample;
- **Confirmed** — facts supported by current evidence;
- **Candidates** — plausible leads that still need proof;
- **Rejected** — approaches or identities already disproved, with the reason;
- **Artifacts** — scripts, addresses, xrefs, captures, files, commits, or external sources that matter;
- **Next step** — the smallest useful action that advances the investigation.

Use the focused analysis directory as the source of truth. Do not create a second competing status document for the same topic.

## Evidence discipline

Use the shared confidence vocabulary from `docs/analysis-contract.md`:

- `CONFIRMED`
- `HIGH_CONFIDENCE`
- `CANDIDATE`
- `REJECTED`
- `UNRESOLVED`

Keep observations separate from interpretations. Record why a conclusion has its confidence level and what evidence would raise or lower it. A mapping does not become canonical just because it makes one server test pass.

Historical and cross-project results remain labeled as historical or cross-project evidence until the current target satisfies its publication gate. When a conclusion changes, preserve why the earlier conclusion was wrong.

## Prefer reproducible tooling

If a manual action is repeated, turn it into a maintained command, script, or documented command sequence. Prefer deterministic inputs and outputs over one-off GUI state.

Heavy executable analysis, resource extraction, live-client captures, and long reverse pipelines stay outside routine CI. Regular CI should remain fast enough that it never becomes a reason to avoid committing progress. The workflow policy in `docs/workflows.md` remains authoritative for Actions.

## Retire superseded paths

Once a reusable replacement is accepted, remove the superseded one-off script, workflow, helper, or duplicate implementation from the maintained tree. Git history preserves the old executable path.

Rejected conclusions may remain as concise evidence when they prevent repeated work. Temporary compatibility paths may remain only while a currently supported client/resource set still requires them; record the concrete dependency and removal condition.

## Promote into AstaPS deliberately

AstaPS should consume reverse-engineering results only after the relevant evidence is stable enough for implementation. For non-obvious protocol or client-behavior dependencies, keep a compact pointer from the AstaPS change to the durable Genshin-Reverse artifact or commit.

Keep server-side changes focused. An unresolved reverse question should remain explicit instead of being hidden behind guessed constants or broad fallbacks.

## Preserve imported AstaPS history

When useful reverse-engineering work already exists on an AstaPS branch or PR, migrate the durable result here instead of re-running the investigation merely to recreate documentation. The migrated record must include its source repository, branch/PR/commit when available, its original validation state, and any unresolved questions.

Migration is provenance work. It does not independently strengthen the evidence. If an AstaPS source says “unit-tested, not tested in game”, the Genshin-Reverse import must preserve that limitation.

## Handoff standard

A handoff is good when the next person can answer quickly:

1. What were we trying to learn?
2. What do we know now?
3. What did we already try and reject?
4. Where is the evidence saved?
5. What is the smallest useful next step?

If any answer exists only in someone's memory, the work is not safely maintained yet.
