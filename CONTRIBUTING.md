# Contributing

Contributions should make a reverse-engineering result easier to reproduce, query or extend.

## Every derived artifact needs provenance

Record, directly or through a sibling manifest:

- game version and region;
- platform/architecture;
- `GenshinImpact.exe` SHA-256 when executable-derived;
- `global-metadata.dat` SHA-256 when metadata-derived;
- generating tool and tool revision/commit;
- generation command or enough parameters to reproduce it;
- evidence/status level.

## Preserve rejected paths

A rejected candidate is useful data. Keep it when the rejection prevents future researchers from repeating the same test. Focused investigations should distinguish `CONFIRMED`, `HIGH_CONFIDENCE`, `CANDIDATE`, `REJECTED` and `UNRESOLVED` results.

Preserve the conclusion and the reason for rejection, not dead executable clutter. Once a rejected probe no longer serves an active investigation, record the useful evidence in the focused analysis and remove the disposable helper.

## Keep the maintained tree current

The working tree should expose one maintained path for each operation. Git history is the archive; do not retain superseded scripts, workflows, helpers or generated variants under names such as `legacy`, `old`, `deprecated`, `backup`, or `workaround` merely to preserve the previous approach.

When a generally useful replacement is accepted, remove the superseded path in the same change. Promote reusable logic into `genshinre/`, keep sample-bound evidence under `versions/`, and delete disposable experiment glue after its result has been preserved.

A temporary compatibility path may remain only for a concrete currently supported dependency. Keep it narrow and document the dependency and the condition that permits removal. Avoid parallel implementations with unclear ownership.

## Prefer machine-readable intermediates

CSV/JSON indexes are preferred over screenshots or prose-only dumps. Human-readable reports should point to the machine-readable source data.

## Research lifecycle and status ownership

Repository governance is defined in [docs/governance.md](docs/governance.md).

The important maintenance rules are:

- ordinary research and small maintenance changes land directly on `main`; use a temporary branch only when isolation has a concrete benefit, and branch it from current `main`;
- issues own scope and promotion gates; version analyses own durable sample-bound conclusions;
- research queues and handoffs summarize those sources and must not become competing truth;
- when a research gate closes, promote evidence/code/tests and synchronize the issue, analysis, queue and handoff in the same maintenance change;
- temporary workflows need an owner and retirement condition, and must be removed after their useful result becomes durable;
- keep `rino` aligned with `main`; do not use `rino-*` branches as topic branches;
- retire temporary branches as soon as their durable result is on `main`.

Research branches are exceptional disposable work areas. Confirmed conclusions and maintained implementations belong on `main`.

## Maintenance and research responsibilities

Repository maintenance and focused reverse-engineering investigations are separate work streams.

Maintainer-owned work includes:

- keeping schemas, CLI/tooling, tests and documentation internally consistent;
- preserving exact-sample provenance and publication gates;
- turning generally useful investigation scripts into reusable tooling;
- keeping normal CI fast and deterministic;
- retiring obsolete one-off workflows after their reusable method and evidence have been preserved;
- reviewing promotion from investigation artifacts into canonical datasets.

A maintainer is not implicitly responsible for resolving every active protocol investigation. Packet- or gameplay-specific reverse-engineering should live in `versions/<target>/analyses/` and/or an issue until its evidence gate is met.

Before adding a new target-specific script or workflow, check whether the same operation belongs in `genshinre/` as a reusable command. One-off experiments are acceptable while a method is still being discovered, but successful methods should be generalized instead of copied into additional workflows.

## CI policy

Normal push/PR CI should run regression tests and artifact validation without downloading full game clients or performing heavyweight executable analysis.

Heavy sample-bound research jobs should use `workflow_dispatch` or narrow path triggers. Do not make ordinary documentation, data-label or maintenance commits wait on sample downloads and long reverse-engineering jobs.

## Raw game files

Do not commit game executables or raw `global-metadata.dat`. Record their hashes under the relevant version directory.

## Before committing

Install the standard-library toolkit entry point:

```bash
python -m pip install -e .
```

Then run:

```bash
python -m unittest discover -s tests -v
genshinre validate versions/7.1.0-global/windows-x64 --allow-partial
```

For a regenerated registry, also create an independent control set and run `genshinre crosscheck-registry` before claiming completeness.

## Pull requests and issues

Issues are encouraged for unknown packets and research tasks when they include reproducible runtime/static evidence. Use the templates so sample identity and capture context survive across sessions and contributors.

Small direct maintenance commits are fine for maintainers. External contributors should normally use pull requests so generated artifact changes can be reviewed together with their provenance.

## Licensing

Repository-authored code, documentation, schemas, and other original material are licensed under the Apache License 2.0; see `LICENSE`.

By intentionally submitting a contribution for inclusion in this repository, you agree that the contribution is provided under the Apache License 2.0 as described by Section 5 of that license, unless you explicitly state otherwise.

Do not import proprietary game binaries, raw `global-metadata.dat`, extracted third-party assets, or other material that you do not have permission to redistribute. Keep third-party provenance and licensing explicit when such material is referenced or incorporated.
