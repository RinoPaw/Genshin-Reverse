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

## Prefer machine-readable intermediates

CSV/JSON indexes are preferred over screenshots or prose-only dumps. Human-readable reports should point to the machine-readable source data.

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

No repository-wide license has been selected yet. Do not assume a license for copied or contributed code/data; keep provenance clear and avoid importing proprietary raw game assets.
