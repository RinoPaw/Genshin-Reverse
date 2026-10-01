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

For a full regenerated registry, also create an independent AstaPS control set and run `genshinre crosscheck-registry` before claiming completeness.

## Pull requests and issues

Issues are encouraged for unknown packets and research tasks when they include reproducible runtime/static evidence. Use the templates so sample identity and capture context survive across sessions and contributors.

Small direct maintenance commits are fine for maintainers. External contributors should normally use pull requests so generated artifact changes can be reviewed together with their provenance.

## Licensing

No repository-wide license has been selected yet. Do not assume a license for copied or contributed code/data; keep provenance clear and avoid importing proprietary raw game assets.
