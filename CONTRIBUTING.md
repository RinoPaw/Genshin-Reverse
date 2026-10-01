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

## Pull requests and issues

Small direct improvements are welcome. For unknown packets or research questions, an issue is useful when it includes reproducible runtime/static evidence. Use the issue templates so sample identity and capture context are not lost.
