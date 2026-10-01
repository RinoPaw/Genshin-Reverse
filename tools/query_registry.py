#!/usr/bin/env python3
"""Query the canonical registry.csv by CmdId or type name."""

from __future__ import annotations

import argparse
import csv
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("registry", type=Path)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--cmd-id", type=int)
    group.add_argument("--type")
    args = parser.parse_args()

    with args.registry.open("r", encoding="utf-8", newline="") as f:
        rows = list(csv.DictReader(f))

    if args.cmd_id is not None:
        matches = [r for r in rows if r.get("cmd_id") == str(args.cmd_id)]
    else:
        needle = args.type.casefold()
        matches = [r for r in rows if needle in r.get("type_name", "").casefold()]

    if not matches:
        raise SystemExit(1)

    columns = list(matches[0])
    for row in matches:
        print(" | ".join(f"{key}={row.get(key, '')}" for key in columns))


if __name__ == "__main__":
    main()
