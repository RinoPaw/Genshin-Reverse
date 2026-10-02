from __future__ import annotations

import csv
import json
from pathlib import Path

from .registry import CANONICAL_REGISTRY_COLUMNS

DIRECTORIES = ("registry", "metadata", "proto", "cmdids", "xrefs", "analyses", "reports")


def scaffold(root: Path, version: str, region: str, platform: str) -> Path:
    target = root / "versions" / f"{version}-{region}" / platform
    target.mkdir(parents=True, exist_ok=True)
    for name in DIRECTORIES:
        (target / name).mkdir(exist_ok=True)

    hashes = target / "hashes.json"
    if not hashes.exists():
        hashes.write_text(
            json.dumps(
                {
                    "game_version": version,
                    "region": region,
                    "platform": platform,
                    "samples": {},
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )

    registry = target / "registry" / "registry.csv"
    if not registry.exists():
        with registry.open("w", encoding="utf-8", newline="") as f:
            csv.writer(f).writerow(CANONICAL_REGISTRY_COLUMNS)

    known = target / "proto" / "known-opcodes.csv"
    if not known.exists():
        with known.open("w", encoding="utf-8", newline="") as f:
            csv.writer(f).writerow(("semantic_name", "cmd_id", "direction", "status", "evidence", "notes"))

    shapes = target / "proto" / "message-shapes.json"
    if not shapes.exists():
        shapes.write_text("{}\n", encoding="utf-8")
    return target
