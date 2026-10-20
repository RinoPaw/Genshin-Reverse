#!/usr/bin/env python3
"""Compare historical ChestDropData.txt with server ChestDrop.json, read-only.

Identical values establish shared historical rows, never official provenance.
"""
from __future__ import annotations

import argparse
from collections import Counter
import csv
import hashlib
import json
from pathlib import Path

COLUMNS = ("minLevel", "index", "dropId", "dropCount", "sourceType", "type")
HEADERS = ("最小等级", "总索引", "掉落ID", "掉落次数", "产出来源类型", "类别")
NUMBERS = frozenset(("minLevel", "dropId", "dropCount", "sourceType"))


def git_blob(path: Path) -> str:
    raw = path.read_bytes()
    return hashlib.sha1(b"blob " + str(len(raw)).encode("ascii") + b"\0" + raw).hexdigest()


def canonical(values: dict) -> tuple:
    if any(name not in values or values[name] is None for name in COLUMNS):
        raise ValueError("Missing one of the six ChestDrop columns")
    return tuple(int(values[name]) if name in NUMBERS else str(values[name]) for name in COLUMNS)


def historical(path: Path) -> list[tuple]:
    with path.open(encoding="utf-8-sig", newline="") as stream:
        reader = csv.DictReader(stream, delimiter="\t")
        if tuple(reader.fieldnames or ()) != HEADERS:
            raise ValueError("Unexpected historical ChestDropData header")
        rows = []
        for n, line in enumerate(reader, start=2):
            if None in line or any(value is None for value in line.values()):
                raise ValueError(f"Malformed historical ChestDropData row {n}")
            rows.append(canonical(dict(zip(COLUMNS, (line[h] for h in HEADERS)))))
    return rows


def server(path: Path) -> list[tuple]:
    data = json.loads(path.read_text(encoding="utf-8-sig"))
    if not isinstance(data, list):
        raise ValueError("Server ChestDrop.json must be a list")
    if not all(isinstance(row, dict) for row in data):
        raise ValueError("Server ChestDrop.json contains a non-object row")
    return [canonical(row) for row in data]


def compare(old: list[tuple], new: list[tuple]) -> dict:
    a, b = Counter(old), Counter(new)
    overlap, removed, added = a & b, a - b, b - a
    return {
        "historicalRows": len(old),
        "serverRows": len(new),
        "unchangedHistoricalRows": sum(overlap.values()),
        "historicalMissingOrChangedRows": sum(removed.values()),
        "serverAdditionalRows": sum(added.values()),
        "historicalIsExactMultisetSubset": not removed,
        "historicalOnlyExamples": [dict(zip(COLUMNS, row)) for row in sorted(removed)[:5]],
        "serverOnlyExamples": [dict(zip(COLUMNS, row)) for row in sorted(added)[:5]],
        "evidenceClass": "historical-cross-repository-structure-only",
        "native71Verified": False,
    }


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--historical", type=Path, required=True)
    ap.add_argument("--server", type=Path, required=True)
    ap.add_argument("--historical-blob", help="Expected historical Git blob SHA-1")
    ap.add_argument("--server-blob", help="Expected server Git blob SHA-1")
    ap.add_argument("--check-contained", action="store_true")
    args = ap.parse_args()
    blobs = {"historical": git_blob(args.historical), "server": git_blob(args.server)}
    for name, expected in (("historical", args.historical_blob), ("server", args.server_blob)):
        if expected and blobs[name] != expected:
            ap.error(f"{name} Git blob changed: expected {expected}, got {blobs[name]}")
    report = compare(historical(args.historical), server(args.server))
    report["gitBlobs"] = blobs
    print(json.dumps(report, ensure_ascii=False, indent=2))
    if args.check_contained and not report["historicalIsExactMultisetSubset"]:
        ap.exit(1, "Historical rows were removed or changed\n")


if __name__ == "__main__":
    main()
