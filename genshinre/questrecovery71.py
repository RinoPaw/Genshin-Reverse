"""Build provenance-preserving 7.1 ordinary Quest recovery manifests.\n\nClient-native retained fields and compatibility-only historical carry-forward\nfields remain explicitly separated; unresolved rows are never synthesized.\n"""\n\nfrom __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Any, Iterable, Mapping


RAW_71_FIELD_KEYS = {
    "finishCond": "finishCond",
    "failCond": "KHEBAEMAPPJ",
    "finishExec": "FAPCNCGCEBJ",
    "failExec": "CNPOFCKIBDL",
}
COMPAT_FIELDS = ("acceptCond", "beginExec")


def _read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def load_raw_71_rows(root: Path) -> dict[int, dict[str, Any]]:
    rows: dict[int, dict[str, Any]] = {}
    for path in sorted(root.glob("*.json")):
        try:
            obj = _read_json(path)
        except (OSError, json.JSONDecodeError):
            continue
        if not isinstance(obj, dict):
            continue
        seq = obj.get("JIJKODHIEED")
        if not isinstance(seq, list):
            seq = obj.get("subQuests")
        if not isinstance(seq, list):
            continue
        for row in seq:
            if not isinstance(row, dict):
                continue
            sub_id = row.get("NFGFDHPPBIF")
            if not isinstance(sub_id, int):
                sub_id = row.get("subId")
            if isinstance(sub_id, int):
                rows[sub_id] = row
    return rows


def load_community_rows(root: Path) -> dict[int, dict[str, Any]]:
    rows: dict[int, dict[str, Any]] = {}
    for path in sorted(root.glob("*.json")):
        try:
            obj = _read_json(path)
        except (OSError, json.JSONDecodeError):
            continue
        if not isinstance(obj, dict):
            continue
        seq = obj.get("subQuests")
        if not isinstance(seq, list):
            continue
        for row in seq: