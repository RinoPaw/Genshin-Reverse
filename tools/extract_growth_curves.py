#!/usr/bin/env python3
"""Extract a reproducible Genshin 7.1 progression snapshot from AstaPS-Resource.

The input checkout is intentionally pinned. This tool does not download data and does not
promote restored resource fields to native 7.1 evidence; provenance stays in the analysis.
"""

from __future__ import annotations

import argparse
import csv
import json
import subprocess
from pathlib import Path
from typing import Any, Iterable

PINNED_RESOURCE_COMMIT = "b0f3a2791607cab2a4c24cb9ef249dd2d94d7ffd"
DEFAULT_OUT = Path("versions/7.1.0-global/windows-x64/analyses/growth-curves/generated")

SOURCE_FILES = [
    "AvatarLevelExcelConfigData.json",
    "AvatarCurveExcelConfigData.json",
    "AvatarPromoteExcelConfigData.json",
    "AvatarExcelConfigData.json",
    "WeaponLevelExcelConfigData.json",
    "WeaponCurveExcelConfigData.json",
    "WeaponPromoteExcelConfigData.json",
    "WeaponExcelConfigData.json",
    "ReliquaryLevelExcelConfigData.json",
    "ReliquaryMainPropExcelConfigData.json",
    "ReliquaryAffixExcelConfigData.json",
    "ReliquaryExcelConfigData.json",
    "PlayerLevelExcelConfigData.json",
    "WorldLevelExcelConfigData.json",
    "MonsterCurveExcelConfigData.json",
    "AvatarFettersLevelExcelConfigData.json",
    "AvatarSkillExcelConfigData.json",
    "AvatarSkillDepotExcelConfigData.json",
    "AvatarTalentExcelConfigData.json",
    "ProudSkillExcelConfigData.json",
]


def git_head(root: Path) -> str | None:
    try:
        return subprocess.check_output(
            ["git", "-C", str(root), "rev-parse", "HEAD"], text=True
        ).strip()
    except (OSError, subprocess.CalledProcessError):
        return None


def load_json(path: Path) -> Any:
    text = path.read_text(encoding="utf-8")
    if not text.strip():
        return []
    return json.loads(text)


def dump_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def write_csv(path: Path, rows: Iterable[dict[str, Any]], columns: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=columns, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def curve_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for row in rows:
        level = row.get("level")
        for info in row.get("curveInfos", []):
            out.append({
                "level": level,
                "type": info.get("type"),
                "value": info.get("value"),
            })
    return out


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--resource-root", type=Path, required=True,
                        help="checkout of RinoPaw/AstaPS-Resource")
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--allow-unpinned", action="store_true",
                        help="permit extraction from a different resource commit")
    args = parser.parse_args()

    root = args.resource_root.resolve()
    excel = root / "ExcelBinOutput"
    out = args.out.resolve()

    head = git_head(root)
    if head != PINNED_RESOURCE_COMMIT and not args.allow_unpinned:
        raise SystemExit(
            f"AstaPS-Resource HEAD is {head!r}; expected {PINNED_RESOURCE_COMMIT}. "
            "Checkout the pinned commit or pass --allow-unpinned explicitly."
        )

    tables: dict[str, Any] = {}
    status: list[dict[str, Any]] = []
    for name in SOURCE_FILES:
        path = excel / name
        if not path.exists():
            status.append({"file": name, "status": "missing"})
            continue
        data = load_json(path)
        tables[name] = data
        status.append({
            "file": name,
            "status": "empty" if data == [] else "present",
            "row_count": len(data) if isinstance(data, list) else None,
        })

    # Preserve exact source data used by the snapshot. Empty legacy tables remain empty.
    raw_dir = out / "raw"
    for name, data in tables.items():
        dump_json(raw_dir / name, data)

    if rows := tables.get("AvatarLevelExcelConfigData.json"):
        write_csv(out / "avatar-level.csv", rows, ["level", "exp"])

    if rows := tables.get("AvatarCurveExcelConfigData.json"):
        write_csv(out / "avatar-curve.csv", curve_rows(rows), ["level", "type", "value"])

    if rows := tables.get("WeaponCurveExcelConfigData.json"):
        write_csv(out / "weapon-curve.csv", curve_rows(rows), ["level", "type", "value"])

    if rows := tables.get("MonsterCurveExcelConfigData.json"):
        write_csv(out / "monster-curve.csv", curve_rows(rows), ["level", "type", "value"])

    if rows := tables.get("PlayerLevelExcelConfigData.json"):
        columns = sorted({key for row in rows for key in row.keys()})
        write_csv(out / "player-level.csv", rows, columns)

    if rows := tables.get("WorldLevelExcelConfigData.json"):
        columns = sorted({key for row in rows for key in row.keys()})
        write_csv(out / "world-level.csv", rows, columns)

    if rows := tables.get("AvatarFettersLevelExcelConfigData.json"):
        write_csv(out / "friendship-level.csv", rows, ["fetter_level", "need_exp"])

    if rows := tables.get("ReliquaryMainPropExcelConfigData.json"):
        write_csv(
            out / "reliquary-main-prop.csv",
            rows,
            ["id", "propDepotId", "propType", "weight", "affixName"],
        )

    affix = tables.get("ReliquaryAffixExcelConfigData.json", [])
    five_star = [row for row in affix if row.get("depotId") == 501]
    if five_star:
        write_csv(
            out / "reliquary-affix-5star.csv",
            five_star,
            ["id", "depotId", "group_id", "propType", "propValue", "weight", "upgradeWeight"],
        )

        classes: dict[str, dict[str, Any]] = {}
        for row in five_star:
            key = row.get("propType")
            entry = classes.setdefault(key, {
                "propType": key,
                "entry_count": 0,
                "class_weight": 0,
                "upgrade_weight_values": set(),
                "roll_values": [],
            })
            entry["entry_count"] += 1
            entry["class_weight"] += row.get("weight", 0)
            entry["upgrade_weight_values"].add(row.get("upgradeWeight"))
            entry["roll_values"].append(row.get("propValue"))
        serializable = []
        for entry in classes.values():
            entry["upgrade_weight_values"] = sorted(entry["upgrade_weight_values"])
            serializable.append(entry)
        dump_json(out / "reliquary-affix-5star-summary.json", serializable)

    dump_json(out / "source-status.json", {
        "resource_repo": "RinoPaw/AstaPS-Resource",
        "resource_head": head,
        "expected_resource_commit": PINNED_RESOURCE_COMMIT,
        "tables": status,
        "provenance_note": (
            "Presence in AstaPS-Resource is integration evidence. Reliquary weight fields "
            "are restored/historical-continuity fields; see analyses/artifact-generation."
        ),
    })

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
