from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .assetindex import unwrap_mihoyo_bin_data
from .questcoverage import analyze_quest_path


class QuestCollectionError(ValueError):
    """Raised when exported Quest assets do not match their exact extraction manifest."""


def _asset_rows(data: dict[str, Any]) -> list[dict[str, Any]]:
    rows = data.get("assets")
    if not isinstance(rows, list):
        raise QuestCollectionError("quest asset manifest has no assets list")
    return rows


def _raw_export_path(export_root: Path, row: dict[str, Any]) -> Path:
    try:
        group_id = int(row["groupId"])
        block_id = int(row["blockId"])
        exported_name = str(row["exportedName"])
    except (KeyError, TypeError, ValueError) as exc:
        raise QuestCollectionError(f"invalid quest asset row: {row}") from exc
    return (
        export_root
        / str(group_id)
        / str(block_id)
        / "MiHoYoBinData"
        / f"{exported_name}.dat"
    )


def collect_quest_payloads(
    asset_manifest: Path,
    export_root: Path,
    output_dir: Path,
    *,
    coverage_path: Path | None = None,
) -> dict[str, Any]:
    """Collect exact Quest payloads from block-scoped AnimeStudio Raw exports.

    The extractor keeps the asset-index proof boundary: every payload comes from the
    block/exported-name pair resolved for that MainQuestIndex handle. Missing or duplicate
    main IDs are hard errors.
    """

    data = json.loads(asset_manifest.read_text(encoding="utf-8"))
    rows = _asset_rows(data)
    expected_ids: set[int] = set()
    for row in rows:
        try:
            main_id = int(row["mainId"])
        except (KeyError, TypeError, ValueError) as exc:
            raise QuestCollectionError(f"invalid mainId in quest asset row: {row}") from exc
        if main_id in expected_ids:
            raise QuestCollectionError(f"duplicate quest asset mainId {main_id}")
        expected_ids.add(main_id)

    output_dir.mkdir(parents=True, exist_ok=True)
    stale = sorted(
        item
        for item in output_dir.rglob("*")
        if item.is_file() and item.name.isdigit() and int(item.name) not in expected_ids
    )
    if stale:
        raise QuestCollectionError(
            f"payload output contains stale Quest files not in manifest: {stale[:10]}"
        )

    seen: set[int] = set()
    collected: list[dict[str, Any]] = []
    for row in rows:
        main_id = int(row["mainId"])
        seen.add(main_id)

        raw_path = _raw_export_path(export_root, row)
        if not raw_path.is_file():
            raise QuestCollectionError(
                f"missing Raw export for mainId {main_id}: expected {raw_path}"
            )
        raw = raw_path.read_bytes()
        payload = unwrap_mihoyo_bin_data(raw)
        target = output_dir / str(main_id)
        target.write_bytes(payload)
        collected.append(
            {
                "mainId": main_id,
                "blockId": int(row["blockId"]),
                "exportedName": str(row["exportedName"]),
                "rawSize": len(raw),
                "payloadSize": len(payload),
                "payload": str(target),
            }
        )

    coverage = analyze_quest_path(output_dir)
    if coverage_path is not None:
        coverage_path.parent.mkdir(parents=True, exist_ok=True)
        coverage_path.write_text(
            json.dumps(coverage, indent=2, ensure_ascii=False, sort_keys=True) + "\n",
            encoding="utf-8",
        )

    return {
        "expected": len(rows),
        "collected": len(collected),
        "outputDir": str(output_dir),
        "coverage": coverage,
        "payloads": collected,
    }
