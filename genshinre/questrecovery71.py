"""Build provenance-preserving 7.1 ordinary Quest recovery manifests.

Client-native retained fields and compatibility-only historical carry-forward
fields remain explicitly separated; unresolved rows are never synthesized.
"""

from __future__ import annotations

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
            if isinstance(row, dict) and isinstance(row.get("subId"), int):
                rows[row["subId"]] = row
    return rows


def _typed_entries(value: Any, *, field: str) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    out: list[dict[str, Any]] = []
    for item in value:
        if not isinstance(item, dict):
            continue
        quest_type = item.get("type")
        if not isinstance(quest_type, str) or not quest_type:
            continue
        # Community converters use this as an empty/default prerequisite slot.
        # It is not accepted as recovered prerequisite semantics.
        if field == "acceptCond" and quest_type == "QUEST_COND_UNKNOWN":
            continue
        out.append(dict(item))
    return out


def _comparison_entry(item: Mapping[str, Any]) -> dict[str, Any]:
    params = item.get("param")
    if isinstance(params, list):
        params = list(params)
        # Only comparison is normalized. The manifest retains exact source
        # entries. This absorbs fixed-width serializer suffix padding.
        while params and params[-1] in (0, "0", ""):
            params.pop()
    else:
        params = []

    param_str = item.get(
        "param_str",
        item.get("paramStr", item.get("JBELGECAIIL", "")),
    )
    return {
        "type": item.get("type"),
        "param": params,
        "param_str": param_str or "",
        "count": int(item.get("count") or 0),
    }


def _comparison_value(value: Any, *, field: str) -> list[dict[str, Any]]:
    return [
        _comparison_entry(item)
        for item in _typed_entries(value, field=field)
    ]


def _has_unknown_accept_placeholder(value: Any) -> bool:
    if not isinstance(value, list):
        return False
    return any(
        isinstance(item, dict) and item.get("type") == "QUEST_COND_UNKNOWN"
        for item in value
    )


def _source_ref(kind: str, label: str) -> dict[str, str]:
    return {"kind": kind, "source": label}


def build_manifest(
    raw_71_rows: Mapping[int, Mapping[str, Any]],
    community_71_rows: Mapping[int, Mapping[str, Any]],
    community_70_rows: Mapping[int, Mapping[str, Any]],
    *,
    raw_71_source: str,
    community_71_source: str,
    community_70_source: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    rows_out: dict[str, Any] = {}
    unresolved_out: dict[str, Any] = {}
    field_counts: dict[str, Counter[str]] = {
        field: Counter() for field in (*RAW_71_FIELD_KEYS, *COMPAT_FIELDS)
    }

    for sub_id in sorted(raw_71_rows):
        raw_row = raw_71_rows[sub_id]
        row_fields: dict[str, Any] = {}
        row_status: dict[str, Any] = {}

        for field, raw_key in RAW_71_FIELD_KEYS.items():
            entries = _typed_entries(raw_row.get(raw_key), field=field)
            if entries:
                row_fields[field] = {
                    "value": entries,
                    "provenance": {
                        **_source_ref("same-version-client-projection", raw_71_source),
                        "raw_field": raw_key,
                        "evidence": "7.1 ordinary Quest retained field",
                    },
                }
                field_counts[field]["nonempty"] += 1
            else:
                field_counts[field]["empty"] += 1

        compat_71 = community_71_rows.get(sub_id)
        compat_70 = community_70_rows.get(sub_id)

        for field in COMPAT_FIELDS:
            if compat_70 is None:
                status = {
                    "status": "unresolved",
                    "reason": "no-predecessor-community-row",
                }
                field_counts[field]["unresolved"] += 1
            elif compat_71 is None:
                status = {
                    "status": "unresolved",
                    "reason": "no-current-community-row",
                    "historical_source": community_70_source,
                }
                field_counts[field]["unresolved"] += 1
            else:
                raw_70 = compat_70.get(field)
                raw_71 = compat_71.get(field)
                value_70 = _comparison_value(raw_70, field=field)
                value_71 = _comparison_value(raw_71, field=field)
                placeholder_70 = (
                    field == "acceptCond"
                    and _has_unknown_accept_placeholder(raw_70)
                )
                placeholder_71 = (
                    field == "acceptCond"
                    and _has_unknown_accept_placeholder(raw_71)
                )
                if not value_70 and not value_71 and (placeholder_70 or placeholder_71):
                    status = {
                        "status": "unresolved",
                        "reason": "community-placeholder-only",
                        "community_70_placeholder": placeholder_70,
                        "community_71_placeholder": placeholder_71,
                    }
                    field_counts[field]["unresolved"] += 1
                elif value_70 != value_71:
                    status = {
                        "status": "unresolved",
                        "reason": "community-carry-forward-diverged",
                        "community_70": value_70,
                        "community_71": value_71,
                    }
                    field_counts[field]["unresolved"] += 1
                elif value_71:
                    exact_entries = _typed_entries(compat_71.get(field), field=field)
                    row_fields[field] = {
                        "value": exact_entries,
                        "provenance": {
                            "kind": "community-carry-forward",
                            "status": "compatibility-only",
                            "source": community_71_source,
                            "predecessor_source": community_70_source,
                            "evidence": "normalized value is identical in predecessor and current community projections",
                            "native_7_1": False,
                        },
                    }
                    status = {
                        "status": "compatibility-value",
                        "source": community_71_source,
                    }
                    field_counts[field]["compatibility_value"] += 1
                else:
                    status = {
                        "status": "compatibility-empty",
                        "source": community_71_source,
                        "predecessor_source": community_70_source,
                    }
                    field_counts[field]["compatibility_empty"] += 1

            row_status[field] = status
            if status["status"] == "unresolved":
                unresolved_out.setdefault(str(sub_id), {"subId": sub_id, "fields": {}})
                unresolved_out[str(sub_id)]["fields"][field] = status

        rows_out[str(sub_id)] = {
            "subId": sub_id,
            "fields": row_fields,
            "missing_field_status": row_status,
        }

    manifest = {
        "schema_version": 1,
        "target": "Genshin Impact 7.1 ordinary Quest field recovery",
        "policy": {
            "native_retained_fields": list(RAW_71_FIELD_KEYS),
            "compatibility_fields": list(COMPAT_FIELDS),
            "previous_row_synthesis": False,
            "quest_cond_unknown_is_placeholder": True,
            "quest_cond_unknown_is_unresolved": True,
            "compatibility_requires_predecessor_equality": True,
        },
        "sources": {
            "raw_7_1": _source_ref("same-version-client-projection", raw_71_source),
            "community_7_1": _source_ref("community-merged-resource", community_71_source),
            "community_7_0": _source_ref("community-predecessor-resource", community_70_source),
        },
        "summary": {
            "raw_7_1_rows": len(raw_71_rows),
            "community_7_1_rows": len(community_71_rows),
            "community_7_0_rows": len(community_70_rows),
            "unresolved_rows": len(unresolved_out),
            "fields": {
                field: dict(counts)
                for field, counts in field_counts.items()
            },
        },
        "rows": rows_out,
    }
    unresolved = {
        "schema_version": 1,
        "target": manifest["target"],
        "sources": manifest["sources"],
        "summary": {
            "rows": len(unresolved_out),
            "field_occurrences": sum(
                len(row["fields"]) for row in unresolved_out.values()
            ),
        },
        "rows": unresolved_out,
    }
    return manifest, unresolved


def build_from_directories(
    raw_71_root: Path,
    community_71_root: Path,
    community_70_root: Path,
    *,
    raw_71_source: str,
    community_71_source: str,
    community_70_source: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    return build_manifest(
        load_raw_71_rows(raw_71_root),
        load_community_rows(community_71_root),
        load_community_rows(community_70_root),
        raw_71_source=raw_71_source,
        community_71_source=community_71_source,
        community_70_source=community_70_source,
    )


def _write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Build a provenance-preserving Genshin 7.1 ordinary Quest field "
            "recovery manifest."
        )
    )
    parser.add_argument("--raw-7-1-root", type=Path, required=True)
    parser.add_argument("--community-7-1-root", type=Path, required=True)
    parser.add_argument("--community-7-0-root", type=Path, required=True)
    parser.add_argument("--raw-7-1-source", required=True)
    parser.add_argument("--community-7-1-source", required=True)
    parser.add_argument("--community-7-0-source", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--unresolved-output", type=Path, required=True)
    args = parser.parse_args(list(argv) if argv is not None else None)

    manifest, unresolved = build_from_directories(
        args.raw_7_1_root,
        args.community_7_1_root,
        args.community_7_0_root,
        raw_71_source=args.raw_7_1_source,
        community_71_source=args.community_7_1_source,
        community_70_source=args.community_7_0_source,
    )
    _write_json(args.output, manifest)
    _write_json(args.unresolved_output, unresolved)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())