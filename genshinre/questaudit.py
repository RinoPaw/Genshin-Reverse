"""Audit AstaPS-style Quest resources against preserved 7.1 evidence."""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any, Mapping

from .questrecovery71 import (
    COMPAT_FIELDS,
    RAW_71_FIELD_KEYS,
    normalize_quest_entries,
    load_community_rows,
    load_raw_71_rows,
)


_CONFLICT_STATUSES = {
    "resource-missing-native",
    "resource-extra-vs-native",
    "resource-diverged-native",
    "compatibility-diverged",
    "compatibility-present-without-evidence",
}


def _read_manifest(path: Path | None) -> Mapping[str, Any] | None:
    if path is None:
        return None
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("recovery manifest must be a JSON object")
    return value


def _status(
    *,
    status: str,
    native_7_1: bool,
    resource_value: list[dict[str, Any]],
    expected_value: list[dict[str, Any]] | None = None,
    evidence: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    out: dict[str, Any] = {
        "status": status,
        "native_7_1": native_7_1,
        "resource_value": resource_value,
    }
    if expected_value is not None:
        out["expected_value"] = expected_value
    if evidence is not None:
        out["evidence"] = dict(evidence)
    return out


def audit_quest_rows(
    raw_71_rows: Mapping[int, Mapping[str, Any]],
    resource_rows: Mapping[int, Mapping[str, Any]],
    *,
    recovery_manifest: Mapping[str, Any] | None = None,
    only_problems: bool = False,
) -> dict[str, Any]:
    rows_out: dict[str, Any] = {}
    counts: Counter[str] = Counter()
    ids = sorted(set(raw_71_rows) | set(resource_rows))
    recovery_rows = (
        recovery_manifest.get("rows", {})
        if isinstance(recovery_manifest, Mapping)
        else {}
    )

    for sub_id in ids:
        raw_row = raw_71_rows.get(sub_id, {})
        resource_row = resource_rows.get(sub_id, {})
        fields: dict[str, Any] = {}

        for field, raw_key in RAW_71_FIELD_KEYS.items():
            native_value = normalize_quest_entries(raw_row.get(raw_key), field=field)
            resource_value = normalize_quest_entries(resource_row.get(field), field=field)

            if native_value == resource_value:
                status = "native-match" if native_value else "native-empty-match"
            elif native_value and not resource_value:
                status = "resource-missing-native"
            elif resource_value and not native_value:
                status = "resource-extra-vs-native"
            else:
                status = "resource-diverged-native"

            fields[field] = _status(
                status=status,
                native_7_1=True,
                resource_value=resource_value,
                expected_value=native_value,
            )
            counts[status] += 1

        recovery_row = (
            recovery_rows.get(str(sub_id), {})
            if isinstance(recovery_rows, Mapping)
            else {}
        )
        recovery_fields = (
            recovery_row.get("fields", {})
            if isinstance(recovery_row, Mapping)
            else {}
        )
        recovery_statuses = (
            recovery_row.get("missing_field_status", {})
            if isinstance(recovery_row, Mapping)
            else {}
        )

        for field in COMPAT_FIELDS:
            resource_value = normalize_quest_entries(resource_row.get(field), field=field)
            evidence = (
                recovery_statuses.get(field)
                if isinstance(recovery_statuses, Mapping)
                else None
            )
            recovered = (
                recovery_fields.get(field)
                if isinstance(recovery_fields, Mapping)
                else None
            )
            expected_value: list[dict[str, Any]] | None = None
            recovery_status = evidence.get("status") if isinstance(evidence, Mapping) else None

            if isinstance(recovered, Mapping):
                expected_value = normalize_quest_entries(recovered.get("value"), field=field)

            if recovery_status == "compatibility-value":
                if resource_value == (expected_value or []):
                    status = "compatibility-supported"
                else:
                    status = "compatibility-diverged"
            elif recovery_status == "compatibility-empty":
                status = (
                    "compatibility-empty-match"
                    if not resource_value
                    else "compatibility-diverged"
                )
                expected_value = []
            elif recovery_status == "unresolved":
                status = (
                    "compatibility-unresolved-present"
                    if resource_value
                    else "compatibility-unresolved-empty"
                )
            else:
                status = (
                    "compatibility-present-without-evidence"
                    if resource_value
                    else "compatibility-unclassified-empty"
                )

            fields[field] = _status(
                status=status,
                native_7_1=False,
                resource_value=resource_value,
                expected_value=expected_value,
                evidence=evidence if isinstance(evidence, Mapping) else None,
            )
            counts[status] += 1

        problems = sorted(
            field
            for field, item in fields.items()
            if item["status"] in _CONFLICT_STATUSES
        )
        unresolved = sorted(
            field
            for field, item in fields.items()
            if item["status"].startswith("compatibility-unresolved")
        )

        if only_problems and not problems and not unresolved:
            continue

        rows_out[str(sub_id)] = {
            "subId": sub_id,
            "problems": problems,
            "unresolved": unresolved,
            "fields": fields,
        }

    return {
        "schema_version": 1,
        "target": "AstaPS Quest resource vs Genshin Impact 7.1 evidence",
        "policy": {
            "ordinary_native_fields": list(RAW_71_FIELD_KEYS),
            "compatibility_fields": list(COMPAT_FIELDS),
            "compatibility_fields_are_native_7_1": False,
            "unknown_compatibility_evidence_is_not_accepted": True,
        },
        "summary": {
            "native_rows": len(raw_71_rows),
            "resource_rows": len(resource_rows),
            "reported_rows": len(rows_out),
            "conflicts": sum(counts[name] for name in _CONFLICT_STATUSES),
            "statuses": dict(sorted(counts.items())),
        },
        "rows": rows_out,
    }


def audit_quest_directories(
    raw_71_root: Path,
    resource_root: Path,
    *,
    recovery_manifest_path: Path | None = None,
    only_problems: bool = False,
) -> dict[str, Any]:
    return audit_quest_rows(
        load_raw_71_rows(raw_71_root),
        load_community_rows(resource_root),
        recovery_manifest=_read_manifest(recovery_manifest_path),
        only_problems=only_problems,
    )
