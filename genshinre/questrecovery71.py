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
    # Some leaked/source-table serializers repeat an identical logical slot
    # when adjacent physical TSV columns contain the same entry. Keep source
    # values exact in manifests, but collapse exact duplicates for evidence
    # comparison so a duplicate column does not become a semantic conflict.
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in _typed_entries(value, field=field):
        normalized = _comparison_entry(item)
        key = json.dumps(
            normalized,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        if key in seen:
            continue
        seen.add(key)
        out.append(normalized)
    return out


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
    historical_tsv_rows: Mapping[int, Mapping[str, Any]] | None = None,
    historical_tsv_source: str | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    rows_out: dict[str, Any] = {}
    unresolved_out: dict[str, Any] = {}
    field_counts: dict[str, Counter[str]] = {
        field: Counter() for field in (*RAW_71_FIELD_KEYS, *COMPAT_FIELDS)
    }
    historical_tsv_rows = historical_tsv_rows or {}
    if historical_tsv_rows and not historical_tsv_source:
        raise ValueError(
            "historical_tsv_source is required when historical_tsv_rows are provided"
        )

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
        compat_tsv = historical_tsv_rows.get(sub_id)

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

            base_status_name = status["status"]

            # The leaked TSV is an independent historical server/design-table
            # source. It can strengthen a compatibility value or fill a gap,
            # but it never upgrades acceptCond/beginExec to native 7.1.
            pre_tsv_status = status["status"]
            if compat_tsv is not None:
                raw_tsv = compat_tsv.get(field)
                value_tsv = _comparison_value(raw_tsv, field=field)
                if value_tsv:
                    if field in row_fields:
                        current = _comparison_value(
                            row_fields[field]["value"],
                            field=field,
                        )
                        if current == value_tsv:
                            provenance = row_fields[field]["provenance"]
                            provenance["historical_server_source"] = historical_tsv_source
                            provenance["historical_server_source_agrees"] = True
                            status["historical_server_source"] = historical_tsv_source
                            field_counts[field]["historical_tsv_support"] += 1
                        else:
                            row_fields.pop(field, None)
                            status = {
                                "status": "unresolved",
                                "reason": "historical-tsv-community-diverged",
                                "historical_tsv_source": historical_tsv_source,
                                "historical_tsv": value_tsv,
                                "community": current,
                            }
                            field_counts[field]["historical_tsv_conflict"] += 1
                    elif (
                        status.get("status") == "unresolved"
                        and status.get("reason") != "community-carry-forward-diverged"
                    ):
                        row_fields[field] = {
                            "value": _typed_entries(raw_tsv, field=field),
                            "provenance": {
                                "kind": "historical-server-source",
                                "status": "compatibility-only",
                                "source": historical_tsv_source,
                                "evidence": (
                                    "direct GC leaked TSV column retained the "
                                    "compatibility field"
                                ),
                                "native_7_1": False,
                            },
                        }
                        status = {
                            "status": "compatibility-value",
                            "source": historical_tsv_source,
                            "historical_server_source": True,
                        }
                        field_counts[field]["historical_tsv_value"] += 1
                    elif status.get("status") == "compatibility-empty":
                        status = {
                            "status": "unresolved",
                            "reason": "historical-tsv-community-empty-diverged",
                            "historical_tsv_source": historical_tsv_source,
                            "historical_tsv": value_tsv,
                        }
                        field_counts[field]["historical_tsv_conflict"] += 1
                elif (
                    field not in row_fields
                    and status.get("status") == "unresolved"
                    and status.get("reason") != "community-carry-forward-diverged"
                    and not (
                        field == "acceptCond"
                        and _has_unknown_accept_placeholder(raw_tsv)
                    )
                ):
                    status = {
                        "status": "compatibility-empty",
                        "source": historical_tsv_source,
                        "evidence": "historical leaked TSV row has no typed field entries",
                        "native_7_1": False,
                    }
                    field_counts[field]["historical_tsv_empty"] += 1

            if status["status"] != base_status_name:
                count_key = {
                    "unresolved": "unresolved",
                    "compatibility-value": "compatibility_value",
                    "compatibility-empty": "compatibility_empty",
                }
                old_key = count_key.get(base_status_name)
                new_key = count_key.get(status["status"])
                if old_key is not None:
                    field_counts[field][old_key] -= 1
                if new_key is not None:
                    field_counts[field][new_key] += 1

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
            "historical_tsv_is_native_7_1": False,
            "historical_tsv_can_resolve_missing_community_evidence": True,
            "historical_tsv_conflicts_remain_unresolved": True,
        },
        "sources": {
            "raw_7_1": _source_ref("same-version-client-projection", raw_71_source),
            "community_7_1": _source_ref("community-merged-resource", community_71_source),
            "community_7_0": _source_ref("community-predecessor-resource", community_70_source),
            **(
                {
                    "historical_tsv": _source_ref(
                        "historical-server-source",
                        historical_tsv_source,
                    )
                }
                if historical_tsv_source
                else {}
            ),
        },
        "summary": {
            "raw_7_1_rows": len(raw_71_rows),
            "community_7_1_rows": len(community_71_rows),
            "community_7_0_rows": len(community_70_rows),
            "historical_tsv_rows": len(historical_tsv_rows),
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



def _compat_class(
    row: Mapping[str, Any] | None,
    *,
    field: str,
) -> tuple[str, list[dict[str, Any]]]:
    if row is None:
        return "no-row", []
    if field not in row:
        return "absent-key", []

    raw_value = row.get(field)
    if not isinstance(raw_value, list):
        return "non-list", []

    value = _comparison_value(raw_value, field=field)
    if value:
        return "nonempty", value
    if field == "acceptCond" and _has_unknown_accept_placeholder(raw_value):
        return "placeholder-only", []
    return "empty", []


def _community_consensus(
    community_sources: Mapping[str, Mapping[int, Mapping[str, Any]]],
    *,
    sub_id: int,
    field: str,
) -> tuple[dict[str, Any], list[dict[str, Any]] | None, str | None]:
    classes = {
        label: _compat_class(rows.get(sub_id), field=field)
        for label, rows in community_sources.items()
    }
    present = {
        label: state
        for label, state in classes.items()
        if state[0] != "no-row"
    }
    nonempty = {
        label: state[1]
        for label, state in classes.items()
        if state[0] == "nonempty"
    }

    if nonempty:
        canonical = {
            json.dumps(
                value,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            for value in nonempty.values()
        }
        if len(canonical) != 1:
            return (
                {
                    "status": "unresolved",
                    "reason": "community-consensus-diverged",
                    "classes": {
                        label: state[0] for label, state in classes.items()
                    },
                    "values": nonempty,
                },
                None,
                None,
            )

        chosen_source = next(iter(nonempty))
        chosen_row = community_sources[chosen_source][sub_id]
        return (
            {
                "status": "compatibility-value",
                "source": chosen_source,
                "consensus_sources": list(nonempty),
            },
            _typed_entries(chosen_row.get(field), field=field),
            chosen_source,
        )

    placeholders = [
        label for label, state in present.items()
        if state[0] == "placeholder-only"
    ]
    if placeholders:
        return (
            {
                "status": "unresolved",
                "reason": "community-placeholder-only",
                "placeholder_sources": placeholders,
                "classes": {
                    label: state[0] for label, state in classes.items()
                },
            },
            None,
            None,
        )

    emptyish = {
        "absent-key",
        "empty",
        "non-list",
    }
    if len(present) >= 2 and all(
        state[0] in emptyish for state in present.values()
    ):
        return (
            {
                "status": "compatibility-empty",
                "sources": list(present),
                "evidence": "multiple community sources agree the field is empty",
            },
            None,
            None,
        )

    if not present:
        return (
            {
                "status": "unresolved",
                "reason": "no-community-row-anywhere",
            },
            None,
            None,
        )

    return (
        {
            "status": "unresolved",
            "reason": "single-source-absence-only",
            "source": next(iter(present)),
            "class": next(iter(present.values()))[0],
        },
        None,
        None,
    )


def build_consensus_manifest(
    raw_71_rows: Mapping[int, Mapping[str, Any]],
    community_sources: Mapping[str, Mapping[int, Mapping[str, Any]]],
    *,
    raw_71_source: str,
    historical_tsv_rows: Mapping[int, Mapping[str, Any]] | None = None,
    historical_tsv_source: str | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    if len(community_sources) < 2:
        raise ValueError("community consensus requires at least two sources")

    historical_tsv_rows = historical_tsv_rows or {}
    if historical_tsv_rows and not historical_tsv_source:
        raise ValueError(
            "historical_tsv_source is required when historical_tsv_rows are provided"
        )

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
                        **_source_ref(
                            "same-version-client-projection",
                            raw_71_source,
                        ),
                        "raw_field": raw_key,
                        "evidence": "7.1 ordinary Quest retained field",
                    },
                }
                field_counts[field]["nonempty"] += 1
            else:
                field_counts[field]["empty"] += 1

        compat_tsv = historical_tsv_rows.get(sub_id)

        for field in COMPAT_FIELDS:
            status, consensus_value, chosen_source = _community_consensus(
                community_sources,
                sub_id=sub_id,
                field=field,
            )

            if status["status"] == "compatibility-value":
                assert consensus_value is not None
                row_fields[field] = {
                    "value": consensus_value,
                    "provenance": {
                        "kind": "community-consensus",
                        "status": "compatibility-only",
                        "source": chosen_source,
                        "consensus_sources": status["consensus_sources"],
                        "evidence": (
                            "all nonempty pinned community projections agree "
                            "after normalized comparison"
                        ),
                        "native_7_1": False,
                    },
                }

            base_status_name = status["status"]

            if compat_tsv is not None:
                tsv_class, value_tsv = _compat_class(
                    compat_tsv,
                    field=field,
                )
                if tsv_class == "nonempty":
                    if field in row_fields:
                        current = _comparison_value(
                            row_fields[field]["value"],
                            field=field,
                        )
                        if current == value_tsv:
                            provenance = row_fields[field]["provenance"]
                            provenance["historical_server_source"] = (
                                historical_tsv_source
                            )
                            provenance["historical_server_source_agrees"] = True
                            status["historical_server_source"] = (
                                historical_tsv_source
                            )
                            field_counts[field]["historical_tsv_support"] += 1
                        else:
                            row_fields.pop(field, None)
                            status = {
                                "status": "unresolved",
                                "reason": "historical-tsv-community-diverged",
                                "historical_tsv_source": historical_tsv_source,
                                "historical_tsv": value_tsv,
                                "community": current,
                            }
                            field_counts[field]["historical_tsv_conflict"] += 1
                    elif status.get("reason") in {
                        "no-community-row-anywhere",
                        "community-placeholder-only",
                        "single-source-absence-only",
                    }:
                        row_fields[field] = {
                            "value": _typed_entries(
                                compat_tsv.get(field),
                                field=field,
                            ),
                            "provenance": {
                                "kind": "historical-server-source",
                                "status": "compatibility-only",
                                "source": historical_tsv_source,
                                "evidence": (
                                    "direct GC leaked TSV column fills a "
                                    "community consensus gap"
                                ),
                                "native_7_1": False,
                            },
                        }
                        status = {
                            "status": "compatibility-value",
                            "source": historical_tsv_source,
                            "historical_server_source": True,
                        }
                        field_counts[field]["historical_tsv_value"] += 1
                    elif status["status"] == "compatibility-empty":
                        status = {
                            "status": "unresolved",
                            "reason": "historical-tsv-community-empty-diverged",
                            "historical_tsv_source": historical_tsv_source,
                            "historical_tsv": value_tsv,
                        }
                        field_counts[field]["historical_tsv_conflict"] += 1
                elif (
                    tsv_class in {"absent-key", "empty", "non-list"}
                    and field not in row_fields
                    and status.get("reason") in {
                        "no-community-row-anywhere",
                        "community-placeholder-only",
                        "single-source-absence-only",
                    }
                ):
                    status = {
                        "status": "compatibility-empty",
                        "source": historical_tsv_source,
                        "evidence": (
                            "historical leaked TSV row has no typed field entries"
                        ),
                        "native_7_1": False,
                    }
                    field_counts[field]["historical_tsv_empty"] += 1

            final_status_name = status["status"]
            count_key = {
                "unresolved": "unresolved",
                "compatibility-value": "compatibility_value",
                "compatibility-empty": "compatibility_empty",
            }
            final_key = count_key[final_status_name]
            field_counts[field][final_key] += 1

            row_status[field] = status
            if final_status_name == "unresolved":
                unresolved_out.setdefault(
                    str(sub_id),
                    {"subId": sub_id, "fields": {}},
                )
                unresolved_out[str(sub_id)]["fields"][field] = status

        rows_out[str(sub_id)] = {
            "subId": sub_id,
            "fields": row_fields,
            "missing_field_status": row_status,
        }

    sources = {
        "raw_7_1": _source_ref(
            "same-version-client-projection",
            raw_71_source,
        ),
        "community_consensus": {
            label: _source_ref("community-resource", label)
            for label in community_sources
        },
    }
    if historical_tsv_source:
        sources["historical_tsv"] = _source_ref(
            "historical-server-source",
            historical_tsv_source,
        )

    manifest = {
        "schema_version": 2,
        "target": "Genshin Impact 7.1 ordinary Quest field recovery",
        "policy": {
            "native_retained_fields": list(RAW_71_FIELD_KEYS),
            "compatibility_fields": list(COMPAT_FIELDS),
            "previous_row_synthesis": False,
            "quest_cond_unknown_is_placeholder": True,
            "community_nonempty_requires_value_consensus": True,
            "community_empty_requires_at_least_two_sources": True,
            "historical_tsv_is_native_7_1": False,
            "historical_tsv_conflicts_remain_unresolved": True,
        },
        "sources": sources,
        "summary": {
            "raw_7_1_rows": len(raw_71_rows),
            "community_sources": {
                label: len(rows)
                for label, rows in community_sources.items()
            },
            "historical_tsv_rows": len(historical_tsv_rows),
            "unresolved_rows": len(unresolved_out),
            "fields": {
                field: dict(counts)
                for field, counts in field_counts.items()
            },
        },
        "rows": rows_out,
    }
    unresolved = {
        "schema_version": 2,
        "target": manifest["target"],
        "sources": sources,
        "summary": {
            "rows": len(unresolved_out),
            "field_occurrences": sum(
                len(row["fields"]) for row in unresolved_out.values()
            ),
        },
        "rows": unresolved_out,
    }
    return manifest, unresolved


def build_consensus_from_directories(
    raw_71_root: Path,
    community_roots: Mapping[str, Path],
    *,
    raw_71_source: str,
    historical_tsv_root: Path | None = None,
    historical_tsv_source: str | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    return build_consensus_manifest(
        load_raw_71_rows(raw_71_root),
        {
            label: load_community_rows(root)
            for label, root in community_roots.items()
        },
        raw_71_source=raw_71_source,
        historical_tsv_rows=(
            load_community_rows(historical_tsv_root)
            if historical_tsv_root is not None
            else None
        ),
        historical_tsv_source=historical_tsv_source,
    )


def build_from_directories(
    raw_71_root: Path,
    community_71_root: Path,
    community_70_root: Path,
    *,
    raw_71_source: str,
    community_71_source: str,
    community_70_source: str,
    historical_tsv_root: Path | None = None,
    historical_tsv_source: str | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    return build_manifest(
        load_raw_71_rows(raw_71_root),
        load_community_rows(community_71_root),
        load_community_rows(community_70_root),
        raw_71_source=raw_71_source,
        community_71_source=community_71_source,
        community_70_source=community_70_source,
        historical_tsv_rows=(
            load_community_rows(historical_tsv_root)
            if historical_tsv_root is not None
            else None
        ),
        historical_tsv_source=historical_tsv_source,
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
    parser.add_argument("--historical-tsv-root", type=Path)
    parser.add_argument("--historical-tsv-source")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--unresolved-output", type=Path, required=True)
    args = parser.parse_args(list(argv) if argv is not None else None)
    if (args.historical_tsv_root is None) != (args.historical_tsv_source is None):
        parser.error(
            "--historical-tsv-root and --historical-tsv-source must be provided together"
        )

    manifest, unresolved = build_from_directories(
        args.raw_7_1_root,
        args.community_7_1_root,
        args.community_7_0_root,
        raw_71_source=args.raw_7_1_source,
        community_71_source=args.community_7_1_source,
        community_70_source=args.community_7_0_source,
        historical_tsv_root=args.historical_tsv_root,
        historical_tsv_source=args.historical_tsv_source,
    )
    _write_json(args.output, manifest)
    _write_json(args.unresolved_output, unresolved)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())