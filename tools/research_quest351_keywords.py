from __future__ import annotations

import csv
import json
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
META = ROOT / "versions/7.1.0-global/windows-x64/metadata"
OUT = ROOT / "quest351-keyword-sweep.json"

KEYWORDS = (
    "quest",
    "rewind",
    "tracking",
    "navigation",
    "navigate",
    "servercond",
    "born",
    "transmit",
    "backbutton",
    "paimon",
)

# Named types/fields that survived obfuscation in the exact 7.1 metadata and are
# directly relevant to issue #9.  Keep this list narrow so the research report
# answers ownership questions instead of becoming another global metadata dump.
TARGET_TYPE_NAMES = {
    "UserLocalDataItem",
    "QuestProxy",
    "MonoReturnToQuestBtn",
    "MonoInLevelMainPage",
}
TARGET_FIELD_NAMES = {
    "trackingMainQuestIDList",
    "ReturnToQuestEvent",
    "ToggleQuestTrackingEvent",
}


def hit(text: str) -> list[str]:
    folded = text.casefold()
    return [word for word in KEYWORDS if word in folded]


def main() -> None:
    type_hits: list[dict[str, object]] = []
    interesting_type_ids: set[int] = set()
    named_type_ids: dict[str, int] = {}
    type_rows: dict[int, dict[str, object]] = {}
    with (META / "types.csv").open("r", encoding="utf-8-sig", newline="") as f:
        for row in csv.DictReader(f):
            idx = int(row["type_definition_index"])
            type_name = row.get("type_name", "")
            type_rows[idx] = {
                "type_definition_index": idx,
                "namespace": row.get("namespace", ""),
                "type_name": type_name,
                "field_count": int(row.get("field_count") or 0),
                "method_count": int(row.get("method_count") or 0),
                "method_start": int(row.get("method_start") or -1),
            }
            if type_name in TARGET_TYPE_NAMES:
                named_type_ids[type_name] = idx
            hay = f"{row.get('namespace','')} {type_name}"
            words = hit(hay)
            if not words:
                continue
            interesting_type_ids.add(idx)
            item = dict(type_rows[idx])
            item["keywords"] = words
            type_hits.append(item)

    method_hits: list[dict[str, object]] = []
    methods_by_interesting_type: dict[int, list[dict[str, object]]] = defaultdict(list)
    methods_by_owner: dict[int, list[dict[str, object]]] = defaultdict(list)
    parameter_type_hits: list[dict[str, object]] = []
    target_type_method_refs: list[dict[str, object]] = []
    with (META / "methods.csv").open("r", encoding="utf-8-sig", newline="") as f:
        for row in csv.DictReader(f):
            owner_raw = row.get("type_definition_index", "")
            owner = int(owner_raw) if owner_raw else -1
            name = row.get("method_name", "")
            words = hit(name)
            params = json.loads(row.get("parameter_types") or "[]")
            return_type = row.get("return_type", "")
            param_words = sorted({w for p in params for w in hit(str(p))})
            item = {
                "method_index": int(row["method_index"]),
                "type_definition_index": owner,
                "type_name": row.get("type_name", ""),
                "method_name": name,
                "rva": row.get("rva", ""),
                "parameter_count": int(row.get("parameter_count") or 0),
                "parameter_types": params,
                "parameter_type_indices": json.loads(row.get("parameter_type_indices") or "[]"),
                "return_type": return_type,
            }
            methods_by_owner[owner].append(item)
            if words:
                named = dict(item)
                named["keywords"] = words
                method_hits.append(named)
            if param_words:
                p = dict(item)
                p["keywords"] = param_words
                parameter_type_hits.append(p)
            if owner in interesting_type_ids:
                methods_by_interesting_type[owner].append(item)
            referenced = sorted(
                target
                for target in TARGET_TYPE_NAMES
                if target == return_type or any(target == str(param) for param in params)
            )
            if referenced:
                ref = dict(item)
                ref["referenced_target_types"] = referenced
                target_type_method_refs.append(ref)

    field_hits: list[dict[str, object]] = []
    target_type_field_refs: list[dict[str, object]] = []
    target_named_fields: list[dict[str, object]] = []
    field_ref_owner_ids: set[int] = set()
    with (META / "fields.csv").open("r", encoding="utf-8-sig", newline="") as f:
        for row in csv.DictReader(f):
            owner = int(row["type_definition_index"]) if row.get("type_definition_index") else -1
            field_name = row.get("field_name", "")
            field_type = row.get("field_type", "")
            base = {
                "field_index": int(row["field_index"]),
                "type_definition_index": owner,
                "type_name": row.get("type_name", ""),
                "field_name": field_name,
                "field_type": field_type,
                "field_type_index": int(row["field_type_index"]) if row.get("field_type_index") else -1,
            }
            words = sorted(set(hit(field_name) + hit(field_type)))
            if words:
                item = dict(base)
                item["keywords"] = words
                field_hits.append(item)
            if field_type in TARGET_TYPE_NAMES:
                item = dict(base)
                item["referenced_target_type"] = field_type
                target_type_field_refs.append(item)
                field_ref_owner_ids.add(owner)
            if field_name in TARGET_FIELD_NAMES:
                target_named_fields.append(dict(base))
                field_ref_owner_ids.add(owner)

    # If a manager/controller owns UserLocalDataItem or one of the target event
    # fields, include all its methods.  This gives the next native pass a small
    # list of concrete RVAs to disassemble.
    field_ref_owner_methods = {
        str(owner): {
            "type": type_rows.get(owner),
            "methods": methods_by_owner.get(owner, []),
        }
        for owner in sorted(field_ref_owner_ids)
    }

    payload = {
        "keywords": KEYWORDS,
        "target_type_names": sorted(TARGET_TYPE_NAMES),
        "named_type_ids": named_type_ids,
        "target_field_names": sorted(TARGET_FIELD_NAMES),
        "type_hits": type_hits,
        "method_name_hits": method_hits,
        "parameter_type_hits": parameter_type_hits,
        "field_hits": field_hits,
        "methods_for_semantic_type_hits": methods_by_interesting_type,
        "target_type_method_refs": target_type_method_refs,
        "target_type_field_refs": target_type_field_refs,
        "target_named_fields": target_named_fields,
        "field_ref_owner_methods": field_ref_owner_methods,
    }
    OUT.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    print(
        f"type_hits={len(type_hits)} method_name_hits={len(method_hits)} "
        f"parameter_type_hits={len(parameter_type_hits)} field_hits={len(field_hits)} "
        f"target_method_refs={len(target_type_method_refs)} "
        f"target_field_refs={len(target_type_field_refs)} "
        f"target_named_fields={len(target_named_fields)}"
    )
    print("\nTARGET TYPE IDS")
    print(json.dumps(named_type_ids, ensure_ascii=False, sort_keys=True))
    print("\nTARGET NAMED FIELDS")
    for row in target_named_fields:
        print(json.dumps(row, ensure_ascii=False, separators=(",", ":")))
    print("\nTARGET TYPE FIELD REFS")
    for row in target_type_field_refs:
        print(json.dumps(row, ensure_ascii=False, separators=(",", ":")))
    print("\nTARGET TYPE METHOD REFS")
    for row in target_type_method_refs:
        print(json.dumps(row, ensure_ascii=False, separators=(",", ":")))


if __name__ == "__main__":
    main()
