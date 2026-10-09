"""Join Dungeon source rows to drop graphs without interpreting reward semantics."""
from __future__ import annotations

from collections import Counter

WEEKDAYS = ("monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday")


def _index(rows: list[dict], label: str) -> dict[int, dict]:
    result = {row["id"]: row for row in rows}
    if len(result) != len(rows):
        raise ValueError(f"duplicate {label} ID")
    return result


def collect_dungeon_drop_links(
    dungeons: list[dict], drops: list[dict], subtables: list[dict],
    schedules: list[dict],
) -> dict:
    """Preserve pointers, missing roots, nested nodes and explicit weekday membership.

    A terminal ID means only that neither drop table contains it. It does not
    establish inventory-item identity or completeness of the source graph.
    """
    _index(dungeons, "dungeon")
    roots = _index(drops, "DropTable")
    subnodes = _index(subtables, "DropSubTable")
    if roots.keys() & subnodes.keys():
        raise ValueError("ambiguous drop node ID across tables")
    schedule_by_id = _index(schedules, "schedule")
    memberships: dict[int, list[dict]] = {}
    for schedule_id, row in sorted(schedule_by_id.items()):
        days_by_dungeon: dict[int, list[str]] = {}
        for day in WEEKDAYS:
            for dungeon_id in row.get(day, []):
                if dungeon_id in days_by_dungeon and day in days_by_dungeon[dungeon_id]:
                    raise ValueError("duplicate weekday dungeon reference")
                days_by_dungeon.setdefault(dungeon_id, []).append(day)
        for dungeon_id, days in days_by_dungeon.items():
            memberships.setdefault(dungeon_id, []).append({
                "dailyDungeonConfigId": schedule_id, "weekdays": days,
            })

    visited: set[int] = set()
    active: set[int] = set()

    def visit(node_id: int) -> None:
        if node_id in active:
            raise ValueError(f"cyclic drop node {node_id}")
        if node_id in visited:
            return
        active.add(node_id)
        node = roots.get(node_id) or subnodes[node_id]
        for entry in node["dropVec"]:
            child = entry["itemId"]
            if child <= 0:
                raise ValueError(f"invalid drop target {child}")
            if child in roots or child in subnodes:
                visit(child)
        active.remove(node_id)
        visited.add(node_id)

    domains = []
    for row in sorted(dungeons, key=lambda x: x["id"]):
        if row.get("type") not in ("DUNGEON_DAILY_FIGHT", "DUNGEON_BOSS"):
            continue
        pointer = row.get("IAOMJCLOIEL") or None
        status = ("NO_POINTER" if pointer is None else
                  "ROOT_PRESENT" if pointer in roots else "ROOT_MISSING")
        if status == "ROOT_PRESENT":
            visit(pointer)
        domains.append({
            "dungeonId": row["id"], "type": row["type"],
            "subType": row.get("subType"), "cityId": row.get("cityID"),
            "sceneId": row.get("sceneId"), "showLevel": row.get("showLevel"),
            "limitLevel": row.get("limitLevel"),
            "passRewardPreviewId": row.get("passRewardPreviewID"),
            "baseResinCostItemId": row.get("statueCostID"),
            "baseResinCostCount": row.get("statueCostCount"),
            "rootDropId": pointer, "rootStatus": status,
            "scheduleReferences": memberships.get(row["id"], []),
        })

    nodes = []
    for node_id in sorted(visited):
        row = roots.get(node_id) or subnodes[node_id]
        nodes.append({
            "id": node_id,
            "table": ("DropTableExcelConfigData" if node_id in roots
                      else "DropSubTableExcelConfigData"),
            "randomType": row["randomType"], "dropLevel": row["dropLevel"],
            "nodeType": row["nodeType"], "sourceType": row.get("sourceType"),
            "dropVec": [{
                "itemId": item["itemId"], "countRange": item["countRange"],
                "weight": item["weight"],
                "targetKind": ("DROP_NODE" if item["itemId"] in roots or
                               item["itemId"] in subnodes else "TERMINAL_ID"),
            } for item in row["dropVec"]],
        })
    by_subtype = {}
    for subtype in sorted({d["subType"] or "UNCLASSIFIED" for d in domains}):
        selected = [d for d in domains if (d["subType"] or "UNCLASSIFIED") == subtype]
        statuses = Counter(d["rootStatus"] for d in selected)
        by_subtype[subtype] = {
            "dungeonRows": len(selected),
            "resolvedRootCount": statuses["ROOT_PRESENT"],
            "missingRootCount": statuses["ROOT_MISSING"],
            "noPointerCount": statuses["NO_POINTER"],
            "scheduleReferencedRows": sum(bool(d["scheduleReferences"]) for d in selected),
        }
    return {
        "summary": {
            "dungeonRows": len(domains), "bySubType": by_subtype,
            "reachableDropTableNodes": sum(n["table"] == "DropTableExcelConfigData" for n in nodes),
            "reachableDropSubTableNodes": sum(n["table"] == "DropSubTableExcelConfigData" for n in nodes),
            "unresolvedRoots": [{"dungeonId": d["dungeonId"], "rootDropId": d["rootDropId"],
                                 "status": d["rootStatus"]}
                                for d in domains if d["rootStatus"] != "ROOT_PRESENT"],
            "unmatchedScheduleDungeonIds": sorted(memberships.keys() - {d["dungeonId"] for d in domains}),
        },
        "domains": domains, "dropNodes": nodes,
    }
