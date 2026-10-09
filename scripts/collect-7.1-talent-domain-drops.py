#!/usr/bin/env python3
"""Collect pinned 7.1 talent-Domain drop-node evidence (not runtime drop rates)."""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from genshinre.dungeondrops import collect_dungeon_drop_links
OUTPUT = ROOT / "versions/7.1.0-global/analyses/progression/economy/7.1-talent-domain-drop-links.json"
REPOSITORY = "RinoPaw/AstaPS-Resource"
COMMIT = "b0f3a2791607cab2a4c24cb9ef249dd2d94d7ffd"
BLOBS = {
    "ExcelBinOutput/DungeonExcelConfigData.json": "92983c5d9d46bccf486b803b7cf65f2cdf9088cb",
    "Server/DropTableExcelConfigData.json": "b46d383b535babd1be6b95e3ea031eef64d1fdfd",
    "Server/DropSubTableExcelConfigData.json": "9397fb0b15c8c4cc82194ec429682f2ef4333767",
    "Server/DropMaterialExcelConfigData.json": "5be570af7dca96d9512d523f63b67e880009d4e1",
    "ExcelBinOutput/DungeonEntryExcelConfigData.json": "e7a92f6df718148fad4dee47a691700407b1ddcf",
    "ExcelBinOutput/RewardPreviewExcelConfigData.json": "a72b299e29c19007c48ed78b2e11aa33e274f98c",
}
SCOPE = ("source-row joins only: DungeonExcelConfigData.IAOMJCLOIEL -> "
         "Server/DropTableExcelConfigData.id; nested nodes via "
         "Server/DropSubTableExcelConfigData; no runtime/probability assertion")


def read_pinned(root: Path) -> tuple[dict[str, list[dict]], dict[str, dict]]:
    rows, evidence = {}, {}
    for filename, expected in BLOBS.items():
        raw = (root / filename).read_bytes()
        actual = hashlib.sha1(
            b"blob " + str(len(raw)).encode("ascii") + b"\0" + raw
        ).hexdigest()
        if actual != expected:
            raise ValueError(f"{filename}: Git blob SHA {actual} != {expected}")
        data = json.loads(raw)
        if not isinstance(data, list):
            raise ValueError(f"{filename}: expected JSON array")
        rows[filename] = data
        evidence[filename] = {"gitBlobSha": actual, "rowCount": len(data)}
    return rows, evidence


def build_snapshot(rows: dict[str, list[dict]], evidence: dict[str, dict]) -> dict:
    dungeons = rows["ExcelBinOutput/DungeonExcelConfigData.json"]
    table = rows["Server/DropTableExcelConfigData.json"]
    sub = rows["Server/DropSubTableExcelConfigData.json"]
    roots = {r["id"]: r for r in table}
    subnodes = {r["id"]: r for r in sub}
    if len(roots) != len(table) or len(subnodes) != len(sub):
        raise ValueError("duplicate drop node ID")

    targets = sorted(
        (r for r in dungeons
         if r.get("type") == "DUNGEON_DAILY_FIGHT"
         and r.get("subType") == "DUNGEON_SUB_TALENT"),
        key=lambda r: r["id"],
    )
    domains = [{
        "dungeonId": r["id"],
        "cityId": r["cityID"],
        "showLevel": r["showLevel"],
        "limitLevel": r["limitLevel"],
        "passRewardPreviewId": r["passRewardPreviewID"],
        "baseResinCostItemId": r["statueCostID"],
        "baseResinCostCount": r["statueCostCount"],
        "rootDropId": r["IAOMJCLOIEL"],
        "rootPresent": r["IAOMJCLOIEL"] in roots,
    } for r in targets]
    # Family ownership is inferred from an exact, unique advertised-material join.
    # This is not a foreign key or confirmation of weekday/runtime selection.
    entry_rows = sorted(
        (r for r in rows["ExcelBinOutput/DungeonEntryExcelConfigData.json"]
         if r.get("type") == "DUNGEN_ENTRY_TYPE_AVATAR_TALENT"),
        key=lambda r: r["id"],
    )
    # The pinned table includes one empty-drop sentinel without an ID.
    preview_rows = rows["ExcelBinOutput/RewardPreviewExcelConfigData.json"]
    previews = {r["id"]: r for r in preview_rows if r.get("id")}
    if len(previews) != sum(bool(r.get("id")) for r in preview_rows):
        raise ValueError("duplicate preview ID")
    entry_links = [{
        "entryExcelId": e["id"], "entryGadgetId": e["dungeonEntryId"],
        "sceneId": e["sceneId"],
        "materialCycleIds": e["descriptionCycleRewardList"][:3],
        "dungeonIds": [],
    } for e in entry_rows]
    for domain in domains:
        advertised = previews[domain["passRewardPreviewId"]]["previewItems"]
        matches = [
            e for e in entry_links
            if any(v.get("id") in {x for xs in e["materialCycleIds"] for x in xs}
                   for v in advertised)
        ]
        if len(matches) != 1:
            raise ValueError(f"dungeon {domain['dungeonId']}: {len(matches)} entry owners")
        matched = matches[0]
        matched["dungeonIds"].append(domain["dungeonId"])
        valid_items = {x for xs in matched["materialCycleIds"] for x in xs}
        domain["entryExcelId"] = matched["entryExcelId"]
        domain["previewTalentMaterialIds"] = list(dict.fromkeys(
            x["id"] for x in advertised if x.get("id") in valid_items
        ))
    if [len(e["dungeonIds"]) for e in entry_links] != [16, 16, 12, 12, 12, 12, 12, 12]:
        raise ValueError("unexpected talent entry distribution")

    if len({d["dungeonId"] for d in domains}) != len(domains):
        raise ValueError("duplicate dungeon ID")
    if any(d["baseResinCostItemId"] != 106
           or d["baseResinCostCount"] != 20 for d in domains):
        raise ValueError("unrecognized pinned cost")

    material_rows = rows["Server/DropMaterialExcelConfigData.json"]
    material_ids = {r["id"] for r in material_rows}
    if len(material_ids) != len(material_rows):
        raise ValueError("duplicate drop material ID")

    # Reuse the maintained graph traversal; keep this focused snapshot schema.
    graph = collect_dungeon_drop_links(targets, table, sub, [])
    nodes = [{**node, "dropVec": [
        {key: value for key, value in edge.items() if key != "targetKind"}
        for edge in node["dropVec"]
    ]} for node in graph["dropNodes"]]
    # Follow both node types through to validated terminal inventory items.
    node_map = {n["id"]: n for n in nodes}

    def collect_terminal_ids(root_id: int) -> list[int]:
        terminals: set[int] = set()
        active: set[int] = set()

        def walk(node_id: int) -> None:
            if node_id in active:
                raise ValueError(f"cyclic terminal chain at {node_id}")
            active.add(node_id)
            for edge in node_map[node_id]["dropVec"]:
                item_id = edge["itemId"]
                if item_id in node_map:
                    walk(item_id)
                else:
                    if item_id not in material_ids:
                        raise ValueError(f"unknown terminal drop material {item_id}")
                    terminals.add(item_id)
            active.remove(node_id)

        walk(root_id)
        return sorted(terminals)

    distinct_terminals: set[int] = set()
    for domain in domains:
        material_list = (collect_terminal_ids(domain["rootDropId"])
                         if domain["rootPresent"] else [])
        domain["terminalItemIds"] = material_list
        if domain["rootPresent"]:
            display_ids = {x.get("id") for x in
                           previews[domain["passRewardPreviewId"]]["previewItems"]}
            if not set(material_list).issubset(display_ids):
                raise ValueError(f"terminal material missing from preview: {domain['dungeonId']}")
        distinct_terminals.update(material_list)

    resolved = sum(d["rootPresent"] for d in domains)
    missing_ids = [d["rootDropId"] for d in domains if not d["rootPresent"]]
    summary = {
        "talentDungeonRows": len(domains),
        "resolvedRootCount": resolved,
        "missingRootCount": len(missing_ids),
        "reachableDropTableNodes": sum(
            n["table"] == "DropTableExcelConfigData" for n in nodes
        ),
        "reachableDropSubTableNodes": sum(
            n["table"] == "DropSubTableExcelConfigData" for n in nodes
        ),
        "unresolvedRootIds": missing_ids,
        "talentEntryRows": len(entry_links),
        "validatedTerminalMaterialIds": len(distinct_terminals),
        "terminalMaterialIdsMissingInPreview": 0,
    }
    if (
        summary["talentDungeonRows"],
        summary["resolvedRootCount"],
        summary["missingRootCount"],
        summary["reachableDropTableNodes"],
        summary["reachableDropSubTableNodes"],
    ) != (104, 56, 48, 112, 6) or len(distinct_terminals) != 39:
        raise ValueError("pinned source coverage changed unexpectedly")

    return {
        "schemaVersion": 1,
        "target": "Genshin Impact 7.1.0 Global",
        "scope": SCOPE,
        "source": {
            "repository": REPOSITORY,
            "commit": COMMIT,
            "files": evidence,
        },
        "summary": summary,
        "domains": domains,
        "dropNodes": nodes,
        "entries": entry_links,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--resource-root", required=True, type=Path,
                        help="unaltered AstaPS-Resource checkout with ExcelBinOutput/ and Server/")
    parser.add_argument("--output", type=Path, default=OUTPUT)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    rows, evidence = read_pinned(args.resource_root)
    result = build_snapshot(rows, evidence)
    if args.check:
        if json.loads(args.output.read_text(encoding="utf-8")) != result:
            raise SystemExit("talent-Domain source joins differ from snapshot")
        print("PASS: pinned 7.1 talent-Domain drop joins")
    else:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(
            json.dumps(result, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        print(f"Wrote {args.output}")


if __name__ == "__main__":
    main()
