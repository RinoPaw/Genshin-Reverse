#!/usr/bin/env python3
"""Audit explicit 3-vs-4 affix item branches in the pinned 7.1 resource drop graph.

This classifies raw *configured* edges. It does not establish the original
DropTable extraction provenance, selection semantics, or live 7.1 probabilities.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DROP_INPUT = ROOT / "versions/7.1.0-global/analyses/progression/economy/7.1-domain-drop-links.json"
RELIC_INPUT = ROOT / "versions/7.1.0-global/windows-x64/analyses/artifact-generation/7.1-reliquary-depot-topology.json"
OUTPUT = ROOT / "versions/7.1.0-global/windows-x64/analyses/artifact-generation/7.1-reliquary-drop-variant-weights.json"

# Pin derived snapshots, each of which already identifies the unmodified
# original Resource Git blobs it was generated from.
SNAPSHOT_BLOBS = {
    "dropGraph": "b5686edf379c01f8a2d1cd323c9a9bf82628e558",
    "reliquaryTopology": "345d4c96803605509cc55e485b4a5f30f35453c0",
}
RESOURCE_COMMIT = "b0f3a2791607cab2a4c24cb9ef249dd2d94d7ffd"
RESOURCE_BLOBS = {
    "dropTable": "b46d383b535babd1be6b95e3ea031eef64d1fdfd",
    "dropSubTable": "9397fb0b15c8c4cc82194ec429682f2ef4333767",
    "reliquaryExcel": "dc617e939a0ad4864f88e32dbf98ace9ac11649f",
}


def load_snapshot(path: Path, expected: str) -> dict:
    raw = path.read_bytes()
    actual = hashlib.sha1(f"blob {len(raw)}\0".encode("ascii") + raw).hexdigest()
    if actual != expected:
        raise ValueError(f"{path}: Git blob {actual} != pinned {expected}")
    return json.loads(raw)


def leaf_ids(node_id: int, nodes: dict[int, dict],
             cache: dict[int, frozenset[int]], active: set[int] | None = None
             ) -> frozenset[int]:
    if node_id in cache:
        return cache[node_id]
    if active is None:
        active = set()
    if node_id in active:
        raise ValueError(f"drop graph cycle at {node_id}")
    node = nodes.get(node_id)
    if node is None:
        raise ValueError(f"missing drop node {node_id}")
    active.add(node_id)
    out: set[int] = set()
    for item in node.get("dropVec", []):
        if item["targetKind"] == "TERMINAL_ID":
            out.add(item["itemId"])
        elif item["targetKind"] == "DROP_NODE":
            out.update(leaf_ids(item["itemId"], nodes, cache, active))
        else:
            raise ValueError(f"unknown drop edge kind {item['targetKind']}")
    active.remove(node_id)
    cache[node_id] = frozenset(out)
    return cache[node_id]


def reachable_nodes(root: int, nodes: dict[int, dict]) -> set[int]:
    seen = set()
    stack = [root]
    while stack:
        node_id = stack.pop()
        if node_id in seen:
            continue
        seen.add(node_id)
        node = nodes.get(node_id)
        if node is None:
            raise ValueError(f"missing drop node {node_id}")
        stack.extend(
            e["itemId"] for e in node.get("dropVec", [])
            if e["targetKind"] == "DROP_NODE"
        )
    return seen


def classify_initial_affix_branch(node: dict, nodes: dict[int, dict],
                                  items: dict[int, dict],
                                  leaf_cache: dict[int, frozenset[int]]
                                  ) -> dict | None:
    """Identify one 3/4-only split, independent of probability interpretation."""
    edges = node.get("dropVec", [])
    if node.get("randomType") != 0 or len(edges) != 2:
        return None
    if any(e["targetKind"] != "DROP_NODE" for e in edges):
        return None

    branches = []
    for e in edges:
        leafs = sorted(leaf_ids(e["itemId"], nodes, leaf_cache))
        # Fail closed: do not mistake a mixed-item drop node for a reliquary split.
        if not leafs or any(item_id not in items for item_id in leafs):
            return None
        rows = [items[item_id] for item_id in leafs]
        variants = {row["appendPropNum"] for row in rows}
        if len(variants) != 1 or next(iter(variants)) not in (3, 4):
            return None
        if any(row["rarity"] != 5 or row["appendPropDepotId"] != 501 for row in rows):
            return None
        branches.append({
            "initialSubstatCount": next(iter(variants)),
            "childNodeId": e["itemId"],
            "configuredWeight": e["weight"],
            "itemIds": leafs,
        })

    if {b["initialSubstatCount"] for b in branches} != {3, 4}:
        return None
    branches.sort(key=lambda b: b["initialSubstatCount"])
    return {"nodeId": node["id"], "randomType": node["randomType"], "branches": branches}


def build_snapshot(drop: dict, topology: dict) -> dict:
    for data, name in [(drop, "Dungeon DropTable"), (topology, "Reliquary")]:
        if data["source"]["commit"] != RESOURCE_COMMIT:
            raise ValueError(f"{name}: source commit changed")
    src_drop = drop["source"]["files"]
    src_relic = topology["source"]["files"]
    if (src_drop["Server/DropTableExcelConfigData.json"]["gitBlobSha"] != RESOURCE_BLOBS["dropTable"] or
            src_drop["Server/DropSubTableExcelConfigData.json"]["gitBlobSha"] != RESOURCE_BLOBS["dropSubTable"] or
            src_relic["ReliquaryExcelConfigData.json"]["gitBlobSha"] != RESOURCE_BLOBS["reliquaryExcel"]):
        raise ValueError("pinned original source identity changed")

    nodes = {n["id"]: n for n in drop["dropNodes"]}
    items = {i["itemId"]: i for i in topology["reliquaries"]}
    if len(nodes) != len(drop["dropNodes"]) or len(items) != len(topology["reliquaries"]):
        raise ValueError("duplicate node or Reliquary ID")

    cache: dict[int, frozenset[int]] = {}
    variants = [
        row for node in nodes.values()
        if (row := classify_initial_affix_branch(node, nodes, items, cache)) is not None
    ]
    variants.sort(key=lambda x: x["nodeId"])
    branch_ids = {row["nodeId"] for row in variants}
    for row in variants:
        branches = row["branches"]
        if ([b["initialSubstatCount"] for b in branches] != [3, 4] or
                [b["configuredWeight"] for b in branches] != [8000, 2000] or
                any(len(b["itemIds"]) != 10 for b in branches)):
            raise ValueError(f"unexpected 3/4 branch data at {row['nodeId']}")

    domains = [d for d in drop["domains"]
               if d["subType"] == "DUNGEON_SUB_RELIQUARY"]
    present = [d for d in domains if d["rootStatus"] == "ROOT_PRESENT"]
    reachable: dict[int, list[int]] = {}
    classified = []
    for d in sorted(present, key=lambda row: row["dungeonId"]):
        nodes_seen = reachable_nodes(d["rootDropId"], nodes)
        hits = sorted(nodes_seen & branch_ids)
        relics = [items[x] for x in leaf_ids(d["rootDropId"], nodes, cache) if x in items]
        rarity_set = sorted({item["rarity"] for item in relics})
        classified.append({
            "dungeonId": d["dungeonId"],
            "rootDropId": d["rootDropId"],
            "reachableReliquaryRarities": rarity_set,
            "initialThreeFourBranchNodeIds": hits,
        })
        for id_ in hits:
            reachable.setdefault(id_, []).append(d["dungeonId"])

    for row in variants:
        row["reachableDungeonIds"] = reachable.get(row["nodeId"], [])
        if not row["reachableDungeonIds"]:
            raise ValueError(f"variant node {row['nodeId']} not reached by a Dungeon")

    with_split = [d for d in classified if d["initialThreeFourBranchNodeIds"]]
    without_split = [d for d in classified if not d["initialThreeFourBranchNodeIds"]]
    if (len(domains), len(present), len(variants), len(with_split),
            len(without_split), len(reachable)) != (98, 54, 27, 27, 27, 27):
        raise ValueError("unexpected pinned 7.1 domain coverage")
    if any(len(d["initialThreeFourBranchNodeIds"]) != 1 for d in with_split):
        raise ValueError("expected one selected branch per reachable domain")
    if any(5 not in d["reachableReliquaryRarities"] for d in with_split):
        raise ValueError("3/4 branch found in a source path without 5-star reliquaries")
    if any(5 in d["reachableReliquaryRarities"] for d in without_split):
        raise ValueError("5-star source path without a corresponding 3/4 branch")
    rarities = Counter("/".join(map(str, d["reachableReliquaryRarities"]))
                       for d in classified)
    if dict(sorted(rarities.items())) != {
        "1/2/3": 1, "2/3": 5, "3/4": 21, "3/4/5": 27,
    }:
        raise ValueError("unexpected domain source rarity coverage")

    return {
        "schemaVersion": 1,
        "target": "Genshin Impact 7.1.0 Global resource integration",
        "scope": (
            "Raw DropTable configured weights and Reliquary item-ID crosswalk; "
            "no proof of original DropTable extraction, runtime randomType semantics "
            "or authoritative 7.1 server behavior"
        ),
        "source": {
            "repository": "RinoPaw/Genshin-Reverse",
            "inputGitBlobs": SNAPSHOT_BLOBS,
            "resourceRepository": "RinoPaw/AstaPS-Resource",
            "resourceCommit": RESOURCE_COMMIT,
            "resourceGitBlobs": RESOURCE_BLOBS,
        },
        "summary": {
            "artifactDungeonRows": len(domains),
            "resolvedRootCount": len(present),
            "missingRootCount": len(domains) - len(present),
            "configuredThreeFourBranchNodeCount": len(variants),
            "resolvedDomainsWithThreeFourBranch": len(with_split),
            "resolvedDomainsWithoutThreeFourBranch": len(without_split),
            "resolvedDomainRarityFamilies": dict(sorted(rarities.items())),
            "threeCountBranchWeight": 8000,
            "fourCountBranchWeight": 2000,
            "requiresRandomTypeSemanticsToCallProbability": True,
        },
        "variantBranches": variants,
        "resolvedArtifactDungeons": classified,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--drop", type=Path, default=DROP_INPUT)
    parser.add_argument("--reliquary", type=Path, default=RELIC_INPUT)
    parser.add_argument("--output", type=Path, default=OUTPUT)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    drop = load_snapshot(args.drop, SNAPSHOT_BLOBS["dropGraph"])
    relic = load_snapshot(args.reliquary, SNAPSHOT_BLOBS["reliquaryTopology"])
    output = build_snapshot(drop, relic)
    if args.check:
        if json.loads(args.output.read_text(encoding="utf-8")) != output:
            raise SystemExit("configured 7.1 Reliquary drop variant snapshot changed")
        print("PASS: 27 configured 8000:2000 split nodes across 27 source artifact Domains")
    else:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(output, ensure_ascii=False, indent=2) + "\n",
                               encoding="utf-8")
        print(f"Wrote {args.output}")


if __name__ == "__main__":
    main()
