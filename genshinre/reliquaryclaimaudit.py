"""Source-pinned check of 7.1 relic preview display IDs versus payable relic IDs.

The current server compares native artifact leaf families with actual ITEM_RELIQUARY
preview IDs, but 7.1 artifact previews contain ITEM_DISPLAY entries instead.
This is a static consumer prediction, not a native drop-rate measurement.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

ECONOMY = Path(__file__).resolve().parents[1] / "versions/7.1.0-global/analyses/progression/economy"
RESOURCE_PIN = "b0f3a2791607cab2a4c24cb9ef249dd2d94d7ffd"
DISPLAY_BLOB = "39e922b84bb42781765868d4efb7d5700967f061"
RELIQUARY_BLOB = "dc617e939a0ad4864f88e32dbf98ace9ac11649f"
GRAPH_BLOB = "b5686edf379c01f8a2d1cd323c9a9bf82628e558"
PREVIEW_BLOB = "8f662184de522c2548bbbdab44d418e4e17e3fed"
CURRENT_AUDIT_BLOB = "c30d3de71e84dc0e7afe1891f8dea05091d96a24"
OUTPUT = ECONOMY / "7.1-artifact-native-only-claim-audit.json"


def git_blob(data: bytes) -> str:
    return hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()


def read_pinned(path: Path, blob: str):
    raw = path.read_bytes()
    if git_blob(raw) != blob:
        raise ValueError(f"{path}: wrong source blob (expected {blob})")
    return json.loads(raw)


def positive_leaves(root: int, nodes: dict[int, dict]) -> list[int]:
    """Walk both DropTable and DropSubTable; only positive-weight paths are payable."""
    result: set[int] = set()

    def visit(node_id: int, active: frozenset[int]) -> None:
        if node_id in active:
            raise ValueError(f"cycle at drop node {node_id}")
        node = nodes.get(node_id)
        if node is None:
            result.add(node_id)
            return
        for entry in node["dropVec"]:
            if entry["weight"] > 0:
                visit(entry["itemId"], active | {node_id})

    visit(root, frozenset())
    return sorted(result)


def investigate(graph: dict, previews: dict, current: dict,
                display_rows: list[dict], reliquary_rows: list[dict]) -> list[dict]:
    if current["source"]["server"]["commit"] != "1c2cb79444ae911baf1fb8a11875ac32ae9783c4":
        raise ValueError("unknown AstaPS consumer revision")
    nodes = {item["id"]: item for item in graph["dropNodes"]}
    preview_map = {item["dungeonId"]: item for item in previews["dungeons"]}
    display = {item["id"]: item for item in display_rows}
    relics = {item["id"]: item for item in reliquary_rows
              if item.get("itemType") == "ITEM_RELIQUARY"}
    output = []
    for row in current["dungeons"]:
        if not (row["subType"] == "DUNGEON_SUB_RELIQUARY"
                and row["staticClaimRoute"] == "NATIVE_ONLY_CANDIDATE"):
            continue
        dungeon_id = row["dungeonId"]
        if row["sourceRootStatus"] != "ROOT_PRESENT" or not row["proxyIssues"]:
            raise ValueError(f"{dungeon_id}: unexpected source state")
        preview_ids = [p["itemId"] for p in preview_map[dungeon_id]["previewItems"]
                       if p["itemId"] > 0]
        display_ids = sorted(item_id for item_id in preview_ids if item_id in display)
        direct_relic_ids = sorted(item_id for item_id in preview_ids if item_id in relics)
        leaves = positive_leaves(row["sourceRootId"], nodes)
        native_relic_ids = sorted(item_id for item_id in leaves if item_id in relics)
        preview_sets = sorted({display[item_id]["param"] for item_id in display_ids})
        native_sets = sorted({relics[item_id]["setId"] for item_id in native_relic_ids})
        if not display_ids or direct_relic_ids or not native_relic_ids:
            raise ValueError(f"{dungeon_id}: preview/native artifact assumptions changed")
        output.append({
            "dungeonId": dungeon_id,
            "nativeRootId": row["sourceRootId"],
            "previewDisplayItemIds": display_ids,
            "previewArtifactSetIds": preview_sets,
            "directReliquaryPreviewItemIds": direct_relic_ids,
            "nativeReliquarySetIds": native_sets,
            "nativeReliquaryItemCount": len(native_relic_ids),
            "rejectedProxyIssues": row["proxyIssues"],
            "predictedCurrentRewardSource": "NONE",
        })
    return sorted(output, key=lambda item: item["dungeonId"])


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("resource_root", type=Path, help="pinned AstaPS-Resource checkout")
    parser.add_argument("--check", action="store_true", help="compare published audit snapshot")
    args = parser.parse_args()
    excel = args.resource_root / "ExcelBinOutput"
    display = read_pinned(excel / "DisplayItemExcelConfigData.json", DISPLAY_BLOB)
    relics = read_pinned(excel / "ReliquaryExcelConfigData.json", RELIQUARY_BLOB)
    graph = read_pinned(ECONOMY / "7.1-domain-drop-links.json", GRAPH_BLOB)
    previews = read_pinned(ECONOMY / "7.1-dungeon-reward-previews.json", PREVIEW_BLOB)
    current = read_pinned(ECONOMY / "7.1-current-asta-dungeon-reward-audit.json",
                          CURRENT_AUDIT_BLOB)
    rows = investigate(graph, previews, current, display, relics)
    snapshot = json.loads(OUTPUT.read_text(encoding="utf-8"))
    if rows != snapshot["dungeons"]:
        if args.check:
            raise SystemExit("artifact claim audit diverged from pinned input")
        print(json.dumps(rows, indent=2))
        return
    print("PASS: 7.1 artifact native-only claim audit" if args.check
          else json.dumps(snapshot, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
