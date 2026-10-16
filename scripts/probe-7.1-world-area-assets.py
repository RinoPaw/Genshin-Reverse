#!/usr/bin/env python3
"""Probe WorldArea asset path identities in the pinned 7.1 client design index.

This deliberately does NOT infer geometry from old community JSON. A hash
match establishes the presence of a possible asset identity, not the payload.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path

from genshinre.assetindex import parse_asset_index, query_asset_paths
from genshinre.nativeprofile import PROFILE_71

INDEX_EXPORT_SHA256 = "fe1e1ce970e3aa72e764b0894d94a684b7a49edc9f3ae6a32c4d7f38d8a64712"
SCENES = (3, 4, 5, 6, 7, 9, 10, 11, 100, 101, 102, 103, 51195)
EXPORTED_STEMS = {
    100: "f0d16079", 101: "8a14d94c", 102: "fe22afa9",
    103: "22149916", 51195: "e0bf65b8",
}
CONTROL_PATHS = (
    "Data/_ExcelBinOutput/QuestExcelConfigData",
    "Data/_ExcelBinOutput/DungeonExcelConfigData",
)


def candidates() -> dict[int, list[str]]:
    """Finite source-path hypotheses, never a claim of exhaustive discovery.

    Existing 1.0 client literal: Data/_BinOutput/Scene/WorldArea/scene3_worldArea.
    The 7.1 asset-index appends .MiHoYoBinData when hashing. Five community
    files are hashed exports; those hashes are not established source names.
    """
    prefixes = (
        "Data/_BinOutput/Scene/WorldArea/",
        "Data/_BinOutput/Scene/WorldArea/",
        "Data/BinOutput/Scene/WorldArea/",
        "BinOutput/Scene/WorldArea/",
        "Scene/WorldArea/",
        "Data/_BinOutput/WorldArea/",
        "Data/_BinOutput/Scene/",
    )
    result: dict[int, list[str]] = {}
    for scene in SCENES:
        stems = (
            f"scene{scene}_worldArea",
            f"scene{scene}_WorldArea",
            f"scene{scene}_worldarea",
            f"scene{scene}_worldArea.json",
        )
        # The hashed names might be export identifiers, not input path names.
        # Probe them separately without promoting a hit as semantic proof.
        if scene in EXPORTED_STEMS:
            stems += (EXPORTED_STEMS[scene],)
        result[scene] = list(dict.fromkeys(prefix + stem
                                           for prefix in prefixes for stem in stems))
    return result


def build_report(raw_export: bytes) -> dict:
    digest = hashlib.sha256(raw_export).hexdigest()
    if digest != INDEX_EXPORT_SHA256:
        raise ValueError(
            f"7.1 design-index export SHA256 mismatch: expected "
            f"{INDEX_EXPORT_SHA256}, observed {digest}"
        )
    index = parse_asset_index(raw_export)
    controls = query_asset_paths(index, list(CONTROL_PATHS))
    for record in controls:
        if (record["status"] != "HASH_RESOLVED"
                or record["groupId"] != 0
                or record["blockId"] != 25539185):
            raise ValueError(f"pinned positive index control changed: {record}")

    paths = candidates()
    all_paths = [name for paths_for_scene in paths.values()
                 for name in paths_for_scene]
    rows = query_asset_paths(index, all_paths)
    if len(rows) != len(set(all_paths)):
        raise ValueError("duplicate or missing asset candidates")
    current = 0
    scenes = []
    for scene, path_list in paths.items():
        selected = rows[current:current + len(path_list)]
        current += len(path_list)
        scenes.append({
            "sceneID": scene,
            "sourcePathHypotheses": len(path_list),
            "matches": [item for item in selected if item["status"] != "HASH_ABSENT"],
        })
    statuses = dict(sorted(Counter(row["status"] for row in rows).items()))
    return {
        "status": "EXACT_7_1_DESIGN_INDEX_HASH_MEMBERSHIP__NOT_GEOMETRY_EXTRACTION",
        "sample": PROFILE_71.identity,
        "sampleExeSha256": PROFILE_71.exe_sha256,
        "indexExportSha256": digest,
        "indexNameCount": len(index.names),
        "indexBlockReferenceCount": len(index.block_refs),
        "candidateCount": len(rows),
        "candidateStatuses": statuses,
        "positiveControls": controls,
        "scenes": scenes,
        "probedPaths": rows,
        "limitations": [
            "A listed path hash alone does not independently prove payload type or content.",
            "Absent finite name guesses cannot prove absence of WorldArea in the client.",
            "This is the design asset index only; native geometry may be stored in a different bundle family.",
            "Community 7.1-labelled geometry matches 7.0 numerically; none of that source is imported here.",
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--index-raw", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = build_report(args.index_raw.read_bytes())
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n",
                           encoding="utf-8")
    print("WORLD_AREA_ASSET_INDEX_BEGIN")
    print(json.dumps({
        "status": report["status"],
        "indexSha256": report["indexExportSha256"],
        "candidateCount": report["candidateCount"],
        "statuses": report["candidateStatuses"],
        "scenesWithCandidates": [
            {"sceneID": scene["sceneID"], "matches": scene["matches"]}
            for scene in report["scenes"] if scene["matches"]
        ],
    }, indent=2, ensure_ascii=False))
    print("WORLD_AREA_ASSET_INDEX_END")


if __name__ == "__main__":
    main()
