#!/usr/bin/env python3
"""Bounded exact-client design-index test for a historical chest scene group.

Only original Global 7.1 MiHoYoBinData asset-index membership is tested.
The scene/group/config example comes from an older public Lua copy, and is
NOT authenticated by using its string in a proposed client path.
No claim is made about Scene Lua in other bundles or on official servers.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path

from genshinre.assetindex import parse_asset_index, query_asset_paths
from genshinre.nativeprofile import PROFILE_71

INDEX_SHA256 = "fe1e1ce970e3aa72e764b0894d94a684b7a49edc9f3ae6a32c4d7f38d8a64712"
SCENE = 3
GROUP = 133003154
CONTROL = {
    "known-Excel": "Data/_ExcelBinOutput/QuestExcelConfigData",
    "known-scene-area": "Data/_BinOutput/Scene/WorldArea/scene3_worldArea",
}
CONTROL_TARGETS = {
    "known-Excel": (0, 25539185),
    "known-scene-area": (0, 24230448),
}


def candidates() -> dict[str, tuple[str, ...]]:
    """Explicit historical path families; none is claimed exhaustive."""
    excel_names = (
        "SceneExcelConfigData", "SceneTagConfigData", "ScenePointExcelConfigData",
        "SceneAreaExcelConfigData", "SceneNpcBornExcelConfigData",
        "SceneGroupExcelConfigData", "SceneConfigData",
    )
    excel = tuple("Data/_ExcelBinOutput/" + name for name in excel_names)

    scene_paths = (
        "Data/_BinOutput/Scene/",
        "Data/BinOutput/Scene/",
        "BinOutput/Scene/",
        "Scene/",
        "Data/_Lua/Scene/",
        "Data/Lua/Scene/",
        "Data/_BinOutput/Scene/ScriptSceneData/",
    )
    folders = (
        "3/", "Scene3/", "scene3/", "3/Group/", "3/Groups/",
        "3/SceneGroup/", "", "Scene/",
    )
    stems = (
        f"scene{SCENE}_group{GROUP}",
        f"Scene{SCENE}_group{GROUP}",
        f"scene{SCENE}_Group{GROUP}",
        f"group{GROUP}",
    )
    extensions = ("", ".lua", ".json")
    authored = tuple(dict.fromkeys(
        base + folder + stem + ext
        for base in scene_paths for folder in folders
        for stem in stems for ext in extensions
    ))

    nearby = (
        f"scene{SCENE}", f"scene{SCENE}_block133003",
        f"scene{SCENE}_dummy_points", f"scene{SCENE}_grid",
        f"scene{SCENE}_point", f"scene{SCENE}_npcBorn",
    )
    nearby_roots = (
        "Data/_BinOutput/Scene/", "Data/_BinOutput/Scene/Point/",
        "Data/_BinOutput/Scene/SceneNpcBorn/", "Data/_BinOutput/Scene/3/",
        "Data/_BinOutput/Scene/WorldArea/", "Data/_Lua/Scene/3/",
        "Data/_BinOutput/Scene/ScriptSceneData/",
    )
    support = tuple(dict.fromkeys(
        base + name + ext for base in nearby_roots
        for name in nearby for ext in ("", ".json", ".lua")
    ))
    # WorldArea control is excluded from the hypotheses to avoid counting
    # an already-verified known-positive entry as new scene evidence.
    support = tuple(p for p in support if p not in CONTROL.values())
    return {
        "scene-excel-config": excel,
        "historical-group-name-hypotheses": authored,
        "adjacent-scene-point-and-support-hypotheses": support,
    }


def analyze(index, *, digest: str) -> dict:
    source_controls = query_asset_paths(index, list(CONTROL.values()))
    for (label, _path), result in zip(CONTROL.items(), source_controls):
        if result["status"] != "HASH_RESOLVED" or (
                result["groupId"], result["blockId"]) != CONTROL_TARGETS[label]:
            raise ValueError(f"original 7.1 index positive control failed: {label}")

    groups = candidates()
    names = [s for paths in groups.values() for s in paths]
    if len(names) != len(set(names)):
        raise ValueError("duplicate scene name hypothesis across groups")
    if any(name in CONTROL.values() for name in names):
        raise ValueError("positive scene control included as candidate")
    matched = query_asset_paths(index, names)
    if len(matched) != len(names):
        raise ValueError("scene path query cardinality changed")
    statuses = Counter(row["status"] for row in matched)
    offsets = 0
    results = {}
    for group, paths in groups.items():
        rows = matched[offset:offset + len(paths)]
        offsets += len(paths)
        results[group] = {
            "hypothesesTested": len(paths),
            "statusCounts": dict(sorted(Counter(r["status"] for r in rows).items())),
            "matchesOrAmbiguous": [row for row in rows if row["status"] != "HASH_ABSENT"],
        }

    return {
        "schemaVersion": 1,
        "status": "GLOBAL_7_1_SCENE_NAME_HYPOTHESES_TESTED__ORIGINAL_INSTANCE_UNRESOLVED",
        "source": {
            "version": PROFILE_71.identity,
            "exeSha256": PROFILE_71.exe_sha256,
            "designIndexRawSha256": digest,
            "designIndexNameCount": len(index.names),
            "historicalSample": f"scene={SCENE}, group={GROUP}",
            "hypothesesAreSourcePaths": False,
            "indexType": "MiHoYoBinData only",
        },
        "controls": dict(zip(CONTROL.keys(), source_controls)),
        "candidateCount": len(names),
        "candidatesSha256": hashlib.sha256(
            ("\n".join(names) + "\n").encode("utf-8")).hexdigest(),
        "statusCounts": dict(sorted(statuses.items())),
        "groups": results,
        "limitations": [
            "An original-client path-hash match is an asset identity lead requiring exact original payload bytes and a native reader.",
            "An unmatched guessed name does not prove the corresponding asset or scene Lua absent from the client, other asset indexes or server.",
            "Unity TextAsset, script bundles and other asset-type suffixes are outside this MiHoYoBinData-only test.",
            "The tested scene/group identifier came from historical Lua, which is not an authenticated Global 7.1 original placement.",
            "Scene gadget definitions, server-owned drop_tag and reward roots cannot be inferred from index negatives or geographic WorldArea hits.",
        ],
    }


def run(raw: bytes) -> dict:
    digest = hashlib.sha256(raw).hexdigest()
    if digest != INDEX_SHA256:
        raise ValueError("exact original 7.1 design index SHA-256 mismatch")
    return analyze(parse_asset_index(raw), digest=digest)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--index-raw", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    report = run(args.index_raw.read_bytes())
    if args.check:
        if json.loads(args.output.read_text(encoding="utf-8")) != report:
            raise SystemExit("exact 7.1 source-index scene hypothesis report differs")
        print("PASS: source-pinned scene instance name probe")
    else:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2, ensure_ascii=False)+"\n",
                               encoding="utf-8")
    print(json.dumps({
        "status": report["status"],
        "controlStatuses": {k: v["status"] for k,v in report["controls"].items()},
        "candidateCount": report["candidateCount"],
        "statusCounts": report["statusCounts"],
        "hits": {k: v["matchesOrAmbiguous"] for k,v in report["groups"].items()},
    }, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
