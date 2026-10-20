#!/usr/bin/env python3
"""Compare pinned scene Git tree inventories; public copy identity only."""
from __future__ import annotations
import argparse
import hashlib
import json
import re
from pathlib import Path

GROUP = re.compile(r"scene(\d+)_group\d+\.lua\Z")
SHA = re.compile(r"[a-f0-9]{40}\Z")

def load_tree(path: Path, expected: str) -> dict:
    raw = path.read_bytes()
    obj = json.loads(raw)
    if not isinstance(obj, dict) or obj.get("truncated") is not False:
        raise ValueError("missing or truncated Git tree")
    if not SHA.fullmatch(expected) or obj.get("sha") != expected:
        raise ValueError("unexpected Git tree SHA")
    rows = obj.get("tree")
    if not isinstance(rows, list):
        raise ValueError("expected tree array")
    blobs = {}
    for row in rows:
        if not isinstance(row, dict) or row.get("type") != "blob":
            raise ValueError("expected flat blob-only directory")
        name, value = row.get("path"), row.get("sha")
        if (not isinstance(name, str) or not name or "/" in name or name in blobs
                or not isinstance(value, str) or not SHA.fullmatch(value)):
            raise ValueError("invalid or duplicate tree entry")
        blobs[name] = value
    return {"sha": expected, "jsonSha256": hashlib.sha256(raw).hexdigest(), "blobs": blobs}

def compare(older: dict, newer: dict, scene: int, sample: str | None = None) -> dict:
    a, b = older["blobs"], newer["blobs"]
    common = a.keys() & b.keys()
    equal = {p for p in common if a[p] == b[p]}
    groups = {p for p in common if (m := GROUP.fullmatch(p)) and int(m.group(1)) == scene}
    report = {
        "sceneId": scene, "earlierTreeSha": older["sha"], "laterTreeSha": newer["sha"],
        "earlierJsonSha256": older["jsonSha256"], "laterJsonSha256": newer["jsonSha256"],
        "allFiles": {"earlier": len(a), "later": len(b), "shared": len(common),
                     "identical": len(equal), "different": len(common-equal),
                     "earlierOnly": len(a.keys()-b.keys()),
                     "laterOnly": len(b.keys()-a.keys())},
        "groupFiles": {"shared": len(groups), "identical": len(groups & equal),
                       "different": len(groups-equal)},
        "clientNative71Verified": False, "rewardWeightsVerified": False,
    }
    if sample:
        if sample not in common:
            raise ValueError("sample absent from one or both inventories")
        report["sample"] = {"path": sample, "earlyBlob": a[sample],
                            "lateBlob": b[sample], "identical": sample in equal}
    return report

def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--early", required=True, type=Path)
    p.add_argument("--later", required=True, type=Path)
    p.add_argument("--early-tree-sha", required=True)
    p.add_argument("--later-tree-sha", required=True)
    p.add_argument("--scene", required=True, type=int)
    p.add_argument("--sample")
    args = p.parse_args()
    result = compare(load_tree(args.early, args.early_tree_sha),
                     load_tree(args.later, args.later_tree_sha), args.scene, args.sample)
    print(json.dumps(result, ensure_ascii=False, indent=2))

if __name__ == "__main__":
    main()
