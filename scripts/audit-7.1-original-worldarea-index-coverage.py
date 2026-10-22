#!/usr/bin/env python3
"""Audit ORIGINAL Global 7.1 index membership for one source-pinned Unity block.

The exported 8-hex name omits the low 8 bits of the original 40-bit asset
hash. Membership and size observations have no Gadget instance/level meaning.
"""
from __future__ import annotations
import argparse
from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path

from genshinre.assetindex import parse_asset_index, query_asset_paths
from genshinre.nativeprofile import PROFILE_71

INDEX_SHA = "fe1e1ce970e3aa72e764b0894d94a684b7a49edc9f3ae6a32c4d7f38d8a64712"
SCENE3_SHA = "e66d6ec832bed734e824714d345961715b01edbdce50f6115b07983ec205eda9"
BLOCK = (0, 24230448)
SCENES = (3, 4, 5, 6, 7, 9, 10, 11, 100, 101, 102, 103, 51195)


def classify(index, exports):
    """Classify 32-bit name matches, retaining ambiguous/unresolved status."""
    by_asset = defaultdict(set)
    for ref in index.block_refs:
        if ref.block_id in index.block_groups:
            by_asset[ref.asset_id].add((index.block_groups[ref.block_id], ref.block_id))
    by_stem = defaultdict(list)
    for name in index.names:
        by_stem[name.exported_name].append(name)

    index_counts = Counter()
    target_stems = set()
    for name in index.names:
        destinations = by_asset.get(name.sub_asset_id, set())
        if BLOCK in destinations:
            index_counts["targetBlockHashRows40"] += 1
            target_stems.add(name.exported_name)
        elif destinations:
            index_counts["otherBlockHashRows40"] += 1
        else:
            index_counts["unresolvedHashRows40"] += 1
    index_counts["targetBlockExportStems32"] = len(target_stems)
    index_counts["ambiguousStems32"] = sum(len(rows) > 1 for rows in by_stem.values())

    totals = Counter()
    examples = defaultdict(list)
    for filename, size in sorted(exports.items()):
        rows = by_stem.get(filename[:-4], [])
        in_target = [r for r in rows if BLOCK in by_asset.get(r.sub_asset_id, set())]
        in_other = [r for r in rows if by_asset.get(r.sub_asset_id, set())
                    and BLOCK not in by_asset[r.sub_asset_id]]
        if not rows:
            category = "notInThisDesignIndex"
        elif len(rows) == 1 and len(in_target) == 1:
            category = "uniqueStemMappedToTargetBlock"
        elif in_target:
            category = "ambiguousStemIncludingTargetBlock"
        elif in_other:
            category = "stemMappedOnlyToOtherBlocks"
        else:
            category = "stemWithUnresolvedBlockRef"
        totals[category + "Files"] += 1
        totals[category + "RawBytes"] += size
        if len(examples[category]) < 10:
            examples[category].append({"file": filename, "size": size,
                                       "index40BitRows": len(rows),
                                       "rowsMappedToTarget": len(in_target)})
    return {"indexHashCounts": dict(sorted(index_counts.items())),
            "exportGroups": dict(sorted(totals.items())),
            "examples": dict(sorted(examples.items()))}


def size_counts(exports):
    counts = Counter()
    for size in exports.values():
        if size < 8: key = "lt8"
        elif size < 64: key = "8to63"
        elif size < 256: key = "64to255"
        elif size < 1024: key = "256to1023"
        elif size < 4096: key = "1024to4095"
        elif size < 65536: key = "4096to65535"
        else: key = "65536plus"
        counts[key] += 1
    ordered = sorted(exports.values())
    return {"bins": dict(sorted(counts.items())),
            "minimum": ordered[0], "median": ordered[len(ordered)//2],
            "maximum": ordered[-1]}


def audit(index_raw, export_dir):
    if hashlib.sha256(index_raw).hexdigest() != INDEX_SHA:
        raise ValueError("original design index SHA-256 changed")
    index = parse_asset_index(index_raw)
    if len(index.names) != 247073:
        raise ValueError("original source index name count changed")
    paths = [f"Data/_BinOutput/Scene/WorldArea/scene{sid}_worldArea"
             for sid in SCENES]
    controls = query_asset_paths(index, paths)
    if any(c["status"] != "HASH_RESOLVED" or
           (c["groupId"], c["blockId"]) != BLOCK for c in controls):
        raise ValueError("original WorldArea source index control failed")

    folder = export_dir / "MiHoYoBinData"
    scene3 = folder / "0c934d1c.dat"
    if not scene3.is_file() or hashlib.sha256(scene3.read_bytes()).hexdigest() != SCENE3_SHA:
        raise ValueError("independent original scene3 WorldArea Raw control missing")
    exports = {}
    for p in folder.iterdir():
        if not p.is_file() or p.suffix != ".dat" or len(p.stem) != 8 or any(
            x not in "0123456789abcdef" for x in p.stem
        ):
            raise ValueError(f"unexpected exporter filename: {p.name}")
        exports[p.name] = p.stat().st_size
    if len(exports) != 167673 or sum(exports.values()) != 415672040:
        raise ValueError("source-original block file count/bytes changed")

    return {
        "schemaVersion": 1,
        "status": "ORIGINAL_7_1_WORLD_AREA_DESIGN_INDEX_MEMBERSHIP__SCENE_LEVEL_UNPROVEN",
        "client": PROFILE_71.identity,
        "exeSha256": PROFILE_71.exe_sha256,
        "indexRawSha256": INDEX_SHA,
        "worldAreaBlock": "00/24230448.blk",
        "sourceBlockSha256": "71fbe2d10404655fa20e5d612daf5fa2f2336c1d6250ae209b722c894169aff7",
        "scene3RawSha256": SCENE3_SHA,
        "exportedFiles": len(exports),
        "exportedRawBytes": sum(exports.values()),
        "worldAreaIndexControls": [{"hash": c["pathHash"],
                                    "export": c["exportedName"]} for c in controls],
        "coverage": classify(index, exports),
        "rawSizes": size_counts(exports),
        "limits": [
            "Original 40-bit index hash is truncated to 32 bits in Raw exporter filenames. Collisions remain ambiguous.",
            "This original design index does not enumerate every original client asset namespace or block.",
            "Hash membership alone identifies neither resource semantic paths nor original scene Gadget records.",
            "No original scene-instance level, reward grade, drop table or probability is established.",
            "No old private-server scene Lua, community JSON or LootCSS values were used."
        ]
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--index-raw", required=True, type=Path)
    parser.add_argument("--world-export", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    report = audit(args.index_raw.read_bytes(), args.world_export)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print("SOURCE_INDEX_COVERAGE_BEGIN")
    print(json.dumps(report, indent=2))
    print("SOURCE_INDEX_COVERAGE_END")


if __name__ == "__main__":
    main()
