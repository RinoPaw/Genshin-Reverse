#!/usr/bin/env python3
"""Intersect two SHA-256-pinned 7.1 Scene row-reader search results.

Inputs are source-scoped original-client research artifacts: native key
writer candidates and metadata-neighbor readers. Both are only *leads*.
A first-record boundary falsification excludes a specified method from
DIRECT row-reading at offset four; it does not determine vtable ownership.

Run on the short-lived research artifacts archived from exact-client runs.
No original executable, metadata bulk or proprietary binary is included.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from genshinre.nativeprofile import PROFILE_71

KEY_WRITERS_SHA256 = "5a545acb63f01af15dfe2793307c14f9e71a548a829b4e190c62d8a4a6be2169"
NEIGHBOR_SHA256 = "8bd079ed0f05843bb87966f5e2b61c4736c319697c19eb2ac24ebf041fed73aa"
EXPECTED_WRITER_METHODS = {"SceneTag": 485, "SceneExcel": 168}
MANAGER_TYPE_INDICES = {"SceneTag": 84296, "SceneExcel": 35441}
KEY_OFFSETS = {"SceneTag": 0x28, "SceneExcel": 0x50}
# Exact original binary first-record array-bound disproof from separate
# SHA-256-pinned disassembly/source tests. Other candidates stay unknown.
FALSIFIED_DIRECT_FIRST_ROW = {"SceneTag": {696555}, "SceneExcel": {279984}}

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = (ROOT / "versions/7.1.0-global/analyses/progression/economy"
          / "7.1-chest-scene-native-row-reader-candidate-intersection.json")


def intersection(writer: dict, neighbors: dict) -> dict:
    if writer["exeSha256"] != PROFILE_71.exe_sha256:
        raise ValueError("wrong exact 7.1 key-writer source EXE")
    report = {}
    for table, count in EXPECTED_WRITER_METHODS.items():
        methods = writer["keyOffsetCandidates"][table]["methods"]
        if len(methods) != count:
            raise ValueError(f"changed {table} key-writer population")
        if int(writer["keyOffsetCandidates"][table]["memoryOffset"], 16) != KEY_OFFSETS[table]:
            raise ValueError(f"{table} key-writer offset mismatch")
        key_indexes = [int(item["methodIndex"]) for item in methods]
        if len(set(key_indexes)) != count:
            raise ValueError(f"{table} duplicate method indices")
        key_index_set = set(key_indexes)
        near = neighbors["tables"][table]["sameMethodAndInputSignatureCandidates"]
        near_indexes = {int(item["methodIndex"]) for item in near}
        intersection_methods = [
            {"methodIndex": int(item["methodIndex"]),
             "typeName": item["typeName"],
             "typeDefinitionIndex": int(item["typeIndex"]),
             "rva": item["rva"],
             "relativeTypeIndex": int(item["typeIndex"])-MANAGER_TYPE_INDICES[table],
             "falsifiedAsDirectOffsetFourReader":
                 int(item["methodIndex"]) in FALSIFIED_DIRECT_FIRST_ROW[table]}
            for item in near if int(item["methodIndex"]) in key_index_set
        ]
        rejected = FALSIFIED_DIRECT_FIRST_ROW[table] & key_index_set
        report[table] = {
            "originalNativeKeyOffset": f"0x{KEY_OFFSETS[table]:X}",
            "originalManagerTypeIndex": MANAGER_TYPE_INDICES[table],
            "keyWriterMethods": count,
            "metadataNeighborReaderMethods": len(near_indexes),
            "intersectionCount": len(intersection_methods),
            "intersectionCandidates": intersection_methods,
            "verifiedDirectOffsetFourFalsificationsWithinKeyWriterSet": sorted(rejected),
            "unfalsifiedKeyWriterCandidateCount": len(key_index_set - rejected),
            "singleNativeWrapperCallAndOnlyMatchingStore": sum(
                len(item["nativeCallSites"]) == 1
                and item["keyWriteOffsetsAfterWrapper"] == [KEY_OFFSETS[table]]
                for item in methods),
        }
    return {
        "schemaVersion": 1,
        "status": "EXACT_7_1_SCENE_NATIVE_READER_KEYWRITER_NEIGHBOR_INTERSECTION__VTABLE_UNRESOLVED",
        "originalClientExeSha256": PROFILE_71.exe_sha256,
        "inputArtifacts": {
            "nativeKeyWriterFullReportSha256": KEY_WRITERS_SHA256,
            "metadataNeighborFullReportSha256": NEIGHBOR_SHA256,
        },
        "tables": report,
        "limitations": [
            "Metadata neighborhood is a heuristic; absence from the nearby set does not exclude a real row reader.",
            "The key-wrapper writer native call-site selection covers direct calls and a bounded post-call store window; inherited, inlined or indirect writes may be missed.",
            "Only separately source-falsified direct first-record readers are marked false. The other SceneTag neighbor method remains unresolved.",
            "One call to an ID wrapper plus matching field offset is no proof of the correct row type or vtable slot +0xF0.",
            "No original SceneTag data fields, placements, server chest drop_tag, reward roots or payout quantities can be inferred.",
        ],
    }


def run(writer_raw: bytes, neighbor_raw: bytes) -> dict:
    if hashlib.sha256(writer_raw).hexdigest() != KEY_WRITERS_SHA256:
        raise ValueError("source-pinned key-writer artifact SHA-256 mismatch")
    if hashlib.sha256(neighbor_raw).hexdigest() != NEIGHBOR_SHA256:
        raise ValueError("source-pinned neighbor artifact SHA-256 mismatch")
    return intersection(json.loads(writer_raw), json.loads(neighbor_raw))


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--keywriters", type=Path, required=True)
    p.add_argument("--neighbors", type=Path, required=True)
    p.add_argument("--output", type=Path, default=OUTPUT)
    p.add_argument("--check", action="store_true")
    args = p.parse_args()
    report = run(args.keywriters.read_bytes(), args.neighbors.read_bytes())
    if args.check:
        if json.loads(args.output.read_text(encoding="utf-8")) != report:
            raise SystemExit("original native row-reader candidate intersection changed")
        print("PASS: pinned 7.1 native reader candidate intersection")
    else:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n",
                               encoding="utf-8")
        print(json.dumps({
            "status": report["status"],
            "tables": {name: {"keyWriters": r["keyWriterMethods"],
                              "intersection": r["intersectionCount"],
                              "singleStore": r["singleNativeWrapperCallAndOnlyMatchingStore"]}
                       for name, r in report["tables"].items()}
        }, indent=2))


if __name__ == "__main__":
    main()
