#!/usr/bin/env python3
"""Locate chest-related candidate path hashes in the exact 7.1 client design index.

An index match identifies a possible asset location. It does not authenticate
reward rules, entity grade, server payout owner or drop probability.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path

from genshinre.assetindex import parse_asset_index, query_asset_paths, unwrap_mihoyo_bin_data
from genshinre.nativeprofile import PROFILE_71

INDEX_SHA256 = "fe1e1ce970e3aa72e764b0894d94a684b7a49edc9f3ae6a32c4d7f38d8a64712"
CONTROL_PATHS = (
    "Data/_ExcelBinOutput/QuestExcelConfigData",
    "Data/_ExcelBinOutput/DungeonExcelConfigData",
)
# Hypothesized paths only, not proven asset names.
CANDIDATES = {
    "gadget-identity": (
        "Data/_ExcelBinOutput/GadgetExcelConfigData",
        "Data/_ExcelBinOutput/GadgetPropExcelConfigData",
        "Data/_ExcelBinOutput/GadgetInteractExcelConfigData",
    ),
    "chest-selector": (
        "Data/_ExcelBinOutput/ChestDropData",
        "Data/_ExcelBinOutput/ChestDropExcelConfigData",
        "Data/_ExcelBinOutput/ChestExcelConfigData",
        "Data/_BinOutput/ChestDropData",
    ),
    "drop-graph": (
        "Data/_ExcelBinOutput/DropTableExcelConfigData",
        "Data/_ExcelBinOutput/DropSubTableExcelConfigData",
        "Data/_BinOutput/DropTreeData",
        "Data/_BinOutput/DropLeafData",
    ),
    "authored-instance": (
        "Data/_BinOutput/Scene/3/scene3_group133003154",
        "Data/_BinOutput/Scene/3/scene3_group133003154.lua",
        "Data/_BinOutput/Scene/Scene3/scene3_group133003154",
    ),
}


def audit(index, *, index_sha256: str) -> dict:
    controls = query_asset_paths(index, list(CONTROL_PATHS))
    if any(row["status"] != "HASH_RESOLVED" or row.get("groupId") != 0
           or row.get("blockId") != 25539185 for row in controls):
        raise ValueError(f"7.1 control lookup failed: {controls}")
    paths = [path for group in CANDIDATES.values() for path in group]
    if len(paths) != len(set(paths)):
        raise ValueError("duplicate chest path candidate")
    rows = query_asset_paths(index, paths)
    groups: dict[str, list[dict]] = {}
    offset = 0
    for name, candidates in CANDIDATES.items():
        groups[name] = rows[offset:offset + len(candidates)]
        offset += len(candidates)
    return {
        "schemaVersion": 1,
        "status": "EXACT_7_1_DESIGN_INDEX_PATH_HASH_PROBE_ONLY",
        "sample": PROFILE_71.identity,
        "sampleExeSha256": PROFILE_71.exe_sha256,
        "indexExportSha256": index_sha256,
        "indexNameCount": len(index.names),
        "controls": controls,
        "candidateCount": len(rows),
        "candidateStatusCounts": dict(sorted(Counter(row["status"] for row in rows).items())),
        "groups": groups,
        "limitations": [
            "A path hash match is not a decoded table or verified schema.",
            "A missing name hypothesis is not evidence that a table is absent from the client/server.",
            "Scene Lua server ownership is not established by path matching.",
            "No chest grade, tag, root, amount or payout probability is certified.",
        ],
    }



def inspect_candidate_exports(report: dict, export_dir: Path, *, strict: bool = False) -> dict:
    """Hash candidate raw exports; do not imply client or server authorship.

    The index is independently hash-pinned by run(). The exported .dat files
    may still originate from an unrelated bundle unless their source manifest
    is verified separately, so all rows remain candidates.
    """
    hits = [item for group in report["groups"].values() for item in group
            if item["status"] == "HASH_RESOLVED"]
    names = {}
    for hit in hits:
        name = hit["exportedName"]
        if (not isinstance(name, str) or len(name) != 8
                or any(char not in "0123456789abcdef" for char in name)):
            raise ValueError(f"invalid exportedName in asset hit: {name!r}")
        if name in names and names[name] != hit["pathHash"]:
            raise ValueError(f"ambiguous export filename {name} for multiple path hashes")
        names[name] = hit["pathHash"]

    exports = []
    for hit in hits:
        path = export_dir / "MiHoYoBinData" / (hit["exportedName"] + ".dat")
        row = {
            "candidatePath": hit["path"], "pathHash": hit["pathHash"],
            "exportedName": hit["exportedName"], "groupId": hit["groupId"],
            "blockId": hit["blockId"],
        }
        if not path.is_file():
            row["status"] = "EXPORT_MISSING"
            if strict:
                raise FileNotFoundError(f"candidate export missing: {path}")
        else:
            raw = path.read_bytes()
            try:
                payload = unwrap_mihoyo_bin_data(raw)
            except ValueError as error:
                row.update(status="EXPORT_FRAMING_INVALID", framingError=str(error))
                if strict:
                    raise ValueError(f"invalid candidate export {path}: {error}") from error
            else:
                row.update(
                    status="RAW_EXPORT_PRESENT_SCHEMA_UNVERIFIED",
                    rawSize=len(raw), rawSha256=hashlib.sha256(raw).hexdigest(),
                    payloadSize=len(payload), payloadSha256=hashlib.sha256(payload).hexdigest(),
                    payloadFirst16BytesHex=payload[:16].hex(),
                )
        exports.append(row)
    return {
        "status": "HASH_PINNED_INDEX__EXPORT_SOURCE_AND_SCHEMA_UNVERIFIED",
        "exportedCandidateCount": len(exports),
        "exportStatusCounts": dict(sorted(Counter(item["status"] for item in exports).items())),
        "exports": exports,
        "rawAssetsCommitted": False,
        "limitations": [
            "Export filenames are derived from 40-bit candidate path hashes.",
            "The index SHA-256 guards the design index, not the exporter output directory.",
            "Raw export hashes require a separately pinned source bundle and extraction manifest.",
            "A framed payload alone does not establish a Chest record schema, grade or rewards.",
            "Missing guessed names and missing exports cannot prove absence from the client.",
        ],
    }


def run(raw_index: bytes) -> dict:
    digest = hashlib.sha256(raw_index).hexdigest()
    if digest != INDEX_SHA256:
        raise ValueError(f"design-index SHA-256 mismatch: expected {INDEX_SHA256}, got {digest}")
    return audit(parse_asset_index(raw_index), index_sha256=digest)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--index-raw", required=True, type=Path)
    parser.add_argument("--asset-export", type=Path, help="Unmodified exact-client .dat export directory")
    parser.add_argument("--strict-exports", action="store_true", help="Fail on missing or corrupt matching exports")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = run(args.index_raw.read_bytes())
    if args.strict_exports and not args.asset_export:
        parser.error("--strict-exports requires --asset-export")
    if args.asset_export:
        result["candidateRawExports"] = inspect_candidate_exports(
            result, args.asset_export, strict=args.strict_exports)
    report = json.dumps(result, indent=2, ensure_ascii=False) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(report, encoding="utf-8")
    print(report, end="")


if __name__ == "__main__":
    main()
