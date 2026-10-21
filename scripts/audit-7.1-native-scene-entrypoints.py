#!/usr/bin/env python3
"""Source-verified Global 7.1 native SceneExcel/SceneTag raw entrypoint audit.

Requires the exact SHA-256-pinned 7.1 index and extraction of official
Sophon block 00/25539185.blk with the existing pinned AnimeStudio exporter.
One known Gadget raw-asset control prevents silently accepting arbitrary
export directories. Original binary bytes are never written to reports.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from genshinre.assetindex import parse_asset_index, query_asset_paths, unwrap_mihoyo_bin_data

INDEX_SHA256 = "fe1e1ce970e3aa72e764b0894d94a684b7a49edc9f3ae6a32c4d7f38d8a64712"
CONTROL_GADGET_RAW_SHA256 = "a35e3f3ed04f950cb6302099d12aa71e23ece21d8fe578950347d9318f769e35"
OUTPUT = (Path(__file__).resolve().parents[1]
          / "versions/7.1.0-global/analyses/progression/economy"
          / "7.1-chest-scene-native-excel-entrypoints.json")
REQUIRED = (
    "Data/_ExcelBinOutput/SceneExcelConfigData",
    "Data/_ExcelBinOutput/SceneTagConfigData",
)
CONTROL = "Data/_ExcelBinOutput/GadgetExcelConfigData"
BLOCK = (0, 25539185)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def inspect(index, export_dir: Path) -> dict:
    rows = query_asset_paths(index, [CONTROL, *REQUIRED])
    for row in rows:
        if row["status"] != "HASH_RESOLVED" or (
                row["groupId"], row["blockId"]) != BLOCK:
            raise ValueError(f"scene Excel source identity failed: {row}")
    control_path = export_dir / "MiHoYoBinData" / (rows[0]["exportedName"] + ".dat")
    if sha256(control_path.read_bytes()) != CONTROL_GADGET_RAW_SHA256:
        raise ValueError("official 7.1 Gadget control export SHA-256 mismatch")

    assets = []
    for row in rows[1:]:
        file = export_dir / "MiHoYoBinData" / (row["exportedName"] + ".dat")
        raw = file.read_bytes()
        payload = unwrap_mihoyo_bin_data(raw)
        assets.append({
            "candidateSourcePath": row["path"],
            "namePathHash": row["pathHash"],
            "nameCollisionCount": row["nameMatchCount"],
            "sourceBlockGroupId": row["groupId"],
            "sourceBlockId": row["blockId"],
            "rawExportName": row["exportedName"] + ".dat",
            "rawExportBytes": len(raw),
            "rawExportSha256": sha256(raw),
            "payloadBytes": len(payload),
            "payloadSha256": sha256(payload),
            "payloadFirst32Hex": payload[:32].hex(),
            "wholePayloadUtf8": _is_utf8(payload),
        })
    return {
        "schemaVersion": 1,
        "status": "GLOBAL_7_1_SCENE_EXCEL_AND_TAG_NATIVE_BYTES_VERIFIED__FIELD_MEANING_UNKNOWN",
        "sample": "7.1.0-global/windows-x64",
        "indexRawExportSha256": INDEX_SHA256,
        "verifiedGadgetControlSha256": CONTROL_GADGET_RAW_SHA256,
        "originalBlockId": BLOCK[1],
        "assets": assets,
        "limitations": [
            "Sophon block origin and exporter SHA-256 must independently be verified by the calling acquisition workflow.",
            "The original 7.1 Gadget control authenticates the extraction directory but does not prove the schema of these SceneExcel/SceneTag rows.",
            "SceneTagConfigData is a client-side Excel table name; it is not authenticated as a server chest drop_tag selector.",
            "Scene/Gadget instance placement, group/config identity, official server reward roots and probabilities remain unverified.",
            "No unmodified original raw export bytes are committed to this research repository.",
        ],
    }


def _is_utf8(payload: bytes) -> bool:
    try:
        payload.decode("utf-8")
    except UnicodeDecodeError:
        return False
    return True


def audit(index_raw: bytes, export_dir: Path) -> dict:
    if sha256(index_raw) != INDEX_SHA256:
        raise ValueError("original 7.1 design index SHA-256 mismatch")
    return inspect(parse_asset_index(index_raw), export_dir)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--index-raw", type=Path, required=True)
    parser.add_argument("--block-export", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=OUTPUT)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    report = audit(args.index_raw.read_bytes(), args.block_export)
    if args.check:
        if json.loads(args.output.read_text(encoding="utf-8")) != report:
            raise SystemExit("original Scene Excel entrypoints differ from source-pinned report")
        print("PASS: original 7.1 SceneExcel and SceneTag original bytes authenticated")
    else:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n",
                               encoding="utf-8")
    print(json.dumps({
        "status": report["status"],
        "assets": [{"name": a["candidateSourcePath"],
                    "payloadBytes": a["payloadBytes"],
                    "sha256": a["payloadSha256"]} for a in report["assets"]],
    }, indent=2))


if __name__ == "__main__":
    main()
