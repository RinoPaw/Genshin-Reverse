#!/usr/bin/env python3
"""Probe two chest-Lv3-related table path hypotheses in the exact 7.1 index.

Only the SHA-256-pinned original Global 7.1 design index is accepted. Name
hash membership can locate a possible client asset, never server chest loot.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path

from genshinre.assetindex import (
    AssetIndex, mihoyo_name_hash, parse_asset_index, query_asset_paths,
    unwrap_mihoyo_bin_data,
)
from genshinre.nativeprofile import PROFILE_71

GADGET_RAW_SHA256 = "a35e3f3ed04f950cb6302099d12aa71e23ece21d8fe578950347d9318f769e35"
GADGET_EXPORT = "d65ab32f.dat"
INDEX_SHA256 = "fe1e1ce970e3aa72e764b0894d94a684b7a49edc9f3ae6a32c4d7f38d8a64712"
CONTROL = "Data/_ExcelBinOutput/GadgetExcelConfigData"
PATHS = {
    "audioChestType": "Data/_ExcelBinOutput/AudioBattleFervorChestTypeMapConfigData",
    "handbookOpenChest": "Data/_ExcelBinOutput/InvestigationTargetConfigData",
}
EXPECTED_HASHES = {
    "audioChestType": "0x5560E262E3",
    "handbookOpenChest": "0x20C111A6D7",
}


def audit(index: AssetIndex, *, sha256: str) -> dict:
    if sha256 != INDEX_SHA256:
        raise ValueError("original 7.1 design index SHA-256 mismatch")
    if {key: f"0x{mihoyo_name_hash(path):010X}"
            for key, path in PATHS.items()} != EXPECTED_HASHES:
        raise ValueError("7.1 candidate table path hash calculation changed")
    base = query_asset_paths(index, [CONTROL])[0]
    if (base.get("status") != "HASH_RESOLVED"
            or base.get("blockId") != 25539185
            or base.get("groupId") != 0
            or base.get("pathHash") != "0xD65AB32F6B"):
        raise ValueError("Gadget original index control mismatch")
    results = query_asset_paths(index, list(PATHS.values()))
    evidence = {
        key: {"hypothesizedTable": path,
              "expectedPathHash": EXPECTED_HASHES[key],
              "indexResult": result}
        for (key, path), result in zip(PATHS.items(), results, strict=True)
    }
    return {
        "schemaVersion": 1,
        "status": "EXACT_7_1_GLOBAL_DESIGN_INDEX_PATH_PROBE__ROW_SEMANTICS_UNVERIFIED",
        "sample": PROFILE_71.identity,
        "indexRawSha256": sha256,
        "indexNameCount": len(index.names),
        "knownGadgetControl": base,
        "candidates": evidence,
        "candidateStatusCounts": dict(sorted(Counter(x["status"] for x in results).items())),
        "limitations": [
            "The table names are hypotheses from CN/public copies until original 7.1 path resolution and row decoding.",
            "HASH_ABSENT means that this exact guessed path hash is absent from this design index, not that a feature or server table is absent.",
            "A resolved index name/hash requires exact source-block and exported-asset validation before treating raw bytes as original table evidence.",
            "Audio Mid/Hi/Top and handbook chest-open eligibility do not authenticate payable grade, world placement, combat/puzzle tag, payout or probability.",
        ],
    }



def inspect_original_export_dir(report: dict, export_dir: Path) -> dict:
    """Fingerprint exactly two clients assets alongside the pinned Gadget control.

    This is a source-local byte report, not a recovered row decoder. Hosted
    acquisition must separately authenticate the Sophon block and exporter.
    """
    directory = export_dir / "MiHoYoBinData"
    gadget = directory / GADGET_EXPORT
    if not gadget.is_file() or hashlib.sha256(gadget.read_bytes()).hexdigest() != GADGET_RAW_SHA256:
        raise ValueError("original source-block Gadget raw export control mismatch")
    found = {}
    for key, entry in report["candidates"].items():
        hit = entry["indexResult"]
        if hit["status"] != "HASH_RESOLVED":
            found[key] = {"status": "NAME_NOT_RESOLVED"}
            continue
        if hit.get("groupId") != 0 or hit.get("blockId") != 25539185:
            found[key] = {"status": "CANDIDATE_OUTSIDE_VERIFIED_GADGET_BLOCK"}
            continue
        basename = hit["exportedName"]
        if (not isinstance(basename, str) or len(basename) != 8
                or any(char not in "0123456789abcdef" for char in basename)):
            raise ValueError("invalid original-index export basename")
        target = directory / (basename + ".dat")
        if not target.is_file():
            raise FileNotFoundError(f"original index-resolved asset export missing: {basename}")
        raw = target.read_bytes()
        payload = unwrap_mihoyo_bin_data(raw)
        found[key] = {
            "status": "SOURCE_BLOCK_CONTROL_AND_FRAMING_VERIFIED__NATIVE_FIELDS_UNKNOWN",
            "originalIndexPathHash": hit["pathHash"],
            "originalBlock": hit["blockId"],
            "exportedName": basename + ".dat",
            "rawBytes": len(raw),
            "rawSha256": hashlib.sha256(raw).hexdigest(),
            "payloadBytes": len(payload),
            "payloadSha256": hashlib.sha256(payload).hexdigest(),
            "payloadFirst16Hex": payload[:16].hex(),
            "plainAsciiOccurrencesAreNotFieldProof": {
                s: payload.count(s.encode("ascii")) for s in ("Mid", "Hi", "Top")
            },
        }
    return {
        "status": "EXACT_71_SOPHON_EXPORT_WITH_NATIVE_GADGET_CONTROL__ROW_SCHEMA_UNVERIFIED",
        "controlGadgetRawSha256": GADGET_RAW_SHA256,
        "tables": found,
        "limitations": [
            "The paired exact-client source block, Quest positive control, and exporter must be authenticated by the hosted acquisition chain.",
            "Raw hashes and byte string occurrences cannot identify a table row count, audio enum, chest grade, placement or server payout.",
            "The exported original asset bytes must not be committed as research artifacts.",
        ],
    }


def run(raw: bytes) -> dict:
    sha256 = hashlib.sha256(raw).hexdigest()
    if sha256 != INDEX_SHA256:
        raise ValueError("original 7.1 design index SHA-256 mismatch")
    return audit(parse_asset_index(raw), sha256=sha256)


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--index-raw", required=True, type=Path)
    p.add_argument("--block-export", type=Path, help="Verified exact-client block-25539185 Raw export root")
    p.add_argument("--output", type=Path)
    p.add_argument("--check", action="store_true")
    a = p.parse_args()
    result = run(a.index_raw.read_bytes())
    if a.block_export:
        result["originalTableRawExports"] = inspect_original_export_dir(result, a.block_export)
    if a.check:
        if a.output is None or json.loads(a.output.read_text(encoding="utf-8")) != result:
            raise SystemExit("pinned 7.1 Lv3 original asset index report changed")
    elif a.output:
        a.output.parent.mkdir(parents=True, exist_ok=True)
        a.output.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
