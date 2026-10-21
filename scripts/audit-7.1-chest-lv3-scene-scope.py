#!/usr/bin/env python3
"""Audit chest Gadget coverage in the pinned 7.1-labelled scene scan artifact.

The CSV comes from a historical *resource copy* and its original read-only
GitHub Actions chest-region scan, not a native 7.1 client scene extraction.
Do not infer original placement or server chest reward semantics.
"""
from __future__ import annotations

import argparse
from collections import Counter
import csv
import hashlib
import io
import json
from pathlib import Path

CSV_SHA256 = "ba53152e17dbe019482920ad179ff90c62419d385390f9d0eb952dcb7895dcc1"
SUMMARY_SHA256 = "c2e81ab79eb891f448421a6944017c0d1ccc3547079fa1364dae8bde0a117d58"
NATIVE_GADGET_SHA256 = "a35e3f3ed04f950cb6302099d12aa71e23ece21d8fe578950347d9318f769e35"
SCANNER_COMMIT = "e2541630f5ae4d4c95b81f7440293d3419a776d1"
RESOURCE_COMMIT = "85b81a691fcf3d9e8e7db50a8febc8f9043bc084"
EXPECTED_RECORDS = 14084
REQUIRED_COLUMNS = ("scene", "file", "config_id", "gadget_id", "source", "drop_tag", "source_grade")
CORE = {70210000 + level * 10 + variant for level in range(1, 6)
        for variant in range(1, 5)}
LV3 = tuple(range(70210031, 70210035))
HISTORICAL_SAMPLE = {
    "combat": (70211001, 70211002, 70211011, 70211012,
               70211021, 70211022, 70211031, 70211032),
    "puzzle": (70211101, 70211102, 70211111, 70211112,
               70211121, 70211122, 70211131, 70211132),
}
ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / "versions/7.1.0-global/analyses/progression/economy/7.1-chest-native-gadget-prefab-controls.json"


def pinned_json(raw: bytes, digest: str):
    if hashlib.sha256(raw).hexdigest() != digest:
        raise ValueError("pinned scene summary SHA-256 mismatch")
    return json.loads(raw)


def audit(rows: list[dict], summary: dict, native: dict) -> dict:
    if summary.get("pinned_source") != {
        "resource_repository": "MeChen618/AstaPS-Resource",
        "resource_commit": RESOURCE_COMMIT,
        "scanner_repository": "RinoPaw/AstaPS",
        "scanner_commit": SCANNER_COMMIT,
    }:
        raise ValueError("historical scene scan input revision changed")
    totals = summary.get("totals", {})
    if (totals.get("ordinary_chests") != EXPECTED_RECORDS
            or totals.get("lua_files") != 41110 or totals.get("excluded_boss") != 43):
        raise ValueError("historical scene scan scope changed")
    if (native.get("source", {}).get("rawExportSha256") != NATIVE_GADGET_SHA256
            or native.get("controls", {}).get("verifiedGadgetDefinitionCount") != 20):
        raise ValueError("native original 7.1 Gadget source changed")
    observed_native = {int(row["gadgetIdPreWrapperScalar"])
                       for row in native["controls"]["nativeNameFields"]}
    if observed_native != CORE:
        raise ValueError("original client 20-ID control set changed")
    if len(rows) != EXPECTED_RECORDS:
        raise ValueError("scene CSV record count changed")
    counts: Counter[int] = Counter()
    by_grade: dict[int, Counter[str]] = {}
    for row in rows:
        if any(key not in row for key in REQUIRED_COLUMNS):
            raise ValueError("incomplete scene CSV schema")
        raw_id = row["gadget_id"]
        if not raw_id.isascii() or not raw_id.isdecimal():
            raise ValueError("nondecimal scene gadget ID")
        gid = int(raw_id)
        counts[gid] += 1
        by_grade.setdefault(gid, Counter())[row["source_grade"] or "(not-tagged)"] += 1
    core_counts = {str(gid): counts[gid] for gid in sorted(CORE)}
    historical = {
        group: [
            {"gadgetId": gid, "instanceCount": counts[gid],
             "gradeFromHistoricalDropTag": dict(sorted(by_grade.get(gid, Counter()).items()))}
            for gid in ids
        ]
        for group, ids in HISTORICAL_SAMPLE.items()
    }
    return {
        "schemaVersion": 1,
        "status": "LEGACY_SCENE_SNAPSHOT_HAS_ZERO_CORE_LV1_TO_LV5_PLACEMENTS__ORIGINAL_71_SCENE_UNVERIFIED",
        "evidence": {
            "githubActionsRun": "https://github.com/RinoPaw/Genshin-Reverse/actions/runs/38499376170",
            "artifact": "chest-region-71-audit/chest-region-per-gadget.csv",
            "sceneCsvSha256": CSV_SHA256,
            "sceneSummarySha256": SUMMARY_SHA256,
            "resourceCommit": RESOURCE_COMMIT,
            "scannerCommit": SCANNER_COMMIT,
            "originalNativeGadgetAssetSha256": NATIVE_GADGET_SHA256,
        },
        "sceneCandidateRecords": len(rows),
        "sceneGadgetIdsObserved": len(counts),
        "originalClientCoreDefinitionsChecked": len(CORE),
        "originalClientCoreDefinitionInstanceCounts": core_counts,
        "lv3OriginalClientDefinitionInstanceCounts": {str(i): counts[i] for i in LV3},
        "legacySourceSpecificGadgetSample": historical,
        "limitations": [
            "CSV is the previous resource-derived scan of gadgets whose community GadgetExcel type was Chest; it is not an authenticated original 7.1 client scene list.",
            "The four Lv3 and other core zero-counts apply only to this scanned resource/selection and cannot establish global absence.",
            "Other placed Gadget IDs with historical combat/puzzle tags have real counts in this resource copy but are not authenticated original 7.1 payout types.",
            "Audio labels, handbook ID membership and historical Chinese drop_tag are separate data with separate provenance.",
            "No original 7.1 reward grade, chest_drop_id, server payable root, amount or probability follows from these counts.",
        ],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--csv", type=Path, required=True)
    parser.add_argument("--summary", type=Path, required=True)
    parser.add_argument("--native", type=Path, default=NATIVE)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    raw_csv = args.csv.read_bytes()
    if hashlib.sha256(raw_csv).hexdigest() != CSV_SHA256:
        raise SystemExit("pinned chest scene CSV SHA-256 mismatch")
    rows = list(csv.DictReader(io.StringIO(raw_csv.decode("utf-8-sig"))))
    summary = pinned_json(args.summary.read_bytes(), SUMMARY_SHA256)
    native = json.loads(args.native.read_text(encoding="utf-8"))
    report = audit(rows, summary, native)
    serialized = json.dumps(report, indent=2, ensure_ascii=False) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(serialized, encoding="utf-8")
    print(serialized, end="")


if __name__ == "__main__":
    main()
