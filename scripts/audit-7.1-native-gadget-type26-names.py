#!/usr/bin/env python3
"""Extract original Global 7.1 Gadget type-26 *literal name* groups.

The source must be the exact pinned original GadgetExcel Raw asset.
Buckets are purely string-prefix observations; no inferred chest grade,
scene placement, drop_tag, payable root, or server-side probability.
Optionally export the 309 decoded rows as derived local JSON for explicit
scene-instance crosschecks, without storing raw game asset bytes in Git.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import re

from genshinre.assetindex import unwrap_mihoyo_bin_data
from genshinre.gadgetbin import scan_gadget_payload

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = (ROOT / "versions/7.1.0-global/analyses/progression/economy"
          / "7.1-chest-native-gadget-type26-name-groups.json")
RAW_SHA = "a35e3f3ed04f950cb6302099d12aa71e23ece21d8fe578950347d9318f769e35"
PAYLOAD_SHA = "b8f35d6f3fe1aec90398ccbbe205335fe0d9ae45245b206096be5e434746c354"
SOURCE_BYTES = 2854888
EXPECTED_ROWS = 30599
EXPECTED_TYPE26 = 309


def name_group(name: str) -> str:
    if name.startswith("SceneObj_Chest"):
        return "literal_SceneObj_Chest_prefix"
    if name.startswith("SearchPoint"):
        return "literal_SearchPoint_prefix"
    return "other_literal_names"


def analyze(scan) -> tuple[dict, list[dict]]:
    found = [row for row in scan.rows if row.fields.get(0x6C) == 26]
    if len(found) != EXPECTED_TYPE26:
        raise ValueError(f"native type-code-26 population changed: {len(found)}")
    ids = [row.gadget_id for row in found]
    if len(set(ids)) != len(ids):
        raise ValueError("duplicate source 7.1 wire-key scalars")
    groups: dict[str, list] = {
        "literal_SceneObj_Chest_prefix": [],
        "literal_SearchPoint_prefix": [],
        "other_literal_names": [],
    }
    details: list[dict] = []
    suffix_regex = re.compile(r"_Lv[1-5]$")
    for row in found:
        name = row.fields.get(0x58)
        if not isinstance(name, str) or not name:
            raise ValueError(f"native Gadget type26 name missing at wire key {row.gadget_id}")
        group = name_group(name)
        groups[group].append(row)
        details.append({
            "preWrapperWireKey": row.gadget_id,
            "literalNativeName": name,
            "nativeNameGroup": group,
            "nativeInheritedMask": f"0x{row.base_mask:02X}",
            "nativeGadgetMask": f"0x{row.mask:X}",
            "fieldsPresentAtMemoryOffsets": [f"0x{k:X}" for k in sorted(row.fields)],
            "nativeFieldsByCandidateMemoryOffset": {
                f"0x{k:X}": row.fields[k] for k in sorted(row.fields)
            },
        })
    summaries = {}
    for group, items in groups.items():
        counts = Counter(row.fields[0x58] for row in items)
        top = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))[:6]
        summaries[group] = {
            "records": len(items),
            "distinctLiteralNames": len(counts),
            "withLiteralLv1ThroughLv5Suffix": sum(
                bool(suffix_regex.search(row.fields[0x58])) for row in items),
            "exampleNameFrequencies": [{"name": name, "records": n} for name, n in top],
        }
    return {
        "schemaVersion": 1,
        "status": "EXACT_7_1_GADGET_TYPE26_LITERAL_NAME_GROUPS__REWARD_CLASSIFICATION_UNVERIFIED",
        "source": {
            "sample": "7.1.0-global/windows-x64",
            "officialBlock": "00/25539185.blk",
            "asset": "GadgetExcelConfigData",
            "rawExportSha256": RAW_SHA,
            "payloadSha256": PAYLOAD_SHA,
            "nativeTableLoaderRva": "0x968F690",
            "nativeInheritedReaderRva": "0xBD56F60",
            "nativeGadgetReaderRva": "0x10278E50",
        },
        "observed": {
            "allGadgetDefinitions": len(scan.rows),
            "nativeTypeCodeCandidate": 26,
            "nativeType26Definitions": len(found),
            "distinctNameStrings": len({r.fields[0x58] for r in found}),
            "groupingRule": "case-sensitive literal string startswith only",
            "groups": summaries,
            "embeddedSearchPointOutsideLiteralPrefix": sum(
                "SearchPoint" in r.fields[0x58]
                for r in groups["other_literal_names"]),
            "literalLvSuffixTotal": sum(
                bool(suffix_regex.search(r.fields[0x58])) for r in found),
        },
        "limitations": [
            "Literal name prefixes are directly read from the original client and do not encode payable chest classification.",
            "A Gadget type-code candidate 26 also covers SearchPoint, puzzle and event objects; treating every row as an ordinary chest is unsafe.",
            "Literal Lv1..Lv5 suffixes do not identify server reward grades or item amounts.",
            "The inherited uint32 key is a pre-wrapper wire scalar; runtime substitution-table round trip is unverified.",
            "The exact 7.1 scene/group/config placement and server drop_tag owner remain unknown.",
            "The optional detailed output is decoded derivative data, not verified original scene placement or server reward data.",
        ],
    }, details


def audit(raw: bytes) -> tuple[dict, list[dict]]:
    if (len(raw) != SOURCE_BYTES
            or hashlib.sha256(raw).hexdigest() != RAW_SHA):
        raise ValueError("exact 7.1 Gadget raw SHA-256/size mismatch")
    payload = unwrap_mihoyo_bin_data(raw)
    if hashlib.sha256(payload).hexdigest() != PAYLOAD_SHA:
        raise ValueError("exact 7.1 Gadget payload SHA-256 mismatch")
    return analyze(scan_gadget_payload(payload, expected_rows=EXPECTED_ROWS))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--raw-export", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=OUTPUT)
    parser.add_argument("--detail-output", type=Path)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    result, details = audit(args.raw_export.read_bytes())
    if args.check:
        if json.loads(args.output.read_text(encoding="utf-8")) != result:
            raise SystemExit("native type26 name-group audit differs from pinned source")
        print("PASS: all 309 original 7.1 type26 names and literal groups")
    else:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(result, indent=2, ensure_ascii=False)+"\n",
                               encoding="utf-8")
    if args.detail_output:
        args.detail_output.parent.mkdir(parents=True, exist_ok=True)
        args.detail_output.write_text(json.dumps({
            "sample": result["source"], "records": details,
            "classificationAuthority": "literal native Gadget fields only"
        }, indent=2, ensure_ascii=False)+"\n", encoding="utf-8")


if __name__ == "__main__":
    main()
