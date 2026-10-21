#!/usr/bin/env python3
"""Audit the historical four-grade regex against exact 7.1 native chest controls.

This deliberately does not map client Lv suffixes to payable grade/rewards.
The 20 native definitions are a bounded, pinned sample, not all Chest gadgets.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import runpy

ROOT = Path(__file__).resolve().parents[1]
PREFABS = ROOT / "versions/7.1.0-global/analyses/progression/economy/7.1-chest-native-gadget-prefab-controls.json"
LEGACY = ROOT / "scripts/audit-7.1-legacy-chest-sources.py"
SOURCE_SHA = "a35e3f3ed04f950cb6302099d12aa71e23ece21d8fe578950347d9318f769e35"
STYLES = ("Default", "Locked", "Bramble", "Frozen")


def audit(native: dict, old_prefab_regex) -> dict:
    if (native.get("schemaVersion") != 2 or
            native.get("source", {}).get("rawExportSha256") != SOURCE_SHA or
            native.get("source", {}).get("assetName") != "GadgetExcelConfigData"):
        raise ValueError("unexpected original 7.1 Gadget control source")
    rows = native["controls"]["nativeNameFields"]
    if native["controls"]["verifiedGadgetDefinitionCount"] != 20 or len(rows) != 20:
        raise ValueError("expected exactly 20 source-pinned core prefab controls")
    by_id = {}
    for row in rows:
        gid = row["gadgetIdPreWrapperScalar"]
        if gid in by_id:
            raise ValueError("duplicate source-pinned native gadget scalar")
        by_id[gid] = row
    expected_ids = {70210000 + level * 10 + variant for level in range(1, 6)
                    for variant in range(1, 5)}
    if set(by_id) != expected_ids:
        raise ValueError("source-pinned core prefab ID coverage changed")
    detail = []
    for gid in sorted(by_id):
        row = by_id[gid]
        level = (gid - 70210000) // 10
        style = STYLES[(gid - 70210000) % 10 - 1]
        expected_name = f"SceneObj_Chest_{style}_Lv{level}"
        if (row["nameSuffixLevel"] != level or row["nameVariant"] != style
                or row["nativeNameString"] != expected_name):
            raise ValueError(f"original native name or suffix mismatch: {gid}")
        included = bool(old_prefab_regex.fullmatch(expected_name))
        detail.append({"nativeGadgetIdPreWrapperScalar": gid,
                       "nativeName": expected_name, "literalLvSuffix": level,
                       "historicalFourGradeRegexIncluded": included})
    selected = [r for r in detail if r["historicalFourGradeRegexIncluded"]]
    excluded = [r for r in detail if not r["historicalFourGradeRegexIncluded"]]
    if (len(selected) != 16 or len(excluded) != 4
            or {r["literalLvSuffix"] for r in excluded} != {3}):
        raise ValueError("historical four-grade source scope changed; re-audit")
    return {
        "schemaVersion": 1,
        "status": "EXACT_7_1_NATIVE_CORE_LV3_EXCLUDED_BY_HISTORICAL_FOUR_GRADE_FILTER__SEMANTICS_UNKNOWN",
        "originalClientAssetSha256": SOURCE_SHA,
        "originalClientCoreDefinitions": 20,
        "historicalFourGradeFilterMatches": len(selected),
        "historicalFourGradeFilterExcludes": len(excluded),
        "excludedNativeSuffixes": [3],
        "excludedNativeIds": [r["nativeGadgetIdPreWrapperScalar"] for r in excluded],
        "scope": "Only the 20 exact original-client Default/Locked/Bramble/Frozen x Lv1..Lv5 controls",
        "limitations": [
            "The source labels Lv1..Lv5 are literal original-client strings; reward-grade meanings are unverified.",
            "A legacy source scanner selects 1,2,4,5; its statistics cannot describe Lv3 placements.",
            "Excluding a native gadget definition in a scanner does not prove that it is absent from world placements.",
            "This comparison does not authenticate historical scene Lua, server drop_tag, chest root IDs or payout amounts.",
        ],
    }


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--native-report", type=Path, default=PREFABS)
    p.add_argument("--legacy-script", type=Path, default=LEGACY)
    a = p.parse_args()
    regex = runpy.run_path(str(a.legacy_script))["PREFAB"]
    print(json.dumps(audit(json.loads(a.native_report.read_text(encoding="utf-8")), regex),
                     ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
