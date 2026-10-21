#!/usr/bin/env python3
"""Audit original Global 7.1 Gadget selector limits without assigning semantics.

Input is the committed 30,599-row-derived native field vectors, previously
decoded from the exact original binary. Verify source identity before using it.
This stage does not itself read the proprietary binary and does not claim
a grade, level, type or reward selector has been semantically reconstructed.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import json
from pathlib import Path

from genshinre.nativeprofile import PROFILE_71

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "versions/7.1.0-global/analyses/progression/economy/7.1-native-gadget-field-vectors.json"
OUTPUT = ROOT / "versions/7.1.0-global/analyses/progression/economy/7.1-native-gadget-selector-grade-level-boundary.json"
RAW_SHA = "a35e3f3ed04f950cb6302099d12aa71e23ece21d8fe578950347d9318f769e35"
KIND_26 = 26
SUFFIX_VARIANTS = ("Default", "Locked", "Bramble", "Frozen")
ICON = "UI_Icon_Intee_TreasureBox"


def value_or_absent(row: dict, offset: str) -> str:
    fields = row["gadgetByOffset"]
    return str(fields[offset]) if offset in fields else "absent"


def audit(report: dict) -> dict:
    source = report["source"]
    if (source["rawSha256"] != RAW_SHA or
            source["exeSha256"] != PROFILE_71.exe_sha256 or
            source["nativeGadgetReaderRva"] != "0x10278E50" or
            source["nativeInheritedReaderRva"] != "0xBD56F60" or
            source["decoder"] != "genshinre/gadgetbin.py"):
        raise ValueError("unverified or different original 7.1 Gadget source")
    if (report["controls"]["fullDecodedRows"] != 30599 or
            report["controls"]["numeric26Rows"] != 309 or
            report["controls"]["literalChestOutsideNumeric26Rows"] != 31):
        raise ValueError("original 7.1 complete table control mismatch")
    rows = report["numeric26Records"]
    if len(rows) != 309 or len({r["preWrapperKeyAt0x30"] for r in rows}) != 309:
        raise ValueError("original 7.1 numeric-26 key coverage mismatch")
    if any(r["gadgetByOffset"].get("0x6C") != KIND_26 for r in rows):
        raise ValueError("type-26 field changed")
    by_key = {r["preWrapperKeyAt0x30"]: r for r in rows}
    controls = []
    for lv in range(1, 6):
        for n, variant in enumerate(SUFFIX_VARIANTS, start=1):
            key = 70210000 + 10 * lv + n
            row = by_key[key]
            original_name = f"SceneObj_Chest_{variant}_Lv{lv}"
            if (row["literalAt0x58"] != original_name or
                    row["gadgetByOffset"].get("0x58") != original_name or
                    row["gadgetByOffset"].get("0x84") != 2 or
                    row["inheritedByOffset"].get("0x18") != 5001 or
                    row["gadgetByOffset"].get("0x50") != ICON):
                raise ValueError(f"original client control changed for key {key}")
            controls.append({
                "preWrapperKey": key,
                "literalName": original_name,
                "literalLvSuffix": lv,
                "offset0x84": 2,
                "inherited0x18": 5001,
            })
    normal = sorted(
        (r for r in rows if r["literalAt0x58"] == "SceneObj_Chest_NormalChest"),
        key=lambda r: r["preWrapperKeyAt0x30"])
    if [r["preWrapperKeyAt0x30"] for r in normal] != list(range(70210001, 70210007)):
        raise ValueError("six original normal-literal controls changed")
    normal_states = [value_or_absent(r, "0x84") for r in normal]
    if normal_states != ["1", "1", "1", "1", "1", "absent"]:
        raise ValueError("original normal-literal 0x84 states changed")
    lv4 = sorted(
        (r for r in rows if r["literalAt0x58"] == "SceneObj_Chest_Default_Lv4"),
        key=lambda r: r["preWrapperKeyAt0x30"])
    if len(lv4) != 8 or Counter(value_or_absent(r, "0x84") for r in lv4) != {
            "1": 2, "2": 1, "absent": 5}:
        raise ValueError("same-name Lv4 control 0x84 changed")
    distribution = Counter(value_or_absent(r, "0x84") for r in rows)
    if distribution != {"1": 97, "2": 21, "4": 29, "absent": 162}:
        raise ValueError("native 0x84 distribution changed")
    by_name = defaultdict(list)
    for row in rows:
        by_name[row["literalAt0x58"]].append(row)
    conflicting = sorted(
        name for name, siblings in by_name.items()
        if len(siblings) > 1 and len({
            value_or_absent(row, "0x84") for row in siblings}) > 1)
    if len(conflicting) != 11:
        raise ValueError("same-name native 0x84 disagreement count changed")
    non26_chest = sorted(
        (r for r in report["literalChestOutsideNumeric26Records"]
         if r["literalAt0x58"].startswith("SceneObj_Chest")),
        key=lambda r: r["preWrapperKeyAt0x30"])
    if len(non26_chest) != 5:
        raise ValueError("outside numeric26 SceneObj_Chest-prefix count changed")
    return {
        "schemaVersion": 1,
        "status": "VERIFIED_ORIGINAL_7_1_GADGET_FIELD_CONTROLS__SELECTOR_SEMANTICS_UNRESOLVED",
        "source": {
            "nativeVectorInventory": "versions/7.1.0-global/analyses/progression/economy/7.1-native-gadget-field-vectors.json",
            "originalRawSha256": RAW_SHA,
            "exeSha256": PROFILE_71.exe_sha256,
            "gadgetReaderRva": "0x10278E50",
            "inheritedReaderRva": "0xBD56F60",
            "origin": "source-verified original GadgetExcelConfigData rows; this audit uses decoded vectors",
        },
        "observations": {
            "canonicalLiteralLvControls": controls,
            "normalChestLiteralSix": [
                {"preWrapperKey": r["preWrapperKeyAt0x30"],
                 "offset0x84": value_or_absent(r, "0x84")} for r in normal],
            "sameLiteralDefaultLv4": [
                {"preWrapperKey": r["preWrapperKeyAt0x30"],
                 "offset0x84": value_or_absent(r, "0x84")} for r in lv4],
            "numeric26Offset0x84Counts": dict(sorted(distribution.items())),
            "repeatedLiteralNamesWithDifferent0x84": conflicting,
            "namedSceneObjChestOutsideNumeric26": [
                {"preWrapperKey": r["preWrapperKeyAt0x30"],
                 "literalName": r["literalAt0x58"],
                 "offset0x6C": r["gadgetByOffset"].get("0x6C")}
                for r in non26_chest],
        },
        "limits": [
            "These are original-client Gadget definition values, not verified scene-instance properties.",
            "0x84 is insufficient to represent the five literal Lv suffixes in these 20 controls.",
            "A literal Lv suffix is not an authenticated ordinary chest reward grade or scene level.",
            "The original source has no proven semantic binding to LootCSS grade or level.",
            "Pre-wrapper keys are not the verified final runtime wrapper values.",
            "No community, historical Lua, private-server semantics or reward tables were used.",
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=SOURCE)
    parser.add_argument("--output", type=Path, default=OUTPUT)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    native_vectors = json.loads(args.source.read_text(encoding="utf-8"))
    result = audit(native_vectors)
    if args.check:
        if json.loads(args.output.read_text(encoding="utf-8")) != result:
            raise SystemExit("verified Global 7.1 Gadget selector boundary changed")
        print("PASS: 20 canonical Lv controls, 6 same-name controls, and 309 native type-26 rows")
    else:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n",
                               encoding="utf-8")
        print(json.dumps({
            "status": result["status"],
            "native0x84Counts": result["observations"]["numeric26Offset0x84Counts"],
        }, indent=2))


if __name__ == "__main__":
    main()
