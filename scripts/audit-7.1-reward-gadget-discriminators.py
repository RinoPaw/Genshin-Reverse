#!/usr/bin/env python3
"""Audit *discriminating attributes*, never reward contents or weights.

Exact Global 7.1 native Gadget identities are separately source-pinned.
The historical Lua scan may describe older scenes; it is used solely to show
which fields can and cannot distinguish different Gadget instances.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import csv
import hashlib
import io
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CONTROL = ROOT / "versions/7.1.0-global/analyses/progression/economy/7.1-chest-native-gadget-prefab-controls.json"
SCENE_SHA = "ba53152e17dbe019482920ad179ff90c62419d385390f9d0eb952dcb7895dcc1"
NATIVE_SHA = "a35e3f3ed04f950cb6302099d12aa71e23ece21d8fe578950347d9318f769e35"
SCENE_RECORDS = 14084
EXPECTED_CORE = {
    70210000 + level * 10 + variant
    for level in range(1, 6) for variant in range(1, 5)
}
SCENE_FIELDS = (
    "scene", "file", "config_id", "gadget_id", "x", "y", "z",
    "source", "drop_tag", "chest_drop_id", "lua_area_id",
    "city_id", "area1", "area2", "lookup_status", "source_region",
    "source_grade", "is_oneoff", "persistent", "explore_chest",
)


def native_ids(control: dict) -> set[int]:
    if (control.get("source", {}).get("rawExportSha256") != NATIVE_SHA
            or control.get("controls", {}).get("verifiedGadgetDefinitionCount") != 20):
        raise ValueError("exact Global 7.1 Gadget source identity changed")
    entries = control["controls"]["nativeNameFields"]
    ids = {r["gadgetIdPreWrapperScalar"] for r in entries}
    if len(entries) != 20 or ids != EXPECTED_CORE:
        raise ValueError("original 20 Gadget name/ID controls changed")
    for r in entries:
        if (r["nativeNameString"] !=
                f'SceneObj_Chest_{r["nameVariant"]}_Lv{r["nameSuffixLevel"]}'):
            raise ValueError("original prefab name pattern changed")
    return ids


def audit(rows: list[dict[str, str]], control: dict, *, full: bool = True) -> dict:
    core = native_ids(control)
    if full and len(rows) != SCENE_RECORDS:
        raise ValueError("historical scene census cardinality changed")
    id_rows: dict[str, list[dict]] = defaultdict(list)
    identities = set()
    source_counts = Counter()
    for row in rows:
        if any(k not in row for k in SCENE_FIELDS):
            raise ValueError("historical CSV schema changed")
        identity = (row["file"], row["config_id"])
        if identity in identities:
            raise ValueError("duplicate historical file/config Gadget identity")
        identities.add(identity)
        for k in ("scene", "config_id", "gadget_id"):
            if not row[k].isascii() or not row[k].isdecimal():
                raise ValueError(f"invalid numeric scene identity: {k}")
        if row["source"] not in ("drop_tag", "explicit_id", "no_metadata"):
            raise ValueError("unknown historical reward-source marker")
        if any(row[k] not in ("True", "False")
               for k in ("is_oneoff", "persistent", "explore_chest")):
            raise ValueError("invalid historical oneoff/persistence flag")
        source_counts[row["source"]] += 1
        id_rows[row["gadget_id"]].append(row)

    def sources(records: list[dict]) -> list[str]:
        return sorted(set(r["source"] for r in records))

    mixed = {gid: records for gid, records in id_rows.items()
             if len(sources(records)) > 1}
    all_three = {gid: records for gid, records in id_rows.items()
                 if len(sources(records)) == 3}
    multi_tag = {gid: records for gid, records in id_rows.items()
                 if len({r["drop_tag"] for r in records if r["drop_tag"]}) > 1}
    grades = {gid: records for gid, records in id_rows.items()
              if len({r["source_grade"] for r in records if r["source_grade"]}) > 1}

    examples = {}
    for gid in ("70210101", "70211101", "70211001", "70217020"):
        if gid not in id_rows:
            continue
        records = id_rows[gid]
        tags = Counter(r["drop_tag"] for r in records if r["drop_tag"])
        examples[gid] = {
            "instances": len(records),
            "sourceCounts": dict(sorted(Counter(r["source"] for r in records).items())),
            "distinctDropTags": len(tags),
            "exampleTags": [tag for tag, _ in tags.most_common(5)],
            "differentSourceGradeValues": sorted(
                {r["source_grade"] for r in records if r["source_grade"]}),
            "oneoffValuesObserved": sorted({r["is_oneoff"] for r in records}),
            "historicalSource": "community Lua; cannot certify exact 7.1",
        }
    observed = {int(gid) for gid in id_rows}
    if full and (source_counts != {"drop_tag": 9020, "explicit_id": 1339,
                                    "no_metadata": 3725}
                 or len(id_rows) != 171
                 or len(mixed) != 37 or len(all_three) != 21
                 or len(multi_tag) != 28
                 or len(grades) != 3 or (core & observed)):
        raise ValueError("historical Gadget discrimination statistics changed")

    return {
        "schemaVersion": 1,
        "status": "GADGET_IDENTITY_AND_INSTANCE_ATTRIBUTES__EXACT_NATIVE_NAMES_PLUS_HISTORICAL_LUA_SCOPE",
        "nativeGlobal71": {
            "originalGadgetRawSha256": NATIVE_SHA,
            "corePrefabIdentities": len(core),
            "attributesFromNativeControl": [
                "gadgetIdPreWrapperScalar", "nativeNameString",
                "nameVariant", "nameSuffixLevel", "sourceTypeCandidate",
                "nativeIconString", "nativeInheritedMask",
                "offset0x48PresentOnWire", "offset0x84Scalar",
                "booleanTrueOffsets",
            ],
            "originalPlacementOrOfficialLootGradeProven": False,
        },
        "historicalScene": {
            "sceneCsvSha256": SCENE_SHA if full else None,
            "recordCount": len(rows),
            "uniqueGadgetIds": len(id_rows),
            "sourceCounts": dict(sorted(source_counts.items())),
            "gadgetIdsWithMultipleSourceKinds": len(mixed),
            "gadgetIdsWithAllThreeSourceKinds": len(all_three),
            "gadgetIdsWithMultipleDropTags": len(multi_tag),
            "gadgetIdsWithMultipleChineseGradeSubstrings": len(grades),
            "native20CoreIdsObserved": len(core & observed),
            "sceneRowAvailableKeys": list(SCENE_FIELDS),
            "perInstanceLevelAvailableInThisCSV": "level" in SCENE_FIELDS,
            "selectorDiscriminators": [
                "scene + file/group + config_id (instance identity)",
                "gadget_id (definition identity, ambiguous alone)",
                "drop_tag (historical selector/source type, when present)",
                "chest_drop_id (separate explicit-source marker, when present)",
                "is_oneoff / persistent / explore_chest (lifecycle hints only)",
                "lua_area_id + city_id + area1/area2 (source/derived region; verify provenance)",
                "coordinates x/y/z (location, not automatic reward grade)",
            ],
            "ambiguousIds": examples,
        },
        "cannotDerive": [
            "Gadget ID alone cannot determine reward-source kind, ordinary chest tier or payout.",
            "The native class/type candidate 26 includes special gadgets and SearchPoint-like names; it is not an ordinary-chest selector.",
            "The scene CSV omits per-instance level and dynamic spawn state; zero or missing values are not a valid inferred level.",
            "Name Lv1..Lv5 suffix, historical Chinese low/mid/high/super string, and audio Mid/Hi/Top are three different unproven-to-be-equivalent classifications.",
            "chestType, chestGrade and rewardRegion are fork/importer-added annotations, not authenticated original 7.1 wire fields.",
            "No original Global 7.1 placed instance identifiers or server reward data established by this report.",
        ],
    }


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--scene-csv", type=Path, required=True)
    p.add_argument("--native-control", type=Path, default=CONTROL)
    p.add_argument("--output", type=Path)
    a = p.parse_args()
    raw = a.scene_csv.read_bytes()
    if hashlib.sha256(raw).hexdigest() != SCENE_SHA:
        raise SystemExit("historical CSV SHA-256 mismatch")
    rows = list(csv.DictReader(io.StringIO(raw.decode("utf-8-sig"))))
    control = json.loads(a.native_control.read_text(encoding="utf-8"))
    report = audit(rows, control)
    result = json.dumps(report, indent=2, ensure_ascii=False) + "\n"
    if a.output:
        a.output.parent.mkdir(parents=True, exist_ok=True)
        a.output.write_text(result, encoding="utf-8")
    print(result, end="")


if __name__ == "__main__":
    main()
