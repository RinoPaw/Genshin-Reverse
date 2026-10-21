#!/usr/bin/env python3
"""Cross-check historical scene drop_tag names with the pinned AstaPS selectors.

The 7.1-labelled scene Lua copy and ChestDrop.json are HISTORICAL COMMUNITY
SOURCES. Full selector-name coverage does not authenticate original Global 7.1
server data, claim dispatch, root contents or actual payout weights.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import csv
import hashlib
import io
import json
from pathlib import Path

SCENE_CSV_SHA256 = "ba53152e17dbe019482920ad179ff90c62419d385390f9d0eb952dcb7895dcc1"
CHEST_DROP_GIT_BLOB = "789e885d37535280dc923e5c69e1aa2fc23714dd"
SCENE_RESOURCE_COMMIT = "85b81a691fcf3d9e8e7db50a8febc8f9043bc084"
ASTAPS_COMMIT = "dcf04369a356486a07be976b244b83d7208c3992"
EXPECTED_SCENE_RECORDS = 14084
EXPECTED_TAG_RECORDS = 9020
EXPECTED_TAGS = 109

# Lexical grouping of historical Chinese names, no gameplay tier inference.
FAMILIES = (
    ("combat_or_puzzle", ("战斗", "雪山战斗", "解谜", "雪山解谜")),
    ("search_point", ("搜刮点", "水上搜刮点", "一次性搜刮点")),
    ("mora_container", ("摩拉石箱",)),
    ("shrine", ("灵龛",)),
    ("book_page", ("书页",)),
    ("event", ("逐月节", "渊下宫活动")),
    ("crimson_agate", ("雪山玉髓",)),
)
EXPECTED_FAMILY_COUNTS = {
    "combat_or_puzzle": 5252,
    "search_point": 2869,
    "mora_container": 530,
    "shrine": 38,
    "book_page": 80,
    "event": 223,
    "crimson_agate": 28,
}


def sha256_gate(raw: bytes, expected: str, label: str) -> None:
    if hashlib.sha256(raw).hexdigest() != expected:
        raise ValueError(f"{label}: pinned SHA-256 mismatch")


def blob_gate(raw: bytes, expected: str, label: str) -> None:
    git_blob = hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
    if git_blob != expected:
        raise ValueError(f"{label}: pinned Git blob mismatch")


def family(tag: str) -> str:
    matched = [name for name, prefixes in FAMILIES if tag.startswith(prefixes)]
    if len(matched) != 1:
        raise ValueError(f"historical source label has ambiguous/no prefix family: {tag}")
    return matched[0]


def analyze(scene_rows: list[dict], selectors: list[dict], *, enforce_original: bool = True) -> dict:
    if enforce_original and len(scene_rows) != EXPECTED_SCENE_RECORDS:
        raise ValueError("historical scene candidate count changed")
    tagged = [r for r in scene_rows if r.get("source") == "drop_tag"]
    if enforce_original and len(tagged) != EXPECTED_TAG_RECORDS:
        raise ValueError("historical tagged scene count changed")
    tag_counts = Counter()
    family_counts: Counter[str] = Counter()
    family_oneoff: Counter[str] = Counter()
    family_explore: Counter[str] = Counter()
    family_gadgets: dict[str, set[int]] = defaultdict(set)
    for row in tagged:
        tag = row.get("drop_tag", "")
        if not tag or int(row.get("chest_drop_id", "0")) != 0:
            raise ValueError("tagged scene row has missing tag or explicit reward ID")
        grp = family(tag)
        tag_counts[tag] += 1
        family_counts[grp] += 1
        family_gadgets[grp].add(int(row["gadget_id"]))
        if row.get("is_oneoff") not in ("True", "False") or row.get("explore_chest") not in ("True", "False"):
            raise ValueError("historical Lua oneoff/explore projection changed")
        family_oneoff[grp] += (row["is_oneoff"] == "True")
        family_explore[grp] += (row["explore_chest"] == "True")
    if enforce_original and (len(tag_counts) != EXPECTED_TAGS
                             or {name: family_counts[name] for name, _ in FAMILIES} != EXPECTED_FAMILY_COUNTS):
        raise ValueError("historical tag family counts changed")

    index: dict[str, list[dict]] = defaultdict(list)
    for row in selectors:
        if not isinstance(row, dict):
            raise ValueError("malformed ChestDrop selector")
        tag, threshold, root = row.get("index"), row.get("minLevel"), row.get("dropId")
        if (not isinstance(tag, str) or not tag
                or type(threshold) is not int or threshold < 1
                or type(root) is not int or root <= 0):
            raise ValueError("malformed ChestDrop name/level/root")
        index[tag].append(row)
    duplicate_levels = {
        tag: sorted(Counter(r["minLevel"] for r in rs).items())
        for tag, rs in index.items()
        if len({r["minLevel"] for r in rs}) != len(rs)
    }
    if duplicate_levels:
        raise ValueError("duplicate ChestDrop minLevel for same tag")

    unmatched = sorted(set(tag_counts) - set(index))
    selected = [r for tag in tag_counts for r in index.get(tag, [])]
    rows_by_family: dict[str, dict] = {}
    for name, _ in FAMILIES:
        names = sorted(t for t in tag_counts if family(t) == name)
        matches = [r for tag in names for r in index.get(tag, [])]
        rows_by_family[name] = {
            "historicalInstances": family_counts[name],
            "distinctTags": len(names),
            "taggedOneoffTrue": family_oneoff[name],
            "taggedExploreChestTrue": family_explore[name],
            "distinctHistoricalGadgetIds": len(family_gadgets[name]),
            "matchedSelectorRows": len(matches),
            "matchedDistinctRoots": len({r["dropId"] for r in matches}),
            "unmatchedNames": [tag for tag in names if tag not in index],
        }
    if enforce_original and (
        len(selectors) != 1771 or len(index) != 215 or unmatched
        or len(selected) != 229 or len({r["dropId"] for r in selected}) != 158
    ):
        raise ValueError("pinned historical scene to AstaPS ChestDrop selector coverage changed")
    return {
        "schemaVersion": 1,
        "status": "HISTORICAL_SCENE_TAG_NAMES_ALL_MATCH_ASTAPS_CHESTDROP__ORDINARY_CLAIM_NOT_USING_TAG_LOOKUP",
        "sources": {
            "historicalSceneCSVsha256": SCENE_CSV_SHA256 if enforce_original else None,
            "historicalSceneResourceCommit": SCENE_RESOURCE_COMMIT,
            "forkChestDropJsonGitBlob": CHEST_DROP_GIT_BLOB if enforce_original else None,
            "forkImplementationCommit": ASTAPS_COMMIT,
        },
        "historicalTaggedInstances": len(tagged),
        "historicalDistinctTags": len(tag_counts),
        "forkChestDropSelectorRows": len(selectors),
        "forkChestDropDistinctTags": len(index),
        "sceneTagNamesWithForkSelector": len(tag_counts) - len(unmatched),
        "sceneTagNamesWithoutForkSelector": unmatched,
        "matchingForkSelectorRows": len(selected),
        "matchingDistinctForkRoots": len({r["dropId"] for r in selected}),
        "families": rows_by_family,
        "examples": {
            tag: [{"minLevel": r["minLevel"], "dropId": r["dropId"],
                   "sourceType": r.get("sourceType"), "type": r.get("type")}
                  for r in index.get(tag, [])]
            for tag in ("战斗低级蒙德", "解谜中级璃月", "搜刮点解谜通用须弥",
                        "摩拉石箱须弥", "书页章节1稻妻", "灵龛蒙德")
            if tag in tag_counts
        },
        "limitations": [
            "Prefix groups are historical label lexemes; they do not establish an official four-grade chest classification.",
            "A matching label and historical fork root do not prove that ordinary GadgetChest invokes tag-to-root dispatch; current fork skips that overload.",
            "The historical scene CSV omits per-instance Lua level; multiple minLevel entries for a tag prevent selecting a specific root for any scanned object.",
            "Some tagged scene gadgets are search points, mora containers, shrine/page/event objects; they are not automatically ordinary claimable chests.",
            "Neither historical scene Lua nor the fork ChestDrop JSON has authenticated Global 7.1 server reward-source ancestry.",
            "Matched root IDs give no verified root existence, contents, drop weights, payable amounts or 7.1 server behavior.",
        ],
    }


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--scene-csv", type=Path, required=True)
    p.add_argument("--chest-drop", type=Path, required=True)
    p.add_argument("--output", type=Path)
    a = p.parse_args()
    scene_raw = a.scene_csv.read_bytes()
    drop_raw = a.chest_drop.read_bytes()
    sha256_gate(scene_raw, SCENE_CSV_SHA256, "historical scene")
    blob_gate(drop_raw, CHEST_DROP_GIT_BLOB, "fork chest selectors")
    scene_rows = list(csv.DictReader(io.StringIO(scene_raw.decode("utf-8-sig"))))
    result = analyze(scene_rows, json.loads(drop_raw))
    output = json.dumps(result, ensure_ascii=False, indent=2) + "\n"
    if a.output:
        a.output.parent.mkdir(parents=True, exist_ok=True)
        a.output.write_text(output, encoding="utf-8")
    print(output, end="")


if __name__ == "__main__":
    main()
