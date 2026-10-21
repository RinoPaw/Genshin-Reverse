#!/usr/bin/env python3
"""Bound ordinary-chest payout routing to two exact, separate source snapshots.

Historical scene candidates came from the pinned AstaPS-Resource Lua scan.
Java branches came from RinoPaw/AstaPS at a separate, pinned main commit.
Neither snapshot authenticates original Genshin 7.1 server reward tables.
"""
from __future__ import annotations

import argparse
from collections import Counter
import csv
import hashlib
import io
import json
from pathlib import Path
import re

SCENE_CSV_SHA256 = "ba53152e17dbe019482920ad179ff90c62419d385390f9d0eb952dcb7895dcc1"
SCENE_SUMMARY_SHA256 = "c2e81ab79eb891f448421a6944017c0d1ccc3547079fa1364dae8bde0a117d58"
RESOURCE_COMMIT = "85b81a691fcf3d9e8e7db50a8febc8f9043bc084"
SCENE_SCANNER_COMMIT = "e2541630f5ae4d4c95b81f7440293d3419a776d1"
ASTAPS_COMMIT = "dcf04369a356486a07be976b244b83d7208c3992"
JAVA_GIT_BLOBS = {
    "GadgetChest": "72293aed5983092fe0e27d992ba3c1ba08c5f4b7",
    "DropSystem": "e04918a478e75414435f89f8bfd002f39d804af3",
    "WorldChestLootHelper": "395092db65f81407087f98275bb2b57bfc976517",
}
TOTAL = 14084
SOURCE_CLASSES = ("drop_tag", "explicit_id", "no_metadata")


def require_sha256(data: bytes, digest: str, label: str) -> None:
    actual = hashlib.sha256(data).hexdigest()
    if actual != digest:
        raise ValueError(f"{label} SHA-256 mismatch: {actual}")


def require_blob(data: bytes, digest: str, label: str) -> None:
    actual = hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()
    if actual != digest:
        raise ValueError(f"{label} Git blob mismatch: {actual}")


def checked_scene(rows: list[dict[str, str]], summary: dict, *, full: bool = True) -> dict:
    if full:
        if summary.get("pinned_source") != {
            "resource_repository": "MeChen618/AstaPS-Resource",
            "resource_commit": RESOURCE_COMMIT,
            "scanner_repository": "RinoPaw/AstaPS",
            "scanner_commit": SCENE_SCANNER_COMMIT,
        }:
            raise ValueError("historical Lua scan source revision changed")
        if len(rows) != TOTAL or summary.get("totals", {}).get("ordinary_chests") != TOTAL:
            raise ValueError("historical candidate census record count changed")
    by_source: Counter[str] = Counter()
    scene3: Counter[str] = Counter()
    oneoff: dict[str, Counter[str]] = {kind: Counter() for kind in SOURCE_CLASSES}
    explored: dict[str, Counter[str]] = {kind: Counter() for kind in SOURCE_CLASSES}
    unique_tags, unique_roots, identities = set(), set(), set()
    for row in rows:
        kind = row.get("source")
        if kind not in SOURCE_CLASSES:
            raise ValueError(f"unrecognized resource-derived candidate source: {kind}")
        try:
            root = int(row["chest_drop_id"])
            scene = int(row["scene"])
            config = int(row["config_id"])
            gadget = int(row["gadget_id"])
        except (ValueError, KeyError) as exc:
            raise ValueError("invalid historical chest scene row identifiers") from exc
        tag = row.get("drop_tag") or ""
        if (kind == "drop_tag" and (not tag or root != 0)
                or kind == "explicit_id" and (root <= 0 or tag)
                or kind == "no_metadata" and (tag or root != 0)):
            raise ValueError(f"inconsistent scene extraction classification: {kind}")
        identity = (row["file"], config)
        if identity in identities:
            raise ValueError("duplicate scene file/config identity")
        identities.add(identity)
        if gadget <= 0 or scene <= 0:
            raise ValueError("invalid scene/Gadget identity")
        by_source[kind] += 1
        if scene == 3:
            scene3[kind] += 1
        flag = row.get("is_oneoff", "")
        explore = row.get("explore_chest", "")
        if flag not in ("True", "False") or explore not in ("True", "False"):
            raise ValueError("unknown historical Lua boolean projection")
        oneoff[kind][flag] += 1
        explored[kind][explore] += 1
        if tag:
            unique_tags.add(tag)
        if root > 0:
            unique_roots.add(root)
    if full:
        totals = summary["totals"]
        if any(totals.get("source_" + kind) != by_source[kind] for kind in SOURCE_CLASSES):
            raise ValueError("historical scan summary/source counts disagree")
    return {
        "totalCandidates": len(rows),
        "sourceCounts": {kind: by_source[kind] for kind in SOURCE_CLASSES},
        "sourceSharePercent": {kind: round(100 * by_source[kind] / len(rows), 2)
                               for kind in SOURCE_CLASSES},
        "scene3Counts": {kind: scene3[kind] for kind in SOURCE_CLASSES},
        "distinctHistoricalDropTags": len(unique_tags),
        "distinctHistoricalExplicitRoots": len(unique_roots),
        "oneoffCounts": {kind: dict(oneoff[kind]) for kind in SOURCE_CLASSES},
        "exploreChestCounts": {kind: dict(explored[kind]) for kind in SOURCE_CLASSES},
    }


def checked_java(java: dict[str, str]) -> dict:
    ordinary = java["GadgetChest"].split("private void grantOrdinaryChestLoot(Player player) {", 1)[1].split(
        "protected boolean grantBossChestFallback", 1)[0]
    if (not all(token in ordinary for token in (
        "meta.chest_drop_id > 0",
        "SceneType.SCENE_DUNGEON",
        "gadget.getGroupId() == 0",
        "dropSystem.hasQuestItemDrop(meta.chest_drop_id)",
        "dropSystem.handleChestDrop(",
        "meta.chest_drop_id, Math.max(1, meta.drop_count), gadget",
        "WorldChestLootHelper.grant(player, gadget)",
    )) or "meta.drop_tag" in ordinary):
        raise ValueError("pinned ordinary-chest claim path changed")
    drop = java["DropSystem"]
    if ("public boolean handleChestDrop(String dropTag, int level, GameEntity bornFrom)" not in drop
            or "int dropId = queryDropData(dropTag, level, chestReward)" not in drop):
        raise ValueError("pinned tag-based DropSystem overload changed")
    fallback = java["WorldChestLootHelper"]
    if (not all(s in fallback for s in (
        "public static Tier resolveTier",
        "sceneGadget.drop_tag",
        "containsLv(string, 5)",
        "containsLv(string, 4)",
        "containsLv(string, 3)",
        "containsLv(string, 2)",
        "containsLv(string, 1)",
    ))):
        raise ValueError("pinned name/tag quality inference changed")
    expected = {"COMMON": 66, "EXQUISITE": 166, "PRECIOUS": 366, "LUXURIOUS": 566}
    actual = {}
    for name in expected:
        m = re.search(r"(?m)^\s*" + name + r"\((\d+),", fallback)
        if m is None:
            raise ValueError("pinned hardcoded ordinary-chest reward table changed")
        actual[name] = int(m.group(1))
    if actual != expected:
        raise ValueError("pinned ordinary fallback Primogem quantities changed")
    return {
        "ordinaryClaimSource": "GadgetChest.grantOrdinaryChestLoot",
        "explicitChestDropIdOnlyWhen": [
            "SceneType.SCENE_DUNGEON",
            "entity groupId == 0",
            "DropSystem.hasQuestItemDrop(chest_drop_id)",
        ],
        "ordinaryClaimDirectlyCallsTagTable": False,
        "dropSystemTagTableOverloadExists": True,
        "otherwiseFallsBackTo": "WorldChestLootHelper.grant",
        "fallbackTierEvidence": "Gadget ID, jsonName Lv string, historical scene drop_tag substrings",
        "hardcodedFallbackPrimogems": actual,
    }


def make_report(rows: list[dict], summary: dict, java: dict[str, str],
                *, full: bool = True) -> dict:
    return {
        "schemaVersion": 1,
        "status": "PINNED_HISTORICAL_SCENE_AND_CURRENT_FORK_CLAIM_BRANCH_AUDIT__OFFICIAL_71_PAYOUT_UNKNOWN",
        "source": {
            "sceneCsvSha256": SCENE_CSV_SHA256 if full else None,
            "sceneSummarySha256": SCENE_SUMMARY_SHA256 if full else None,
            "sceneResourceCommit": RESOURCE_COMMIT,
            "sceneScannerCommit": SCENE_SCANNER_COMMIT,
            "astapsImplementationCommit": ASTAPS_COMMIT,
            "astapsJavaGitBlobs": JAVA_GIT_BLOBS,
        },
        "historicalCandidateDistribution": checked_scene(rows, summary, full=full),
        "forkImplementation": checked_java(java),
        "limitations": [
            "14,084 scanned Chest-type scene gadgets are historical resource candidates, including non-oneoff and other possibly non-ordinary objects, not 14,084 verified original 7.1 loot chests.",
            "Historical Lua scene and newer fork Java were captured at different revisions; these counts do not measure a runtime profile of a single released version.",
            "Tag-bearing ordinary candidates are not directly routed through the tag-to-root DropSystem overload; the fallback may still inspect tag substrings for tier/sigil.",
            "Explicit ID source membership does not prove claim delivery: dungeon/group/quest-item gate, loaded DropTable and execution state matter.",
            "The fallback Primogem values are fork hardcoded constants, not verified original Genshin 7.1 reward values.",
            "No original 7.1 server Lua, root selection, world placement, payout quantity or probability has been authenticated.",
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--csv", required=True, type=Path)
    parser.add_argument("--summary", required=True, type=Path)
    parser.add_argument("--gadget-chest", required=True, type=Path)
    parser.add_argument("--drop-system", required=True, type=Path)
    parser.add_argument("--world-chest-loot", required=True, type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    csv_raw, summary_raw = args.csv.read_bytes(), args.summary.read_bytes()
    require_sha256(csv_raw, SCENE_CSV_SHA256, "historical scene CSV")
    require_sha256(summary_raw, SCENE_SUMMARY_SHA256, "historical scene summary")
    paths = {
        "GadgetChest": args.gadget_chest,
        "DropSystem": args.drop_system,
        "WorldChestLootHelper": args.world_chest_loot,
    }
    raw_java = {name: path.read_bytes() for name, path in paths.items()}
    for name, raw in raw_java.items():
        require_blob(raw, JAVA_GIT_BLOBS[name], f"fork {name}")
    rows = list(csv.DictReader(io.StringIO(csv_raw.decode("utf-8-sig"))))
    report = make_report(rows, json.loads(summary_raw),
                         {name: raw.decode("utf-8") for name, raw in raw_java.items()})
    output = json.dumps(report, indent=2, ensure_ascii=False) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(output, encoding="utf-8")
    print(output, end="")


if __name__ == "__main__":
    main()
