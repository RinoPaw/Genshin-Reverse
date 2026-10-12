"""Reproducible source-pinned current AstaPS 7.1 Dungeon claim audit.

Static source/proxy candidates do not establish successful live claims or
native probabilities. Does not overwrite the historical audit.
"""
from __future__ import annotations
from collections import Counter, defaultdict
import argparse
import hashlib
import json
from pathlib import Path

SERVER_COMMIT = "1c2cb79444ae911baf1fb8a11875ac32ae9783c4"
RESOURCE_COMMIT = "b0f3a2791607cab2a4c24cb9ef249dd2d94d7ffd"
SERVER_FILES = {
    "data/DungeonDrop.json": "2397bd0338246a8200f1dfb99e8a31e9caca45d0",
    "src/main/java/emu/grasscutter/data/excels/dungeon/DungeonData.java": "03f78783c88eaec4b9bc873fa92f25984a3301d9",
    "src/main/java/emu/grasscutter/game/drop/DropSystem.java": "e04918a478e75414435f89f8bfd002f39d804af3",
    "src/main/java/emu/grasscutter/game/dungeons/DomainDropRoller.java": "033155e4efbfc275a5f6d70c6fba3ec5f8594624",
    "src/main/java/emu/grasscutter/game/dungeons/DomainDropSafety.java": "5ed3537057a23e5d28a688e9fedfac0b1d814fe9",
    "src/main/java/emu/grasscutter/game/dungeons/DomainStatueClaimHelper.java": "fd538cc5915d9f0973420627d3d232a615534be7",
    "src/main/java/emu/grasscutter/game/dungeons/DomainStatueDropService.java": "3cc0854ad2e785f4f14a303672726e99e19d0dbd",
    "src/main/java/emu/grasscutter/game/dungeons/DungeonDropLoader.java": "2ec3db990d5390fb2f07f14831f417b5a93b6a10"
}
DOMAIN_LINKS_BLOB = "b5686edf379c01f8a2d1cd323c9a9bf82628e558"
PREVIEWS_BLOB = "8f662184de522c2548bbbdab44d418e4e17e3fed"
ECONOMY = Path(__file__).resolve().parents[1] / "versions/7.1.0-global/analyses/progression/economy"


def git_blob(raw: bytes) -> str:
    return hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()


def load_pinned(path: Path, expected: str):
    data = path.read_bytes()
    actual = git_blob(data)
    if actual != expected:
        raise ValueError(f"{path}: source blob {actual} != pinned {expected}")
    return json.loads(data)


def pool_issues(entries: list, sub_type: str | None) -> list[str]:
    """Mirror deterministic DomainDropSafety.validatePool checks without ItemData."""
    if not isinstance(entries, list) or not entries:
        return ["EMPTY_PROXY"]
    errors: set[str] = set()
    for item in entries:
        if not isinstance(item, dict):
            errors.add("INVALID_ENTRY")
            continue
        counts, ids = item.get("counts"), item.get("items")
        if (not isinstance(counts, list) or not counts
                or any(type(n) is not int for n in counts)
                or counts[0] < 0 or counts[-1] < counts[0]
                or counts[-1] > 10000 or counts[-1] - counts[0] + 1 > 10000):
            errors.add("INVALID_COUNT_RANGE")
            continue
        if (not isinstance(ids, list) or not ids or
                any(type(n) is not int or n <= 0 for n in ids)):
            errors.add("INVALID_ITEM_POOL")
        if sub_type == "DUNGEON_SUB_RELIQUARY" and isinstance(ids, list):
            if any(type(n) is int and 114000 <= n < 115000 for n in ids):
                errors.add("RELIQUARY_WEAPON_MATERIAL")
        for key, n in (("probabilities", counts[-1] - counts[0] + 1),
                       ("itemProbabilities", len(ids) if isinstance(ids, list) else 0)):
            w = item.get(key)
            if w is None or w == []:
                continue
            if (not isinstance(w, list) or len(w) != n
                    or any(type(x) is not int or x < 0 for x in w)
                    or not 0 < sum(w) < 2147483647):
                errors.add("INVALID_" + key.upper())
    return sorted(errors)


def audit(graph: dict, previews: dict, server_rows: list) -> dict:
    domains, preview_rows = graph["domains"], previews["dungeons"]
    for label, data in (("domain", domains), ("preview", preview_rows), ("proxy", server_rows)):
        ids = [row["dungeonId"] for row in data]
        if len(ids) != len(set(ids)):
            raise ValueError(f"duplicate {label} Dungeon IDs")
    preview_map = {row["dungeonId"]: row for row in preview_rows}
    pool_map = {row["dungeonId"]: row["drops"] for row in server_rows if row.get("drops")}
    unknown = sorted(set(pool_map) - {row["dungeonId"] for row in domains})
    if unknown:
        raise ValueError(f"unmapped proxy Dungeon IDs: {unknown}")
    rows, issues_by_id = [], defaultdict(list)
    for d in sorted(domains, key=lambda x: x["dungeonId"]):
        did = d["dungeonId"]
        pool = pool_map.get(did)
        issues = pool_issues(pool, d.get("subType")) if pool is not None else []
        for issue in issues:
            issues_by_id[issue].append(did)
        status = "ABSENT" if pool is None else "STRUCTURE_INVALID" if issues else "STRUCTURE_VALID"
        has_preview = any(i.get("itemId", 0) > 0 and i.get("displayCount") not in (None, "")
                          for i in preview_map.get(did, {}).get("previewItems", []))
        if not has_preview and not d.get("rootDropId") and pool is None:
            route = "INITIAL_GATE_REJECT"
        elif d["rootStatus"] == "ROOT_PRESENT":
            route = ("NATIVE_WITH_PROXY_FALLBACK_CANDIDATE"
                     if status == "STRUCTURE_VALID" else "NATIVE_ONLY_CANDIDATE")
        elif status == "STRUCTURE_VALID":
            route = "PROXY_ONLY_CANDIDATE"
        else:
            route = "NO_PAYABLE_SOURCE_IN_DOMAIN_STATUE_PATH"
        rows.append({
            "dungeonId": did, "type": d["type"], "subType": d.get("subType"),
            "sourceRootId": d.get("rootDropId"), "sourceRootStatus": d["rootStatus"],
            "sourceRootBoundByCurrentJavaAlias": bool(d.get("rootDropId")),
            "proxyStructure": status, "proxyIssues": issues,
            "hasUsablePreviewMetadata": has_preview, "staticClaimRoute": route,
        })
    counts = lambda key: dict(sorted(Counter(row[key] for row in rows).items()))
    return {
        "schemaVersion": 1,
        "target": "AstaPS 7.1 configured Dungeon statue-claim paths",
        "evidence": "B implementation/source static audit; not a native probability or live claim measurement",
        "source": {
            "server": {"repository": "RinoPaw/AstaPS", "commit": SERVER_COMMIT,
                       "files": {p: {"gitBlobSha": h} for p, h in sorted(SERVER_FILES.items())}},
            "resource": {"repository": "RinoPaw/AstaPS-Resource", "commit": RESOURCE_COMMIT},
            "researchSnapshots": {
                "7.1-domain-drop-links.json": DOMAIN_LINKS_BLOB,
                "7.1-dungeon-reward-previews.json": PREVIEWS_BLOB,
            },
        },
        "summary": {
            "dungeonRows": len(rows), "sourceRootStates": counts("sourceRootStatus"),
            "proxyStates": counts("proxyStructure"),
            "staticClaimRoutes": counts("staticClaimRoute"),
            "issuesByDungeonIds": {k: sorted(set(v)) for k, v in sorted(issues_by_id.items())},
            "sourceRootMissingWithInvalidProxy": [
                r["dungeonId"] for r in rows
                if r["sourceRootStatus"] == "ROOT_MISSING"
                and r["proxyStructure"] == "STRUCTURE_INVALID"],
            "bossRowsWithoutPayableDomainStatueSource": [
                r["dungeonId"] for r in rows
                if r["type"] == "DUNGEON_BOSS"
                and r["staticClaimRoute"] == "NO_PAYABLE_SOURCE_IN_DOMAIN_STATUE_PATH"],
        },
        "limitations": [
        "Native ROOT_PRESENT records are source-graph matches, not proof of loaded, positive, complete or semantically matching runtime roots.",
        "STRUCTURE_VALID proxies may still fail ItemData existence, item-type or artifact-family validation (notably dungeon 4706).",
        "Validated native source takes precedence over validated proxy. Reward previews never construct payable items.",
        "Malformed proxies are rejected before charging, but eligible native roots can still be considered independently.",
        "Boss dungeon rows are audited only against DomainStatueDropService, not an independently traced weekly/world Boss claim path.",
        "Claims also require successful dungeon completion, scene/run identity, bag capacity and payment. Mongo receipt stages are not atomic transactions.",
        "No drop-rate or exact native expected-yield claim follows from this model."
],
        "dungeons": rows,
    }


def regenerate(server_root: Path) -> dict:
    for path, expected in SERVER_FILES.items():
        actual = git_blob((server_root / path).read_bytes())
        if actual != expected:
            raise ValueError(f"{path}: server blob {actual} != pinned {expected}; update the model and pin")
    graph = load_pinned(ECONOMY / "7.1-domain-drop-links.json", DOMAIN_LINKS_BLOB)
    previews = load_pinned(ECONOMY / "7.1-dungeon-reward-previews.json", PREVIEWS_BLOB)
    pools = load_pinned(server_root / "data/DungeonDrop.json", SERVER_FILES["data/DungeonDrop.json"])
    return audit(graph, previews, pools)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("server_root", type=Path, help="checkout of pinned AstaPS revision")
    parser.add_argument("--check", action="store_true", help="check published JSON")
    parser.add_argument("--output", type=Path, help="write JSON to this path")
    args = parser.parse_args()
    data = regenerate(args.server_root)
    if args.check:
        stored = json.loads((ECONOMY / "7.1-current-asta-dungeon-reward-audit.json").read_text(encoding="utf-8"))
        if data != stored:
            raise SystemExit("current dungeon reward audit snapshot mismatch")
        print("PASS: pinned current AstaPS dungeon reward audit")
    elif args.output:
        args.output.write_text(json.dumps(data, indent=2, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")
    else:
        print(json.dumps(data, indent=2, ensure_ascii=False, sort_keys=True))


if __name__ == "__main__":
    main()
