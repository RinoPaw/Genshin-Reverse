#!/usr/bin/env python3
"""Cross-check historical 3/4-relic branch weights against the pinned AstaPS drop executor.

Does not prove original-game 7.1 rates. Without --server-root, the report
uses the separately audited/pinned Java consumer identity only.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from fractions import Fraction
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ANALYSIS = ROOT / "versions/7.1.0-global/windows-x64/analyses/artifact-generation"
ECONOMY = ROOT / "versions/7.1.0-global/analyses/progression/economy"
WEIGHTS = ANALYSIS / "7.1-reliquary-drop-variant-weights.json"
CLAIMS = ECONOMY / "7.1-current-asta-dungeon-reward-audit.json"
OUTPUT = ANALYSIS / "7.1-reliquary-asta-weight-consumer.json"
REQUIRED_INPUT_BLOBS = {
    "variantBranches": "a75d55a4b2ef3cb7d427741fe2930dfac2cad3dc",
    "staticClaimRoutes": "c30d3de71e84dc0e7afe1891f8dea05091d96a24",
}
SERVER_REPO = "RinoPaw/AstaPS"
SERVER_COMMIT = "dcf04369a356486a07be976b244b83d7208c3992"
SERVER_FILES = {
    "src/main/java/emu/grasscutter/game/drop/DropSystem.java":
        "e04918a478e75414435f89f8bfd002f39d804af3",
    "src/main/java/emu/grasscutter/game/dungeons/DomainStatueDropService.java":
        "3cc0854ad2e785f4f14a303672726e99e19d0dbd",
}
JAVA_REQUIRED_SEQUENCES = {
    "src/main/java/emu/grasscutter/game/drop/DropSystem.java": [
        "dropData.getRandomType() == 0",
        "weightSum += i.getWeight()",
        "rand.nextInt(weightSum)",
        "sum += i.getWeight()",
        "if (weight < sum)",
        "processDrop(dropTable.get(id), amount, items)",
    ],
    "src/main/java/emu/grasscutter/game/dungeons/DomainStatueDropService.java": [
        "hasUsableDungeonRewardRoot(nativeRoot)",
        "DomainDropSafety.matchesNativeFamilies(",
        "DomainDropSafety.chooseRewardSource(verifiedNative, verifiedProxy)",
        "case NATIVE_ROOT:",
        "rollStatueDropTable(player, nativeRoot, rollTimes)",
        "case VALIDATED_PROXY:",
        "rollDungeonDropJson(dm, dungeonData, rollTimes)",
    ],
}


def git_blob(raw: bytes) -> str:
    return hashlib.sha1(b"blob " + str(len(raw)).encode("ascii") + b"\0" + raw).hexdigest()


def read_pinned(path: Path, blob: str) -> dict:
    raw = path.read_bytes()
    if git_blob(raw) != blob:
        raise ValueError(f"{path} no longer has the pinned Git blob {blob}")
    return json.loads(raw)


def validate_server_checkout(root: Path) -> None:
    head = subprocess.check_output(
        ["git", "-C", str(root), "rev-parse", "HEAD"], text=True
    ).strip()
    if head != SERVER_COMMIT:
        raise ValueError(f"AstaPS checkout {head} != pinned {SERVER_COMMIT}")
    for path, sha in SERVER_FILES.items():
        raw = (root / path).read_bytes()
        if git_blob(raw) != sha:
            raise ValueError(f"{path}: AstaPS source changed")
        text = raw.decode("utf-8")
        for marker in JAVA_REQUIRED_SEQUENCES[path]:
            if marker not in text:
                raise ValueError(f"{path}: missing audited code marker {marker}")


def build_snapshot(variant: dict, current: dict) -> dict:
    # The older claim audit must have exercised the same Java consumer blobs,
    # even though its overall AstaPS commit differs from the newer pin.
    audited = current["source"]["server"]["files"]
    for path, expected in SERVER_FILES.items():
        if audited[path]["gitBlobSha"] != expected:
            raise ValueError(f"legacy route audit used different Java source: {path}")
    if variant["summary"]["requiresRandomTypeSemanticsToCallProbability"] is not True:
        raise ValueError("source report no longer has an explicit probability gate")
    rows = variant["variantBranches"]
    claims = {row["dungeonId"]: row for row in current["dungeons"]}
    if len(claims) != len(current["dungeons"]):
        raise ValueError("duplicate Dungeon IDs in current AstaPS audit")
    classified = []
    for branch in sorted(rows, key=lambda x: x["nodeId"]):
        if branch["randomType"] != 0:
            raise ValueError(f"{branch['nodeId']}: not a weighted-choice candidate")
        bs = branch["branches"]
        if ([x["initialSubstatCount"] for x in bs] != [3, 4] or
                [x["configuredWeight"] for x in bs] != [8000, 2000]):
            raise ValueError(f"{branch['nodeId']}: changed branch configuration")
        if len(branch["reachableDungeonIds"]) != 1:
            raise ValueError("this pinned audit expects one Dungeon per branch")
        dungeon_id = branch["reachableDungeonIds"][0]
        route = claims.get(dungeon_id)
        if route is None or route["sourceRootStatus"] != "ROOT_PRESENT":
            raise ValueError(f"{dungeon_id}: missing/potentially changed root")
        if route["staticClaimRoute"] != "NATIVE_WITH_PROXY_FALLBACK_CANDIDATE":
            raise ValueError(f"{dungeon_id}: source-choice route changed")
        if route["proxyIssues"]:
            raise ValueError(f"{dungeon_id}: fallback is no longer structurally valid")
        a, b = (bs[0]["configuredWeight"], bs[1]["configuredWeight"])
        three, four = Fraction(a, a + b), Fraction(b, a + b)
        classified.append({
            "dungeonId": dungeon_id,
            "rootDropId": route["sourceRootId"],
            "choiceNodeId": branch["nodeId"],
            "sourceClaimRoute": route["staticClaimRoute"],
            "configuredWeights": {"3": a, "4": b},
            "conditionalAstaPSProbability": {
                "3": f"{three.numerator}/{three.denominator}",
                "4": f"{four.numerator}/{four.denominator}",
            },
        })
    classified.sort(key=lambda x: x["dungeonId"])
    if len(classified) != 27 or len({d["dungeonId"] for d in classified}) != 27:
        raise ValueError("unexpected audit coverage; the 27 historical links changed")
    if variant["summary"]["configuredThreeFourBranchNodeCount"] != len(classified):
        raise ValueError("variant source coverage changed")
    return {
        "schemaVersion": 1,
        "target": "AstaPS server implementation against historical 7.1-integrated drop graph",
        "confidence": "B_SERVER_IMPLEMENTATION_CONDITIONAL",
        "scope": (
            "Conditioned on a validated native-root source, reaching the variant node, "
            "and running the pinned AstaPS DropSystem. Not a proof of official "
            "Global 7.1 native RNG or unconditional domain reward odds."
        ),
        "source": {
            "reverseRepo": "RinoPaw/Genshin-Reverse",
            "reverseGitBlobs": REQUIRED_INPUT_BLOBS,
            "astaPSRepo": SERVER_REPO,
            "astaPSCommit": SERVER_COMMIT,
            "astaPSFiles": SERVER_FILES,
            "oldClaimAuditServerCommit": current["source"]["server"]["commit"],
        },
        "executor": {
            "choiceType": 0,
            "algorithm": (
                "sum non-zero-id edge weights; pick rand.nextInt(sum); "
                "select first cumulative weight greater than random value"
            ),
            "sourceRoute": (
                "NATIVE_ROOT when verifiedNative; otherwise "
                "VALIDATED_PROXY when verifiedProxy; otherwise NONE"
            ),
            "weightThree": 8000,
            "weightFour": 2000,
            "conditionalThreeFraction": "4/5",
            "conditionalFourFraction": "1/5",
            "notProven": [
                "official Global 7.1 DropTable provenance",
                "official server randomType semantics",
                "native-root source acceptance in deployed AstaPS",
                "per-run five-star occurrence and total drop chance",
                "four-substat probability outside these historical drop nodes",
            ],
        },
        "summary": {
            "variantSplitNodes": len(rows),
            "linkedDungeons": len(classified),
            "nativeWithProxyFallbackCandidates": len(classified),
            "directRuntimeClaimsObserved": 0,
        },
        "dungeons": classified,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--server-root", type=Path,
                        help="optional checkout of AstaPS at the exact pinned commit")
    parser.add_argument("--output", type=Path, default=OUTPUT)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    if args.server_root is not None:
        validate_server_checkout(args.server_root)
    variants = read_pinned(WEIGHTS, REQUIRED_INPUT_BLOBS["variantBranches"])
    claims = read_pinned(CLAIMS, REQUIRED_INPUT_BLOBS["staticClaimRoutes"])
    result = build_snapshot(variants, claims)
    if args.check:
        if result != json.loads(args.output.read_text(encoding="utf-8")):
            raise SystemExit("AstaPS conditional artifact-weight audit changed")
        print("PASS: 27 historical 3/4 branches map to pinned AstaPS weighted selection")
    else:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n",
                               encoding="utf-8")
        print(f"Wrote {args.output}")


if __name__ == "__main__":
    main()
