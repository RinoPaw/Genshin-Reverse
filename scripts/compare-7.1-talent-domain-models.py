#!/usr/bin/env python3
"""Compare source drop nodes and AstaPS's own drop proxy under B assumptions.

The output is a mean-value equivalent, NOT an exact expected stopping time
and NOT validated Genshin 7.1 native probability or reward selection.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

BASE = Path(__file__).resolve().parents[1] / "versions/7.1.0-global/analyses/progression"
ECON = BASE / "economy"


def expected_count(value: str) -> float:
    if ";" in value:
        lo, hi = map(int, value.split(";"))
        return (lo + hi) / 2
    return float(value)


def source_projection(node_id: int, nodes: dict[int, dict]) -> dict[int, float]:
    def walk(ident: int, stack: frozenset[int]) -> dict[int, float]:
        if ident not in nodes:
            return {ident: 1.0}
        if ident in stack:
            raise ValueError(f"recursive drop node {ident}")
        node = nodes[ident]
        kind = node["randomType"]
        if kind not in (0, 1):
            raise ValueError(f"unsupported drop randomType {kind}")
        entries = node["dropVec"]
        denominator = sum(x["weight"] for x in entries) if kind == 0 else 10000
        if denominator <= 0:
            raise ValueError("invalid drop weight total")
        items: dict[int, float] = {}
        for x in entries:
            mean = expected_count(x["countRange"]) * x["weight"] / denominator
            for id_, amount in walk(x["itemId"], stack | {ident}).items():
                items[id_] = items.get(id_, 0.0) + mean * amount
        return items
    return walk(node_id, frozenset())


def server_projection(entries: list[dict]) -> dict[int, float]:
    result: dict[int, float] = {}
    for x in entries:
        values = list(range(x["counts"][0], x["counts"][-1] + 1))
        probabilities = x.get("probabilities")
        if probabilities and len(probabilities) > 1 and len(probabilities) == len(values):
            mean = sum(a * b for a, b in zip(values, probabilities)) / sum(probabilities)
        else:
            mean = sum(values) / len(values)
        items, probabilities = x["items"], x.get("itemProbabilities")
        for i, item in enumerate(items):
            if probabilities and len(probabilities) > 1 and len(probabilities) == len(items):
                probability = probabilities[i] / sum(probabilities)
            else:
                probability = 1 / len(items)
            result[item] = result.get(item, 0.0) + mean * probability
    return result


def compare(talent_group: int = 331, dungeon_id: int = 4223) -> dict:
    read = lambda path: json.loads(path.read_text(encoding="utf-8"))
    native = read(ECON / "7.1-talent-domain-drop-links.json")
    proxy = read(ECON / "7.1-talent-domain-server-proxy.json")
    talent = read(BASE / "character/7.1-talent-cost-groups.json")
    domains = {d["dungeonId"]: d for d in native["domains"]}
    domain = domains[dungeon_id]
    if not domain["rootPresent"]:
        raise ValueError(f"dungeon {dungeon_id} lacks 7.1 source drop roots")
    proxies = {d["dungeonId"]: d for d in proxy["dungeons"]}
    if dungeon_id not in proxies:
        raise ValueError(f"dungeon {dungeon_id} lacks AstaPS proxy data")
    group = next(x for x in talent["proudSkillGroups"]
                 if x["proudSkillGroupId"] == talent_group)
    books = sorted(set(domain["previewTalentMaterialIds"]))
    if len(books) != 3:
        raise ValueError("select a weekday tier with exactly three book IDs")
    costs = {n: sum(item["count"] for level in group["levels"]
                    for item in level["costItems"] if item["itemId"] == n)
             for n in books}
    if any(not x for x in costs.values()):
        raise ValueError("selected talent and dungeon do not share a material family")
    nodes = {n["id"]: n for n in native["dropNodes"]}
    models = {
        "sourceNodesUnderBConsumerSemantics": source_projection(domain["rootDropId"], nodes),
        "AstaPSServerProxy": server_projection(proxies[dungeon_id]["drops"]),
    }
    demand = sum(costs[id_] * 3 ** rank for rank, id_ in enumerate(books))
    result = {}
    for name, expected in models.items():
        yields = [expected.get(n, 0.0) for n in books]
        supply = sum(v * 3 ** i for i, v in enumerate(yields))
        result[name] = {
            "perClaimBookMeans": {str(n): v for n, v in zip(books, yields)},
            "greenEquivalentSupply": supply,
            "ratioEquivalentClaims": demand / supply,
            "ratioEquivalentResin": domain["baseResinCostCount"] * demand / supply,
        }
    return {
        "evidence": "B model calculations only; native selection/probability unverified",
        "talentGroupId": talent_group,
        "dungeonId": dungeon_id,
        "entryExcelId": domain["entryExcelId"],
        "showLevel": domain["showLevel"],
        "bookRequirements": {str(n): v for n, v in costs.items()},
        "threeToOneEquivalentDemand": demand,
        "note": "Ratio of expected book-equivalents, NOT expected finishing runs; assumes 3:1 crafting and excludes other materials.",
        "models": result,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--talent-group", type=int, default=331)
    parser.add_argument("--dungeon", type=int, default=4223)
    args = parser.parse_args()
    print(json.dumps(compare(args.talent_group, args.dungeon), indent=2,
                     ensure_ascii=False))


if __name__ == "__main__":
    main()
