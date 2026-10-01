from __future__ import annotations

import argparse
import csv
import json
import math
from pathlib import Path


def load_registry(path: Path) -> dict[int, dict[str, str]]:
    with path.open("r", encoding="utf-8-sig", newline="") as f:
        return {int(row["cmd_id"], 0): row for row in csv.DictReader(f)}


def parse_pair(text: str) -> tuple[str, int, int]:
    # name:old_cmd:new_cmd
    name, old_s, new_s = text.split(":", 2)
    return name, int(old_s, 0), int(new_s, 0)


def pearson(xs: list[float], ys: list[float]) -> float | None:
    if len(xs) < 2:
        return None
    mx = sum(xs) / len(xs)
    my = sum(ys) / len(ys)
    dx = [x - mx for x in xs]
    dy = [y - my for y in ys]
    den = math.sqrt(sum(x*x for x in dx) * sum(y*y for y in dy))
    if not den:
        return None
    return sum(x*y for x, y in zip(dx, dy)) / den


def linear_fit(xs: list[float], ys: list[float]) -> tuple[float, float] | None:
    if len(xs) < 2:
        return None
    mx = sum(xs) / len(xs)
    my = sum(ys) / len(ys)
    var = sum((x-mx)**2 for x in xs)
    if not var:
        return None
    slope = sum((x-mx)*(y-my) for x, y in zip(xs, ys)) / var
    return slope, my - slope * mx


def main() -> None:
    p = argparse.ArgumentParser(description="Test whether 7.0 packetIds insertion order tracks 7.1 registry index.")
    p.add_argument("old_packet_ids", type=Path)
    p.add_argument("new_registry_csv", type=Path)
    p.add_argument("output_json", type=Path)
    p.add_argument("--pair", action="append", default=[], help="name:old_cmd:new_cmd")
    p.add_argument("--old-target", type=lambda s: int(s, 0), required=True)
    p.add_argument("--candidate", action="append", default=[])
    args = p.parse_args()

    old_map = json.loads(args.old_packet_ids.read_text(encoding="utf-8-sig"))
    old_items = list(old_map.items())
    old_rank_by_cmd: dict[int, list[dict[str, object]]] = {}
    for rank, (type_name, cmd_raw) in enumerate(old_items):
        cmd = int(cmd_raw)
        old_rank_by_cmd.setdefault(cmd, []).append({"rank": rank, "type_name": type_name})

    new_registry = load_registry(args.new_registry_csv)
    anchors = []
    for raw in args.pair:
        name, old_cmd, new_cmd = parse_pair(raw)
        old_hits = old_rank_by_cmd.get(old_cmd, [])
        new_row = new_registry.get(new_cmd)
        if len(old_hits) != 1 or new_row is None:
            anchors.append({
                "name": name,
                "old_cmd": old_cmd,
                "new_cmd": new_cmd,
                "status": "unresolved",
                "old_hits": old_hits,
                "new_found": new_row is not None,
            })
            continue
        anchors.append({
            "name": name,
            "old_cmd": old_cmd,
            "new_cmd": new_cmd,
            "old_type_name": old_hits[0]["type_name"],
            "old_rank": old_hits[0]["rank"],
            "new_type_name": new_row.get("type_name", ""),
            "new_registry_index": int(new_row["registry_index"], 0),
            "status": "ok",
        })

    good = [a for a in anchors if a["status"] == "ok"]
    xs = [float(a["old_rank"]) for a in good]
    ys = [float(a["new_registry_index"]) for a in good]
    fit = linear_fit(xs, ys)
    correlation = pearson(xs, ys)

    old_target_hits = old_rank_by_cmd.get(args.old_target, [])
    target_rank = old_target_hits[0]["rank"] if len(old_target_hits) == 1 else None
    predicted = None
    if fit is not None and target_rank is not None:
        predicted = fit[0] * float(target_rank) + fit[1]

    candidates = []
    for raw in args.candidate:
        cmd = int(raw, 0)
        row = new_registry.get(cmd)
        if row is None:
            candidates.append({"cmd_id": cmd, "status": "missing"})
            continue
        idx = int(row["registry_index"], 0)
        candidates.append({
            "cmd_id": cmd,
            "type_name": row.get("type_name", ""),
            "registry_index": idx,
            "distance_from_predicted": None if predicted is None else abs(idx - predicted),
            "signed_residual": None if predicted is None else idx - predicted,
            "status": "ok",
        })
    candidates.sort(key=lambda x: float("inf") if x.get("distance_from_predicted") is None else x["distance_from_predicted"])

    # Also evaluate local offset new_index-old_rank. A preserved type order with insertions should
    # produce similar offsets for nearby semantic anchors even if a global linear model is imperfect.
    for a in good:
        a["index_offset"] = int(a["new_registry_index"]) - int(a["old_rank"])
    if target_rank is not None:
        nearby = sorted(good, key=lambda a: abs(int(a["old_rank"]) - int(target_rank)))[:6]
    else:
        nearby = []

    result = {
        "old_entry_count": len(old_items),
        "new_registry_count": len(new_registry),
        "anchors": anchors,
        "correlation_old_rank_new_index": correlation,
        "linear_fit": None if fit is None else {"slope": fit[0], "intercept": fit[1]},
        "old_target_cmd": args.old_target,
        "old_target_hits": old_target_hits,
        "predicted_new_registry_index": predicted,
        "nearest_semantic_anchors_to_target": nearby,
        "candidates": candidates,
        "interpretation_guard": "Use this only if independent semantic anchors demonstrate stable order/local offsets. Weak correlation or large local residuals invalidate the heuristic.",
    }
    args.output_json.parent.mkdir(parents=True, exist_ok=True)
    args.output_json.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    print("old entries", len(old_items), "new registry", len(new_registry))
    print("correlation", correlation, "fit", fit)
    for a in anchors:
        print("anchor", a)
    print("target", args.old_target, old_target_hits, "predicted", predicted)
    print("candidates")
    for c in candidates:
        print(c)


if __name__ == "__main__":
    main()
