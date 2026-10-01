from __future__ import annotations

import argparse
import csv
import json
import math
import re
from pathlib import Path

MESSAGE_RE = re.compile(r"^message\s+([A-Za-z_][A-Za-z0-9_]*)\s*\{")


def parse_messages(path: Path) -> list[str]:
    names: list[str] = []
    depth = 0
    with path.open("r", encoding="utf-8-sig", errors="replace") as f:
        for raw in f:
            line = raw.strip()
            if depth == 0:
                match = MESSAGE_RE.match(line)
                if match:
                    names.append(match.group(1))
            # Good enough for generated proto: braces in comments/strings are not expected to drive structure.
            depth += line.count("{") - line.count("}")
            if depth < 0:
                depth = 0
    return names


def load_packet_ids(path: Path) -> dict[int, list[str]]:
    mapping = json.loads(path.read_text(encoding="utf-8-sig"))
    out: dict[int, list[str]] = {}
    for name, cmd in mapping.items():
        out.setdefault(int(cmd), []).append(name)
    return out


def load_registry(path: Path) -> dict[int, dict[str, str]]:
    with path.open("r", encoding="utf-8-sig", newline="") as f:
        return {int(row["cmd_id"], 0): row for row in csv.DictReader(f)}


def parse_pair(text: str) -> tuple[str, int, int]:
    name, old_s, new_s = text.split(":", 2)
    return name, int(old_s, 0), int(new_s, 0)


def pearson(xs: list[float], ys: list[float]) -> float | None:
    if len(xs) < 2:
        return None
    mx = sum(xs) / len(xs)
    my = sum(ys) / len(ys)
    dx = [x - mx for x in xs]
    dy = [y - my for y in ys]
    den = math.sqrt(sum(v*v for v in dx) * sum(v*v for v in dy))
    if not den:
        return None
    return sum(a*b for a, b in zip(dx, dy)) / den


def linear_fit(xs: list[float], ys: list[float]) -> tuple[float, float] | None:
    if len(xs) < 2:
        return None
    mx = sum(xs) / len(xs)
    my = sum(ys) / len(ys)
    var = sum((x-mx)**2 for x in xs)
    if not var:
        return None
    slope = sum((x-mx)*(y-my) for x, y in zip(xs, ys)) / var
    return slope, my - slope*mx


def main() -> None:
    p = argparse.ArgumentParser(description="Validate 7.0 proto message order against current 7.1 typeDefinition order.")
    p.add_argument("old_proto", type=Path)
    p.add_argument("old_packet_ids", type=Path)
    p.add_argument("new_registry", type=Path)
    p.add_argument("output_json", type=Path)
    p.add_argument("--pair", action="append", default=[])
    p.add_argument("--old-target", type=lambda s: int(s, 0), required=True)
    p.add_argument("--candidate", action="append", default=[])
    args = p.parse_args()

    messages = parse_messages(args.old_proto)
    ordinal = {name: i for i, name in enumerate(messages)}
    packet_ids = load_packet_ids(args.old_packet_ids)
    registry = load_registry(args.new_registry)

    anchors = []
    for raw in args.pair:
        semantic, old_cmd, new_cmd = parse_pair(raw)
        old_names = packet_ids.get(old_cmd, [])
        new_row = registry.get(new_cmd)
        old_matches = [{"type_name": name, "message_ordinal": ordinal.get(name)} for name in old_names if name in ordinal]
        typedef = None if new_row is None else int(new_row.get("type_definition_index") or "0", 0)
        status = "ok" if len(old_matches) == 1 and new_row is not None and typedef else "unresolved"
        anchors.append({
            "semantic_name": semantic,
            "old_cmd": old_cmd,
            "new_cmd": new_cmd,
            "old_matches": old_matches,
            "new_type_name": "" if new_row is None else new_row.get("type_name", ""),
            "new_type_definition_index": typedef,
            "status": status,
        })

    good = [a for a in anchors if a["status"] == "ok"]
    xs = [float(a["old_matches"][0]["message_ordinal"]) for a in good]
    ys = [float(a["new_type_definition_index"]) for a in good]
    corr = pearson(xs, ys)
    fit = linear_fit(xs, ys)
    if fit is not None:
        for a in good:
            x = float(a["old_matches"][0]["message_ordinal"])
            predicted = fit[0]*x + fit[1]
            a["fit_residual"] = float(a["new_type_definition_index"]) - predicted

    target_names = packet_ids.get(args.old_target, [])
    target_matches = [{"type_name": name, "message_ordinal": ordinal.get(name)} for name in target_names if name in ordinal]
    target_ordinal = target_matches[0]["message_ordinal"] if len(target_matches) == 1 else None
    predicted_target = None
    if fit is not None and target_ordinal is not None:
        predicted_target = fit[0]*float(target_ordinal) + fit[1]

    candidates = []
    for raw in args.candidate:
        cmd = int(raw, 0)
        row = registry.get(cmd)
        if row is None:
            candidates.append({"cmd_id": cmd, "status": "missing"})
            continue
        typedef = int(row.get("type_definition_index") or "0", 0)
        candidates.append({
            "cmd_id": cmd,
            "type_name": row.get("type_name", ""),
            "type_definition_index": typedef,
            "distance_from_predicted": None if predicted_target is None else abs(typedef-predicted_target),
            "signed_residual": None if predicted_target is None else typedef-predicted_target,
            "status": "ok",
        })
    candidates.sort(key=lambda item: float("inf") if item.get("distance_from_predicted") is None else item["distance_from_predicted"])

    # Rank-order agreement is often more meaningful than a global linear scale when unrelated types
    # are inserted between releases. Count semantic-anchor inversions independently of linear fit.
    inversions = 0
    comparable = 0
    for i in range(len(good)):
        for j in range(i+1, len(good)):
            xi = int(good[i]["old_matches"][0]["message_ordinal"])
            xj = int(good[j]["old_matches"][0]["message_ordinal"])
            yi = int(good[i]["new_type_definition_index"])
            yj = int(good[j]["new_type_definition_index"])
            if xi == xj or yi == yj:
                continue
            comparable += 1
            if (xi < xj) != (yi < yj):
                inversions += 1

    result = {
        "old_top_level_message_count": len(messages),
        "anchor_count": len(anchors),
        "resolved_anchor_count": len(good),
        "correlation_old_message_ordinal_new_typedef": corr,
        "linear_fit": None if fit is None else {"slope": fit[0], "intercept": fit[1]},
        "pairwise_comparisons": comparable,
        "pairwise_inversions": inversions,
        "pairwise_order_agreement": None if not comparable else 1.0 - inversions/comparable,
        "anchors": anchors,
        "old_target_cmd": args.old_target,
        "old_target_matches": target_matches,
        "predicted_new_type_definition_index": predicted_target,
        "candidates": candidates,
        "interpretation_guard": "Promote no candidate unless independent anchors show strong monotonic/type-order stability; weak correlation or many inversions invalidate the heuristic.",
    }
    args.output_json.parent.mkdir(parents=True, exist_ok=True)
    args.output_json.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    print("messages", len(messages), "resolved anchors", len(good))
    print("correlation", corr, "fit", fit, "order agreement", result["pairwise_order_agreement"])
    for anchor in anchors:
        print("anchor", anchor)
    print("target", target_matches, "predicted", predicted_target)
    for candidate in candidates:
        print("candidate", candidate)


if __name__ == "__main__":
    main()
