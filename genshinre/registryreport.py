from __future__ import annotations

import argparse
import csv
import json
from collections import Counter, defaultdict
from pathlib import Path

from .opcodes import crosscheck_registry


def _rows(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))


def _as_int(value: str | None) -> int | None:
    text = "" if value is None else str(value).strip()
    if not text:
        return None
    try:
        return int(text, 0)
    except ValueError:
        return None


def _format_row(row: dict[str, str]) -> str:
    return (
        f"`{row.get('cmd_id', '')}` → `{row.get('type_name', '')}` "
        f"(tdi `{row.get('type_definition_index', '')}`, "
        f"GetCmdId `{row.get('get_cmd_id_rva', '')}`, "
        f"usage `{row.get('usage_destination', '')}`, "
        f"slot `{row.get('type_slot_rva', '')}`)"
    )


def generate_registry_candidate_report(
    graph_csv: Path,
    graph_summary_json: Path,
    output_md: Path,
    known_opcodes_csv: Path | None = None,
    focus_cmd_ids: tuple[int, ...] = (186, 9369, 22899, 26105),
    max_conflicts: int = 40,
) -> dict[str, object]:
    rows = _rows(graph_csv)
    summary = json.loads(graph_summary_json.read_text(encoding="utf-8"))

    by_cmd: dict[int, list[dict[str, str]]] = defaultdict(list)
    by_type: dict[str, list[dict[str, str]]] = defaultdict(list)
    status_counts = Counter()
    for row in rows:
        cmd_id = _as_int(row.get("cmd_id"))
        if cmd_id is not None:
            by_cmd[cmd_id].append(row)
        name = str(row.get("type_name", ""))
        if name:
            by_type[name].append(row)
        status_counts[str(row.get("status", ""))] += 1

    unique_join_cmds = sorted(
        cmd_id
        for cmd_id, group in by_cmd.items()
        if len(group) == 1 and group[0].get("status") == "JOINED_UNIQUE"
    )
    ambiguous_usage_cmds = sorted(
        cmd_id
        for cmd_id, group in by_cmd.items()
        if any(row.get("status") == "JOINED_AMBIGUOUS_USAGE" for row in group)
    )
    duplicate_cmds = sorted(cmd_id for cmd_id, group in by_cmd.items() if len(group) > 1)

    type_to_cmds: dict[str, set[int]] = defaultdict(set)
    for name, group in by_type.items():
        for row in group:
            cmd_id = _as_int(row.get("cmd_id"))
            if cmd_id is not None:
                type_to_cmds[name].add(cmd_id)
    type_cmd_conflicts = {
        name: sorted(cmd_ids)
        for name, cmd_ids in sorted(type_to_cmds.items())
        if len(cmd_ids) > 1
    }

    control = None
    if known_opcodes_csv is not None:
        control = crosscheck_registry(graph_csv, known_opcodes_csv)

    focus: dict[str, list[dict[str, str]]] = {
        str(cmd_id): by_cmd.get(cmd_id, []) for cmd_id in focus_cmd_ids
    }

    result: dict[str, object] = {
        "graph_rows": len(rows),
        "unique_cmd_ids": len(by_cmd),
        "joined_unique_cmd_ids": len(unique_join_cmds),
        "ambiguous_usage_cmd_ids": len(ambiguous_usage_cmds),
        "duplicate_cmd_ids": len(duplicate_cmds),
        "type_to_multiple_cmd_ids": len(type_cmd_conflicts),
        "status_counts": dict(sorted(status_counts.items())),
        "historical_registry_scale": summary.get("historical_registry_scale", 4896),
        "distance_from_historical_scale": summary.get("distance_from_historical_scale"),
        "all_preserved_anchors_pass": bool(summary.get("all_preserved_anchors_pass")),
        "control_set": control,
        "focus": focus,
    }

    lines = [
        "# Registry candidate convergence report",
        "",
        "This report summarizes the current **candidate graph**. It does not promote rows to canonical `registry.csv` by itself.",
        "",
        "## Summary",
        "",
        f"- Graph rows: **{len(rows):,}**",
        f"- Unique CmdIds: **{len(by_cmd):,}**",
        f"- Unique one-to-one joins: **{len(unique_join_cmds):,}**",
        f"- CmdIds with usage ambiguity: **{len(ambiguous_usage_cmds):,}**",
        f"- CmdIds represented by multiple graph rows: **{len(duplicate_cmds):,}**",
        f"- Types associated with multiple candidate CmdIds: **{len(type_cmd_conflicts):,}**",
        f"- Preserved full-registry reference scale: **{int(summary.get('historical_registry_scale', 4896)):,}**",
        f"- Preserved anchors pass: **{'yes' if summary.get('all_preserved_anchors_pass') else 'no'}**",
    ]

    distance = summary.get("distance_from_historical_scale")
    if isinstance(distance, int):
        lines.append(f"- Distance from preserved 4,896 scale: **{distance:+,}**")

    if control is not None:
        lines.extend(
            [
                "",
                "## AstaPS control-set coverage",
                "",
                f"- Control CmdIds: **{int(control['control_set_unique_cmd_ids']):,}**",
                f"- Present in candidate graph: **{int(control['matched']):,}**",
                f"- Missing: **{int(control['missing_count']):,}**",
                f"- Complete coverage: **{'yes' if control['all_control_ids_present'] else 'no'}**",
            ]
        )
        if control["missing_cmd_ids"]:
            preview = ", ".join(str(value) for value in list(control["missing_cmd_ids"])[:80])
            lines.extend(["", f"Missing preview: `{preview}`"])

    lines.extend(["", "## Focus CmdIds", ""])
    for cmd_id in focus_cmd_ids:
        group = by_cmd.get(cmd_id, [])
        lines.append(f"### {cmd_id}")
        lines.append("")
        if not group:
            lines.append("No candidate row in the current graph.")
        else:
            for row in group:
                lines.append(f"- {_format_row(row)} — `{row.get('status', '')}`")
        lines.append("")

    anchor_rows = list(summary.get("anchors", []))
    if anchor_rows:
        lines.extend(["## Preserved anchor checks", ""])
        for anchor in anchor_rows:
            checks = anchor.get("checks", {})
            details = ", ".join(
                f"{key}={'ok' if value else 'FAIL'}" for key, value in checks.items()
            )
            lines.append(
                f"- CmdId `{anchor.get('cmd_id')}`: **{'PASS' if anchor.get('passed') else 'FAIL'}**"
                + (f" — {details}" if details else "")
            )
        lines.append("")

    if ambiguous_usage_cmds:
        lines.extend(["## Usage ambiguity", ""])
        for cmd_id in ambiguous_usage_cmds[:max_conflicts]:
            group = by_cmd[cmd_id]
            slots = sorted({row.get("type_slot_rva", "") for row in group})
            lines.append(
                f"- `{cmd_id}` / `{group[0].get('type_name', '')}` → {len(group)} graph rows; slots: "
                + ", ".join(f"`{slot}`" for slot in slots)
            )
        if len(ambiguous_usage_cmds) > max_conflicts:
            lines.append(f"- … {len(ambiguous_usage_cmds) - max_conflicts} more")
        lines.append("")

    if type_cmd_conflicts:
        lines.extend(["## Types with multiple candidate CmdIds", ""])
        for name, cmd_ids in list(type_cmd_conflicts.items())[:max_conflicts]:
            lines.append(f"- `{name}` → " + ", ".join(f"`{cmd}`" for cmd in cmd_ids))
        if len(type_cmd_conflicts) > max_conflicts:
            lines.append(f"- … {len(type_cmd_conflicts) - max_conflicts} more")
        lines.append("")

    lines.extend(
        [
            "## Interpretation boundary",
            "",
            "The graph combines independent static identities: metadata-usage slot, decoded runtime type and constant-return method candidate. Registration-table membership and direction still require independent closure before canonical publication.",
            "",
        ]
    )

    output_md.parent.mkdir(parents=True, exist_ok=True)
    output_md.write_text("\n".join(lines), encoding="utf-8")
    return result


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="python -m genshinre.registryreport",
        description="Generate a human-readable convergence report for a registry candidate graph.",
    )
    parser.add_argument("graph_csv", type=Path)
    parser.add_argument("graph_summary_json", type=Path)
    parser.add_argument("output_md", type=Path)
    parser.add_argument("--known-opcodes", type=Path)
    parser.add_argument("--focus", default="186,9369,22899,26105")
    parser.add_argument("--max-conflicts", type=int, default=40)
    args = parser.parse_args()

    focus = tuple(int(item.strip(), 0) for item in args.focus.split(",") if item.strip())
    result = generate_registry_candidate_report(
        args.graph_csv,
        args.graph_summary_json,
        args.output_md,
        known_opcodes_csv=args.known_opcodes,
        focus_cmd_ids=focus,
        max_conflicts=args.max_conflicts,
    )
    print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
