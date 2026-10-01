from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path

from .mhy71 import EXPECTED_EXE_SHA256, _sha256
from .pe import PEImage
from .registrylayout import HISTORICAL_ROW_COUNT

RAW_COLUMNS = (
    "index",
    "cmd_id",
    "cmd_hex",
    "registry_flag",
    "type_slot_rva",
    "layout_stride",
    "cmd_width",
    "status",
    "evidence",
)


def _parse_rva(text: object) -> int:
    return int(str(text), 0)


def _dedupe_field_matches(matches: list[dict[str, object]], kind: str) -> list[dict[str, object]]:
    """Collapse equivalent width variants while retaining true layout ambiguity."""
    grouped: dict[tuple[object, ...], dict[str, object]] = {}
    for match in matches:
        if kind == "flag":
            # For a 0/1 flag, the narrowest representation at a given relative
            # offset is the least assumptive. Wider zero-extended reads carry no
            # additional evidence.
            key = (int(match["relative_to_cmd"]),)
            current = grouped.get(key)
            if current is None or int(match["width"]) < int(current["width"]):
                grouped[key] = match
        else:
            key = (int(match["relative_to_cmd"]), str(match["encoding"]))
            grouped[key] = match
    return list(grouped.values())


def _metric_signature(candidate: dict[str, object]) -> tuple[object, ...]:
    metrics = dict(candidate.get("column_metrics", {}))
    # Width aliases are only equivalent when scanning the preserved row span
    # produced the same observable column shape. This prevents a real uint16
    # field followed by meaningful upper bytes from being merged with uint32.
    return (
        metrics.get("readable_rows"),
        metrics.get("nonzero_rows"),
        metrics.get("protocol_range_rows"),
        metrics.get("unique_nonzero_values"),
    )


def _physical_layout_key(candidate: dict[str, object]) -> tuple[object, ...]:
    slot = dict(candidate["selected_slot_field"])
    flag = dict(candidate["selected_flag_field"])
    return (
        int(candidate["stride"]),
        int(candidate["anchor_22899_index_interpretation"]),
        str(candidate["cmd_column_base_rva"]),
        str(candidate.get("anchor_9369_cmd_rva", "")),
        str(candidate.get("anchor_22899_cmd_rva", "")),
        int(slot["relative_to_cmd"]),
        str(slot["encoding"]),
        int(slot["width"]),
        int(flag["relative_to_cmd"]),
        int(flag["width"]),
        _metric_signature(candidate),
    )


def choose_closed_layout(probe: dict[str, object]) -> dict[str, object]:
    strong = [
        candidate
        for candidate in list(probe.get("candidates", []))
        if candidate.get("status") == "strong-layout-candidate"
    ]
    if not strong:
        raise ValueError("registry layout probe contains no strong candidate")

    prepared: list[dict[str, object]] = []
    for candidate in strong:
        slots = _dedupe_field_matches(list(candidate.get("slot_field_matches", [])), "slot")
        flags = _dedupe_field_matches(list(candidate.get("flag_field_matches", [])), "flag")
        if len(slots) == 1 and len(flags) == 1:
            item = dict(candidate)
            item["selected_slot_field"] = slots[0]
            item["selected_flag_field"] = flags[0]
            prepared.append(item)

    grouped: dict[tuple[object, ...], list[dict[str, object]]] = {}
    for candidate in prepared:
        grouped.setdefault(_physical_layout_key(candidate), []).append(candidate)

    if len(grouped) != 1:
        raise ValueError(
            f"registry layout is not closed: {len(strong)} strong candidates, "
            f"{len(prepared)} with unique slot+flag fields, {len(grouped)} physical layouts"
        )

    aliases = next(iter(grouped.values()))
    # GetCmdId returns uint32. When uint16/uint32 scans are observationally
    # identical across the entire preserved table, keep both as provenance and
    # use the wider read as the deterministic export representation.
    selected = max(aliases, key=lambda item: int(item["cmd_width"]))
    result = dict(selected)
    result["cmd_width_aliases"] = sorted({int(item["cmd_width"]) for item in aliases})
    return result


def _decode_slot(image: PEImage, cmd_rva: int, field: dict[str, object]) -> int | None:
    relative = int(field["relative_to_cmd"])
    width = int(field["width"])
    blob = image.read_rva(cmd_rva + relative, width)
    if len(blob) != width:
        return None
    value = int.from_bytes(blob, "little", signed=False)
    encoding = str(field["encoding"])
    if encoding == "va64":
        if value < image.image_base:
            return None
        return value - image.image_base
    if encoding in {"rva32", "rva64"}:
        return value
    raise ValueError(f"unsupported slot encoding: {encoding}")


def _decode_flag(image: PEImage, cmd_rva: int, field: dict[str, object]) -> int | None:
    relative = int(field["relative_to_cmd"])
    width = int(field["width"])
    blob = image.read_rva(cmd_rva + relative, width)
    if len(blob) != width:
        return None
    return int.from_bytes(blob, "little", signed=False)


def export_raw_registry_71(
    exe: Path,
    layout_probe_json: Path,
    output_csv: Path,
    summary_json: Path | None = None,
    allow_unknown_sample: bool = False,
    row_count: int = HISTORICAL_ROW_COUNT,
) -> dict[str, object]:
    exe_sha = _sha256(exe)
    if not allow_unknown_sample and exe_sha != EXPECTED_EXE_SHA256:
        raise ValueError(f"unexpected GenshinImpact.exe SHA-256: {exe_sha}")

    probe = json.loads(layout_probe_json.read_text(encoding="utf-8"))
    layout = choose_closed_layout(probe)
    stride = int(layout["stride"])
    cmd_width = int(layout["cmd_width"])
    cmd_column_base_rva = _parse_rva(layout["cmd_column_base_rva"])
    slot_field = dict(layout["selected_slot_field"])
    flag_field = dict(layout["selected_flag_field"])

    rows: list[dict[str, object]] = []
    with PEImage(exe) as image:
        for index in range(row_count):
            cmd_rva = cmd_column_base_rva + index * stride
            cmd_blob = image.read_rva(cmd_rva, cmd_width)
            if len(cmd_blob) != cmd_width:
                raise ValueError(f"registry row {index} CmdId is outside mapped PE data")
            cmd_id = int.from_bytes(cmd_blob, "little", signed=False)
            flag = _decode_flag(image, cmd_rva, flag_field)
            slot_rva = _decode_slot(image, cmd_rva, slot_field)
            if flag is None or slot_rva is None:
                raise ValueError(f"registry row {index} field decode failed")
            rows.append(
                {
                    "index": index,
                    "cmd_id": cmd_id,
                    "cmd_hex": f"0x{cmd_id:X}",
                    "registry_flag": flag,
                    "type_slot_rva": f"0x{slot_rva:X}",
                    "layout_stride": stride,
                    "cmd_width": cmd_width,
                    "status": "native-registry-row",
                    "evidence": "indexed native layout closed by preserved 9369/22899 CmdId+slot+flag anchors",
                }
            )

    output_csv.parent.mkdir(parents=True, exist_ok=True)
    with output_csv.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=RAW_COLUMNS)
        writer.writeheader()
        writer.writerows(rows)

    cmd_ids = [int(row["cmd_id"]) for row in rows]
    unique_cmd_ids = len(set(cmd_ids))
    protocol_range_rows = sum(1 for cmd_id in cmd_ids if 1 <= cmd_id <= 65535)
    flag_counts: dict[str, int] = {}
    for row in rows:
        key = str(row["registry_flag"])
        flag_counts[key] = flag_counts.get(key, 0) + 1

    row9369 = rows[2232] if len(rows) > 2232 else None
    anchor22899_index = int(layout["anchor_22899_index_interpretation"])
    row22899 = rows[anchor22899_index] if len(rows) > anchor22899_index else None
    anchor_checks = {
        "9369": bool(
            row9369
            and int(row9369["cmd_id"]) == 9369
            and int(row9369["registry_flag"]) == 1
            and _parse_rva(row9369["type_slot_rva"]) == 0x057E6498
        ),
        "22899": bool(
            row22899
            and int(row22899["cmd_id"]) == 22899
            and int(row22899["registry_flag"]) == 0
            and _parse_rva(row22899["type_slot_rva"]) == 0x057F6F60
        ),
    }

    summary: dict[str, object] = {
        "exe_sha256": exe_sha,
        "row_count": len(rows),
        "unique_cmd_ids": unique_cmd_ids,
        "protocol_range_rows": protocol_range_rows,
        "flag_counts": dict(sorted(flag_counts.items())),
        "layout": {
            "stride": stride,
            "cmd_width": cmd_width,
            "cmd_width_aliases": list(layout.get("cmd_width_aliases", [cmd_width])),
            "cmd_column_base_rva": f"0x{cmd_column_base_rva:X}",
            "slot_field": slot_field,
            "flag_field": flag_field,
            "anchor_22899_index_interpretation": anchor22899_index,
        },
        "anchor_checks": anchor_checks,
        "all_anchor_checks_pass": all(anchor_checks.values()),
        "historical_unique_cmdid_reference": HISTORICAL_ROW_COUNT,
        "status": "native-registry-rows",
        "notes": [
            "rows are exported only after one physical layout uniquely explains both preserved indexed CmdId/type-slot/direction anchors",
            "observationally equivalent CmdId read widths are retained as aliases; the widest equivalent read is used for export",
            "the 4,896 row count is a preserved sample invariant and is not used to alter decoded values",
            "semantic protobuf names and global direction-flag interpretation remain separate evidence layers",
        ],
    }
    if summary_json is None:
        summary_json = output_csv.with_suffix(".summary.json")
    summary_json.parent.mkdir(parents=True, exist_ok=True)
    summary_json.write_text(json.dumps(summary, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return summary


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="python -m genshinre.registryraw",
        description="Export raw 7.1 native protocol-registry rows after the indexed layout is uniquely closed.",
    )
    parser.add_argument("exe", type=Path)
    parser.add_argument("layout_probe_json", type=Path)
    parser.add_argument("output_csv", type=Path)
    parser.add_argument("--summary", type=Path)
    parser.add_argument("--allow-unknown-sample", action="store_true")
    parser.add_argument("--require-4896-unique", action="store_true")
    args = parser.parse_args()

    result = export_raw_registry_71(
        args.exe,
        args.layout_probe_json,
        args.output_csv,
        summary_json=args.summary,
        allow_unknown_sample=args.allow_unknown_sample,
    )
    print(json.dumps(result, indent=2, ensure_ascii=False))
    if not result["all_anchor_checks_pass"]:
        raise SystemExit(1)
    if args.require_4896_unique and int(result["unique_cmd_ids"]) != HISTORICAL_ROW_COUNT:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
