from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path

from .mhy71 import EXPECTED_EXE_SHA256, _sha256
from .pe import PEImage
from .registrylayout import HISTORICAL_ROW_COUNT, _read_uint

OUTPUT_COLUMNS = (
    "index",
    "cmd_id",
    "cmd_hex",
    "registry_flag",
    "usage_destination",
    "type_slot_rvas",
    "type_index",
    "type_definition_index",
    "type_name",
    "layout_stride",
    "cmd_width",
    "status",
    "evidence",
)


def _load_csv(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))


def _parse_int(value: object) -> int:
    return int(str(value), 0)


def _is_strong(candidate: dict[str, object]) -> bool:
    cmd = dict(candidate.get("cmd_metrics", {}))
    usage = dict(candidate.get("usage_metrics", {}))
    flag = dict(candidate.get("flag_metrics", {}))
    return (
        int(cmd.get("unique_nonzero_values", 0)) == HISTORICAL_ROW_COUNT
        and float(cmd.get("protocol_range_ratio", 0.0)) == 1.0
        and float(flag.get("binary_ratio", 0.0)) == 1.0
        and float(usage.get("resolved_ratio", 0.0)) >= 0.99
    )


def choose_closed_usage_layout(probe: dict[str, object]) -> dict[str, object]:
    """Close width-only aliases while retaining genuine layout ambiguity.

    uint16 CmdId reads can mirror uint32 values while every current CmdId fits in
    16 bits. Likewise, a zero-extended 0/1 flag can look valid at widths 1/2/4.
    Those cases describe the same offsets. Prefer uint32 CmdIds and the narrowest
    flag read as deterministic representations; different offsets/strides remain
    distinct candidates and therefore fail closed.
    """

    strong = [dict(item) for item in list(probe.get("candidates", [])) if _is_strong(dict(item))]
    reported = int(probe.get("strong_candidate_count", len(strong)))
    if reported != len(strong):
        raise ValueError(
            f"usage-layout probe retained {len(strong)} of {reported} strong candidates; "
            "rerun the probe with a larger --max-results before export"
        )
    if not strong:
        raise ValueError("usage-layout probe contains no strong candidate")

    normalized: dict[tuple[object, ...], dict[str, object]] = {}
    for candidate in strong:
        usage_field = dict(candidate["usage_field"])
        flag_field = dict(candidate["flag_field"])
        key = (
            str(candidate["cmd_column_base_rva"]),
            int(candidate["stride"]),
            int(candidate["anchor_22899_index_interpretation"]),
            int(usage_field["relative_to_cmd"]),
            int(flag_field["relative_to_cmd"]),
        )
        current = normalized.get(key)
        if current is None:
            normalized[key] = candidate
            continue
        current_flag = dict(current["flag_field"])
        candidate_rank = (int(candidate["cmd_width"]), -int(flag_field["width"]))
        current_rank = (int(current["cmd_width"]), -int(current_flag["width"]))
        if candidate_rank > current_rank:
            normalized[key] = candidate

    if len(normalized) != 1:
        raise ValueError(
            f"usage-backed registry layout is not closed: {len(strong)} strong candidates "
            f"collapse to {len(normalized)} distinct offset/stride interpretations"
        )
    return next(iter(normalized.values()))


def _usage_identity_index(usage_types_csv: Path) -> dict[int, dict[str, object]]:
    grouped: dict[int, list[dict[str, str]]] = {}
    for row in _load_csv(usage_types_csv):
        text = str(row.get("usage_destination", "")).strip()
        if not text:
            continue
        try:
            usage = int(text, 0)
        except ValueError:
            continue
        grouped.setdefault(usage, []).append(row)

    result: dict[int, dict[str, object]] = {}
    for usage, rows in grouped.items():
        identities = {
            (
                str(row.get("type_index", "")).strip(),
                str(row.get("type_definition_index", "")).strip(),
                str(row.get("type_name", "")).strip(),
            )
            for row in rows
            if str(row.get("type_name", "")).strip()
        }
        slots: set[int] = set()
        for row in rows:
            text = str(row.get("type_slot_rva", "")).strip()
            if not text:
                continue
            try:
                slots.add(int(text, 0))
            except ValueError:
                continue

        if len(identities) == 1:
            type_index, type_definition_index, type_name = next(iter(identities))
            result[usage] = {
                "resolved": True,
                "ambiguous": False,
                "type_index": type_index,
                "type_definition_index": type_definition_index,
                "type_name": type_name,
                "type_slot_rvas": tuple(sorted(slots)),
            }
        elif len(identities) > 1:
            result[usage] = {
                "resolved": False,
                "ambiguous": True,
                "type_index": "",
                "type_definition_index": "",
                "type_name": "",
                "type_slot_rvas": tuple(sorted(slots)),
            }
        else:
            result[usage] = {
                "resolved": False,
                "ambiguous": False,
                "type_index": "",
                "type_definition_index": "",
                "type_name": "",
                "type_slot_rvas": tuple(sorted(slots)),
            }
    return result


def export_usage_backed_registry_71(
    exe: Path,
    usage_layout_probe_json: Path,
    usage_types_csv: Path,
    output_csv: Path,
    summary_json: Path | None = None,
    allow_unknown_sample: bool = False,
    row_count: int = HISTORICAL_ROW_COUNT,
) -> dict[str, object]:
    exe_sha = _sha256(exe)
    if not allow_unknown_sample and exe_sha != EXPECTED_EXE_SHA256:
        raise ValueError(f"unexpected GenshinImpact.exe SHA-256: {exe_sha}")

    probe = json.loads(usage_layout_probe_json.read_text(encoding="utf-8-sig"))
    layout = choose_closed_usage_layout(probe)
    identities = _usage_identity_index(usage_types_csv)

    stride = int(layout["stride"])
    cmd_width = int(layout["cmd_width"])
    cmd_base = _parse_int(layout["cmd_column_base_rva"])
    usage_field = dict(layout["usage_field"])
    flag_field = dict(layout["flag_field"])
    usage_relative = int(usage_field["relative_to_cmd"])
    flag_relative = int(flag_field["relative_to_cmd"])
    flag_width = int(flag_field["width"])

    rows: list[dict[str, object]] = []
    unresolved_rows = 0
    ambiguous_rows = 0
    with PEImage(exe) as image:
        for index in range(row_count):
            cmd_rva = cmd_base + index * stride
            cmd_id = _read_uint(image, cmd_rva, cmd_width)
            usage = _read_uint(image, cmd_rva + usage_relative, 4)
            flag = _read_uint(image, cmd_rva + flag_relative, flag_width)
            if cmd_id is None or usage is None or flag is None:
                raise ValueError(f"registry row {index} field decode failed")
            if flag not in (0, 1):
                raise ValueError(f"registry row {index} has non-binary flag {flag}")

            identity = identities.get(usage)
            if identity is None:
                identity = {
                    "resolved": False,
                    "ambiguous": False,
                    "type_index": "",
                    "type_definition_index": "",
                    "type_name": "",
                    "type_slot_rvas": (),
                }
            if bool(identity["ambiguous"]):
                ambiguous_rows += 1
            elif not bool(identity["resolved"]):
                unresolved_rows += 1

            slots = tuple(identity["type_slot_rvas"])
            slot_text = "|".join(f"0x{int(slot):X}" for slot in slots)
            status = (
                "usage-type-resolved"
                if bool(identity["resolved"])
                else "usage-type-ambiguous"
                if bool(identity["ambiguous"])
                else "usage-type-unresolved"
            )
            rows.append(
                {
                    "index": index,
                    "cmd_id": cmd_id,
                    "cmd_hex": f"0x{cmd_id:X}",
                    "registry_flag": flag,
                    "usage_destination": usage,
                    "type_slot_rvas": slot_text,
                    "type_index": identity["type_index"],
                    "type_definition_index": identity["type_definition_index"],
                    "type_name": identity["type_name"],
                    "layout_stride": stride,
                    "cmd_width": cmd_width,
                    "status": status,
                    "evidence": "closed usage-backed native layout joined to independently recovered metadata usage/type map",
                }
            )

    output_csv.parent.mkdir(parents=True, exist_ok=True)
    with output_csv.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=OUTPUT_COLUMNS)
        writer.writeheader()
        writer.writerows(rows)

    cmd_ids = [int(row["cmd_id"]) for row in rows]
    flag_counts = {
        "0": sum(1 for row in rows if int(row["registry_flag"]) == 0),
        "1": sum(1 for row in rows if int(row["registry_flag"]) == 1),
    }
    anchor_22899_index = int(layout["anchor_22899_index_interpretation"])
    row9369 = rows[2232] if len(rows) > 2232 else None
    row22899 = rows[anchor_22899_index] if len(rows) > anchor_22899_index else None

    def slot_contains(row: dict[str, object] | None, wanted: int) -> bool:
        if row is None:
            return False
        return any(int(part, 0) == wanted for part in str(row["type_slot_rvas"]).split("|") if part)

    anchor_checks = {
        "9369": bool(
            row9369
            and int(row9369["cmd_id"]) == 9369
            and int(row9369["registry_flag"]) == 1
            and int(row9369["usage_destination"]) == 37_523
            and str(row9369["type_name"]) == "DMMJNICDOHM"
            and slot_contains(row9369, 0x057E6498)
        ),
        "22899": bool(
            row22899
            and int(row22899["cmd_id"]) == 22899
            and int(row22899["registry_flag"]) == 0
            and str(row22899["type_name"]) == "ONKOPMILDMF"
            and slot_contains(row22899, 0x057F6F60)
        ),
    }

    summary: dict[str, object] = {
        "exe_sha256": exe_sha,
        "row_count": len(rows),
        "unique_cmd_ids": len(set(cmd_ids)),
        "protocol_range_rows": sum(1 for cmd_id in cmd_ids if 1 <= cmd_id <= 65535),
        "resolved_type_rows": len(rows) - unresolved_rows - ambiguous_rows,
        "unresolved_type_rows": unresolved_rows,
        "ambiguous_type_rows": ambiguous_rows,
        "flag_counts": flag_counts,
        "layout": {
            "stride": stride,
            "cmd_width": cmd_width,
            "cmd_column_base_rva": f"0x{cmd_base:X}",
            "usage_field": usage_field,
            "flag_field": flag_field,
            "anchor_22899_index_interpretation": anchor_22899_index,
        },
        "anchor_checks": anchor_checks,
        "all_anchor_checks_pass": all(anchor_checks.values()),
        "historical_unique_cmdid_reference": HISTORICAL_ROW_COUNT,
        "status": "usage-backed-native-registry-rows",
        "notes": [
            "the compact row is decoded only after the usage-backed layout closes to one offset/stride interpretation",
            "type identity comes from the independently reconstructed metadata usage destination map",
            "multiple static type slots for one usage destination are preserved rather than silently collapsed",
            "semantic protobuf names remain a separate evidence layer",
        ],
    }
    if summary_json is None:
        summary_json = output_csv.with_suffix(".summary.json")
    summary_json.parent.mkdir(parents=True, exist_ok=True)
    summary_json.write_text(json.dumps(summary, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return summary


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="python -m genshinre.registryusageraw",
        description="Export 7.1 raw protocol rows from a uniquely closed usage-backed native registry layout.",
    )
    parser.add_argument("exe", type=Path)
    parser.add_argument("usage_layout_probe_json", type=Path)
    parser.add_argument("usage_types_csv", type=Path)
    parser.add_argument("output_csv", type=Path)
    parser.add_argument("--summary", type=Path)
    parser.add_argument("--allow-unknown-sample", action="store_true")
    parser.add_argument("--require-4896-unique", action="store_true")
    parser.add_argument("--require-all-types", action="store_true")
    args = parser.parse_args()

    result = export_usage_backed_registry_71(
        args.exe,
        args.usage_layout_probe_json,
        args.usage_types_csv,
        args.output_csv,
        summary_json=args.summary,
        allow_unknown_sample=args.allow_unknown_sample,
    )
    print(json.dumps(result, indent=2, ensure_ascii=False))
    if not result["all_anchor_checks_pass"]:
        raise SystemExit(1)
    if args.require_4896_unique and int(result["unique_cmd_ids"]) != HISTORICAL_ROW_COUNT:
        raise SystemExit(1)
    if args.require_all_types and (
        int(result["unresolved_type_rows"]) != 0 or int(result["ambiguous_type_rows"]) != 0
    ):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
