from __future__ import annotations

import argparse
import json
from pathlib import Path

from .registrylayout import HISTORICAL_ROW_COUNT
from .registryusageraw import export_usage_backed_registry_71


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


def _freeze_metric_value(value: object) -> object:
    if isinstance(value, dict):
        return tuple(sorted((str(key), _freeze_metric_value(item)) for key, item in value.items()))
    if isinstance(value, list):
        return tuple(_freeze_metric_value(item) for item in value)
    return value


def _metric_signature(metrics: dict[str, object], keys: tuple[str, ...]) -> tuple[object, ...]:
    return tuple(_freeze_metric_value(metrics.get(key)) for key in keys)


def _physical_layout_key(candidate: dict[str, object]) -> tuple[object, ...]:
    usage_field = dict(candidate["usage_field"])
    flag_field = dict(candidate["flag_field"])
    cmd_metrics = dict(candidate.get("cmd_metrics", {}))
    usage_metrics = dict(candidate.get("usage_metrics", {}))
    flag_metrics = dict(candidate.get("flag_metrics", {}))
    return (
        str(candidate["cmd_column_base_rva"]),
        int(candidate["stride"]),
        int(candidate["anchor_22899_index_interpretation"]),
        str(candidate.get("anchor_9369_cmd_rva", "")),
        str(candidate.get("anchor_22899_cmd_rva", "")),
        int(usage_field["relative_to_cmd"]),
        int(flag_field["relative_to_cmd"]),
        _metric_signature(
            cmd_metrics,
            (
                "readable_rows",
                "nonzero_rows",
                "protocol_range_rows",
                "unique_nonzero_values",
            ),
        ),
        _metric_signature(
            usage_metrics,
            ("readable_rows", "resolved_rows", "unique_values"),
        ),
        _metric_signature(
            flag_metrics,
            ("readable_rows", "binary_rows", "counts"),
        ),
    )


def choose_strict_usage_layout(probe: dict[str, object]) -> dict[str, object]:
    strong = [dict(item) for item in list(probe.get("candidates", [])) if _is_strong(dict(item))]
    reported = int(probe.get("strong_candidate_count", len(strong)))
    if reported != len(strong):
        raise ValueError(
            f"usage-layout probe retained {len(strong)} of {reported} strong candidates; "
            "rerun with a larger --max-results before export"
        )
    if not strong:
        raise ValueError("usage-layout probe contains no strong candidate")

    grouped: dict[tuple[object, ...], list[dict[str, object]]] = {}
    for candidate in strong:
        grouped.setdefault(_physical_layout_key(candidate), []).append(candidate)
    if len(grouped) != 1:
        raise ValueError(
            f"usage-backed registry layout is not closed: {len(strong)} strong candidates "
            f"form {len(grouped)} observationally distinct physical layouts"
        )

    aliases = next(iter(grouped.values()))
    # GetCmdId returns uint32. A uint16 alias is acceptable only because the
    # full-table CmdId metric signature above is identical. For a 0/1 flag,
    # keep the narrowest observationally identical representation.
    selected = max(
        aliases,
        key=lambda item: (
            int(item["cmd_width"]),
            -int(dict(item["flag_field"])["width"]),
        ),
    )
    result = dict(selected)
    result["cmd_width_aliases"] = sorted({int(item["cmd_width"]) for item in aliases})
    result["flag_width_aliases"] = sorted(
        {int(dict(item["flag_field"])["width"]) for item in aliases}
    )
    return result


def export_validated_usage_registry_71(
    exe: Path,
    usage_layout_probe_json: Path,
    usage_types_csv: Path,
    output_csv: Path,
    summary_json: Path | None = None,
    allow_unknown_sample: bool = False,
) -> dict[str, object]:
    probe = json.loads(usage_layout_probe_json.read_text(encoding="utf-8-sig"))
    selected = choose_strict_usage_layout(probe)

    summary = export_usage_backed_registry_71(
        exe,
        usage_layout_probe_json,
        usage_types_csv,
        output_csv,
        summary_json=summary_json,
        allow_unknown_sample=allow_unknown_sample,
    )

    actual = dict(summary["layout"])
    selected_usage = dict(selected["usage_field"])
    selected_flag = dict(selected["flag_field"])
    expected = {
        "stride": int(selected["stride"]),
        "cmd_width": int(selected["cmd_width"]),
        "cmd_column_base_rva": str(selected["cmd_column_base_rva"]),
        "usage_relative": int(selected_usage["relative_to_cmd"]),
        "flag_relative": int(selected_flag["relative_to_cmd"]),
        "flag_width": int(selected_flag["width"]),
    }
    observed = {
        "stride": int(actual["stride"]),
        "cmd_width": int(actual["cmd_width"]),
        "cmd_column_base_rva": str(actual["cmd_column_base_rva"]),
        "usage_relative": int(dict(actual["usage_field"])["relative_to_cmd"]),
        "flag_relative": int(dict(actual["flag_field"])["relative_to_cmd"]),
        "flag_width": int(dict(actual["flag_field"])["width"]),
    }
    if observed != expected:
        raise ValueError(
            "usage exporter selected a different layout after strict validation: "
            f"expected={expected!r} observed={observed!r}"
        )

    actual["cmd_width_aliases"] = list(selected["cmd_width_aliases"])
    actual["flag_width_aliases"] = list(selected["flag_width_aliases"])
    summary["layout"] = actual
    notes = list(summary.get("notes", []))
    notes.append(
        "CmdId/flag width aliases are accepted only when their complete-table metric signatures are identical"
    )
    summary["notes"] = notes
    summary["status"] = "strict-usage-backed-native-registry-rows"

    if summary_json is None:
        summary_json = output_csv.with_suffix(".summary.json")
    summary_json.parent.mkdir(parents=True, exist_ok=True)
    summary_json.write_text(json.dumps(summary, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return summary


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="python -m genshinre.registryusagevalidated",
        description="Strictly validate width aliases before exporting the 7.1 usage-backed native registry.",
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

    result = export_validated_usage_registry_71(
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
