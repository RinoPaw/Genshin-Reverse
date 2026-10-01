from __future__ import annotations

import argparse
import csv
import json
from collections import Counter, defaultdict
from pathlib import Path

from .registry import CANONICAL_COLUMNS
from .registrylayout import HISTORICAL_ROW_COUNT


def _load_csv(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))


def _load_json(path: Path) -> dict[str, object]:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def _parse_int(value: object) -> int | None:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        return int(text, 0)
    except ValueError:
        return None


def _semantic_names(rows: list[dict[str, str]]) -> dict[int, str]:
    result: dict[int, str] = {}
    for row in rows:
        cmd_id = _parse_int(row.get("cmd_id"))
        name = str(row.get("semantic_name", "")).strip()
        if cmd_id is None or not name:
            continue
        # The importer deduplicates numeric opcode values. Retain that invariant here.
        if cmd_id in result and result[cmd_id] != name:
            raise ValueError(f"control set gives CmdId {cmd_id} multiple semantic names")
        result[cmd_id] = name
    return result


def _getcmd_index(rows: list[dict[str, str]]) -> dict[tuple[int, int], set[str]]:
    result: dict[tuple[int, int], set[str]] = defaultdict(set)
    for row in rows:
        cmd_id = _parse_int(row.get("cmd_id"))
        tdi = _parse_int(row.get("type_definition_index"))
        rva = str(row.get("get_cmd_id_rva", "")).strip()
        if cmd_id is None or tdi is None or not rva:
            continue
        result[(cmd_id, tdi)].add(f"0x{int(rva, 0):X}")
    return result


def _row_index(rows: list[dict[str, str]], name: str) -> dict[int, dict[str, str]]:
    result: dict[int, dict[str, str]] = {}
    for row in rows:
        index = _parse_int(row.get("index"))
        if index is None:
            raise ValueError(f"{name} row is missing a valid index")
        if index in result:
            raise ValueError(f"{name} has duplicate row index {index}")
        result[index] = row
    return result


def publish_canonical_registry_71(
    direct_raw_csv: Path,
    usage_raw_csv: Path,
    compare_json: Path,
    direction_audit_json: Path,
    known_opcodes_csv: Path,
    getcmd_candidates_csv: Path,
    hashes_json: Path,
    output_dir: Path,
) -> dict[str, object]:
    comparison = _load_json(compare_json)
    direction = _load_json(direction_audit_json)
    hashes = _load_json(hashes_json)

    if not bool(comparison.get("full_agreement")):
        raise ValueError("independent native registry paths do not have full row-by-row agreement")
    if comparison.get("status") != "independent-native-paths-agree":
        raise ValueError(f"unexpected native comparison status: {comparison.get('status')}")
    if int(comparison.get("complete_matches", 0)) != HISTORICAL_ROW_COUNT:
        raise ValueError("native comparison does not contain 4,896 complete matches")

    if direction.get("status") != "direction-mapping-strongly-validated":
        raise ValueError("registry direction mapping has not been strongly validated")
    if not bool(direction.get("perfect_req_rsp_suffix_agreement")):
        raise ValueError("Req/Rsp suffix controls do not perfectly agree with registry flags")
    if not bool(direction.get("perfect_req_rsp_pair_agreement")):
        raise ValueError("Req/Rsp pair controls do not perfectly agree with registry flags")

    direct_rows = _load_csv(direct_raw_csv)
    usage_rows = _load_csv(usage_raw_csv)
    known_rows = _load_csv(known_opcodes_csv)
    getcmd_rows = _load_csv(getcmd_candidates_csv)

    direct_by_index = _row_index(direct_rows, "direct raw registry")
    usage_by_index = _row_index(usage_rows, "usage-backed raw registry")
    if len(direct_by_index) != HISTORICAL_ROW_COUNT or len(usage_by_index) != HISTORICAL_ROW_COUNT:
        raise ValueError("raw registry population is not exactly 4,896 rows")
    if set(direct_by_index) != set(range(HISTORICAL_ROW_COUNT)):
        raise ValueError("direct raw registry indices are not contiguous 0..4895")
    if set(usage_by_index) != set(range(HISTORICAL_ROW_COUNT)):
        raise ValueError("usage-backed raw registry indices are not contiguous 0..4895")

    semantic_by_cmd = _semantic_names(known_rows)
    known_ids = set(semantic_by_cmd)
    getcmd_by_identity = _getcmd_index(getcmd_rows)

    canonical: list[dict[str, str]] = []
    raw_ids: set[int] = set()
    missing_type_rows: list[int] = []
    ambiguous_getcmd: list[dict[str, object]] = []

    for index in range(HISTORICAL_ROW_COUNT):
        direct = direct_by_index[index]
        usage = usage_by_index[index]
        cmd_id = _parse_int(direct.get("cmd_id"))
        usage_cmd = _parse_int(usage.get("cmd_id"))
        flag = _parse_int(direct.get("registry_flag"))
        usage_flag = _parse_int(usage.get("registry_flag"))
        if cmd_id is None or usage_cmd != cmd_id:
            raise ValueError(f"raw path CmdId disagreement at row {index}")
        if flag is None or usage_flag != flag:
            raise ValueError(f"raw path flag disagreement at row {index}")
        if cmd_id in raw_ids:
            raise ValueError(f"duplicate CmdId {cmd_id} in raw registry")
        raw_ids.add(cmd_id)

        type_name = str(usage.get("type_name", "")).strip()
        tdi_text = str(usage.get("type_definition_index", "")).strip()
        if not type_name or not tdi_text:
            missing_type_rows.append(index)
            continue
        tdi = int(tdi_text, 0)

        direct_slot = str(direct.get("type_slot_rva", "")).strip()
        if not direct_slot:
            raise ValueError(f"row {index} is missing direct type-slot evidence")
        slot = f"0x{int(direct_slot, 0):X}"
        usage_slots = {
            int(part, 0)
            for part in str(usage.get("type_slot_rvas", "")).split("|")
            if part.strip()
        }
        if int(slot, 0) not in usage_slots:
            raise ValueError(f"row {index} direct type slot is absent from usage-backed slot evidence")

        getcmd_rvas = sorted(getcmd_by_identity.get((cmd_id, tdi), set()))
        if len(getcmd_rvas) > 1:
            ambiguous_getcmd.append(
                {"index": index, "cmd_id": cmd_id, "type_definition_index": tdi, "rvas": getcmd_rvas}
            )
        getcmd_rva = getcmd_rvas[0] if len(getcmd_rvas) == 1 else ""

        if flag == 1:
            direction_text = "C2S"
        elif flag == 0:
            direction_text = "S2C"
        else:
            raise ValueError(f"row {index} has non-binary registry flag {flag}")

        semantic_name = semantic_by_cmd.get(cmd_id, "")
        evidence = (
            "7.1 native registry recovered by independent direct-slot and usage-backed paths; "
            "row agreement verified; direction validated by independent Req/Rsp controls"
        )
        notes = "semantic name imported from AstaPS control set" if semantic_name else "semantic name unresolved"
        canonical.append(
            {
                "cmd_id": str(cmd_id),
                "type_name": type_name,
                "type_definition_index": str(tdi),
                "type_cache_rva": slot,
                "direction": direction_text,
                "get_cmd_id_rva": getcmd_rva,
                "semantic_name": semantic_name,
                "status": "static-verified",
                "evidence": evidence,
                "notes": notes,
            }
        )

    if missing_type_rows:
        raise ValueError(
            f"usage-backed raw registry lacks unique type identity for {len(missing_type_rows)} rows; "
            f"first indices: {missing_type_rows[:20]}"
        )
    if ambiguous_getcmd:
        raise ValueError(
            f"{len(ambiguous_getcmd)} rows have multiple GetCmdId RVA candidates; "
            f"first: {ambiguous_getcmd[:5]}"
        )
    if len(canonical) != HISTORICAL_ROW_COUNT or len(raw_ids) != HISTORICAL_ROW_COUNT:
        raise ValueError("canonical projection did not preserve the exact 4,896-entry population")

    missing_controls = sorted(known_ids - raw_ids)
    if missing_controls:
        raise ValueError(
            f"native registry misses {len(missing_controls)} current control-set CmdIds; "
            f"first: {missing_controls[:20]}"
        )

    canonical.sort(key=lambda row: int(row["cmd_id"]))
    output_dir.mkdir(parents=True, exist_ok=True)
    with (output_dir / "registry.csv").open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=CANONICAL_COLUMNS)
        writer.writeheader()
        writer.writerows(canonical)
    (output_dir / "registry.json").write_text(
        json.dumps(canonical, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )

    samples = dict(hashes.get("samples", {}))
    summary: dict[str, object] = {
        "row_count": len(canonical),
        "unique_cmd_ids": len(raw_ids),
        "direction_counts": dict(Counter(row["direction"] for row in canonical)),
        "semantic_name_count": sum(bool(row["semantic_name"]) for row in canonical),
        "missing_semantic_name": sum(not row["semantic_name"] for row in canonical),
        "get_cmd_id_rva_count": sum(bool(row["get_cmd_id_rva"]) for row in canonical),
        "control_set_unique_cmd_ids": len(known_ids),
        "control_set_missing": 0,
        "native_comparison_status": comparison.get("status"),
        "direction_audit_status": direction.get("status"),
        "provenance": {
            "game_version": hashes.get("game_version"),
            "region": hashes.get("region"),
            "platform": hashes.get("platform"),
            "exe_sha256": dict(samples.get("GenshinImpact.exe", {})).get("sha256"),
            "metadata_sha256": dict(samples.get("global-metadata.dat", {})).get("sha256"),
            "direct_raw_csv": str(direct_raw_csv),
            "usage_raw_csv": str(usage_raw_csv),
            "comparison_json": str(compare_json),
            "direction_audit_json": str(direction_audit_json),
            "known_opcodes_csv": str(known_opcodes_csv),
            "getcmd_candidates_csv": str(getcmd_candidates_csv),
        },
        "status": "canonical-static-registry",
        "notes": [
            "numeric membership, obfuscated client type identity, type slot and direction passed the publication gates",
            "semantic names are supplemental independent control-set labels; blank names remain intentionally unresolved",
            "static-verified does not imply runtime observation of every packet",
        ],
    }
    (output_dir / "summary.json").write_text(
        json.dumps(summary, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    return summary


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="python -m genshinre.registrypublish",
        description="Publish canonical 7.1 registry artifacts only after all structural and direction gates pass.",
    )
    parser.add_argument("direct_raw_csv", type=Path)
    parser.add_argument("usage_raw_csv", type=Path)
    parser.add_argument("compare_json", type=Path)
    parser.add_argument("direction_audit_json", type=Path)
    parser.add_argument("known_opcodes_csv", type=Path)
    parser.add_argument("getcmd_candidates_csv", type=Path)
    parser.add_argument("hashes_json", type=Path)
    parser.add_argument("output_dir", type=Path)
    args = parser.parse_args()

    result = publish_canonical_registry_71(
        args.direct_raw_csv,
        args.usage_raw_csv,
        args.compare_json,
        args.direction_audit_json,
        args.known_opcodes_csv,
        args.getcmd_candidates_csv,
        args.hashes_json,
        args.output_dir,
    )
    print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
