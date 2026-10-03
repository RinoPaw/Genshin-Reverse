from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
import struct
from pathlib import Path

from .nativeprofile import PROFILE_71

EXPECTED_REGISTRY_ROWS = 4896
CMD_BYTES = EXPECTED_REGISTRY_ROWS * 2

CMD_ANCHORS = {
    2232: 9369,
    3118: 22899,
}

COLUMNS = (
    "index",
    "cmd_id",
    "registry_flag",
    "direction",
    "type_slot_rva",
    "status",
    "evidence",
)


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(8 * 1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _read_controls(path: Path) -> dict[int, int]:
    result: dict[int, int] = {}
    with path.open("r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        required = {"cmd_id", "direction"}
        missing = required - set(reader.fieldnames or ())
        if missing:
            raise ValueError(f"{path} missing required columns: {', '.join(sorted(missing))}")
        for line_no, row in enumerate(reader, start=2):
            try:
                cmd = int(str(row["cmd_id"]), 0)
            except ValueError as exc:
                raise ValueError(f"{path}:{line_no}: invalid cmd_id {row['cmd_id']!r}") from exc
            if cmd in result:
                raise ValueError(f"{path}:{line_no}: duplicate cmd_id {cmd}")
            direction = str(row.get("direction", "")).strip().upper()
            if direction == "C2S":
                result[cmd] = 1
            elif direction == "S2C":
                result[cmd] = 0
            else:
                raise ValueError(f"{path}:{line_no}: invalid confirmed direction {direction!r}")
    if not result:
        raise ValueError(f"{path} contains no direction controls")
    return result


def _read_slots(path: Path) -> dict[int, str]:
    result: dict[int, str] = {}
    with path.open("r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        required = {"index", "type_slot_rva"}
        missing = required - set(reader.fieldnames or ())
        if missing:
            raise ValueError(f"{path} missing required columns: {', '.join(sorted(missing))}")
        for line_no, row in enumerate(reader, start=2):
            try:
                index = int(str(row["index"]), 0)
            except ValueError as exc:
                raise ValueError(f"{path}:{line_no}: invalid index {row['index']!r}") from exc
            slot = str(row.get("type_slot_rva", "")).strip()
            if not slot:
                raise ValueError(f"{path}:{line_no}: missing type_slot_rva")
            try:
                int(slot, 0)
            except ValueError as exc:
                raise ValueError(f"{path}:{line_no}: invalid type_slot_rva {slot!r}") from exc
            if index in result:
                raise ValueError(f"{path}:{line_no}: duplicate index {index}")
            result[index] = slot
    return result


def _find_cmd_array(data: bytes) -> tuple[int, list[int], list[int]]:
    needle = struct.pack("<H", CMD_ANCHORS[2232])
    candidates: list[tuple[int, list[int]]] = []
    rejected_bases: list[int] = []
    cursor = 0
    while True:
        pos = data.find(needle, cursor)
        if pos < 0:
            break
        cursor = pos + 1
        base = pos - 2232 * 2
        if base < 0 or base + CMD_BYTES > len(data):
            continue
        if struct.unpack_from("<H", data, base + 3118 * 2)[0] != CMD_ANCHORS[3118]:
            continue
        values = list(struct.unpack_from(f"<{EXPECTED_REGISTRY_ROWS}H", data, base))
        if any(v == 0 for v in values):
            rejected_bases.append(base)
            continue
        if len(set(values)) != EXPECTED_REGISTRY_ROWS:
            rejected_bases.append(base)
            continue
        candidates.append((base, values))
    if len(candidates) != 1:
        raise ValueError(
            f"expected exactly one {EXPECTED_REGISTRY_ROWS:,}-entry CmdId blob, found {len(candidates)}"
        )
    return candidates[0][0], candidates[0][1], rejected_bases


def _find_flag_array(
    data: bytes,
    cmd_ids: list[int],
    controls: dict[int, int],
) -> tuple[int, list[int], int]:
    index_by_cmd = {cmd: i for i, cmd in enumerate(cmd_ids)}
    missing_controls = sorted(set(controls) - set(index_by_cmd))
    if missing_controls:
        raise ValueError(f"direction controls missing from recovered CmdId array: {missing_controls}")
    indexed_controls = {index_by_cmd[cmd]: expected for cmd, expected in controls.items()}
    if len(indexed_controls) < 4:
        raise ValueError(f"need at least four direction controls, got {len(indexed_controls)}")

    one_control_indices = [i for i, expected in indexed_controls.items() if expected == 1]
    if not one_control_indices:
        raise ValueError("direction controls contain no C2S=1 anchor")
    anchor_index = one_control_indices[0]

    candidates: dict[int, list[int]] = {}
    binary_runs = 0
    pattern = re.compile(b"[\x00\x01]{4896,}")
    for match in pattern.finditer(data):
        binary_runs += 1
        start_run, end_run = match.span()
        run = data[start_run:end_run]
        p = run.find(b"\x01")
        while p >= 0:
            base = start_run + p - anchor_index
            if base >= start_run and base + EXPECTED_REGISTRY_ROWS <= end_run:
                if all(data[base + index] == expected for index, expected in indexed_controls.items()):
                    values = list(data[base : base + EXPECTED_REGISTRY_ROWS])
                    if all(v in (0, 1) for v in values):
                        candidates.setdefault(base, values)
            p = run.find(b"\x01", p + 1)

    if len(candidates) != 1:
        detail = [
            {"file_offset": f"0x{base:X}", "ones": sum(values)}
            for base, values in sorted(candidates.items())[:20]
        ]
        raise ValueError(f"expected exactly one flag blob, found {len(candidates)}: {detail}")
    base, values = next(iter(candidates.items()))
    return base, values, binary_runs


def recover_registry_arrays_71(
    exe: Path,
    type_slots_csv: Path,
    known_opcodes_csv: Path,
    output_csv: Path,
    summary_json: Path | None = None,
) -> dict[str, object]:
    exe_sha = _sha256(exe)
    if exe_sha != PROFILE_71.exe_sha256:
        raise ValueError(f"unexpected GenshinImpact.exe SHA-256: {exe_sha}")

    data = exe.read_bytes()
    slots = _read_slots(type_slots_csv)
    if len(slots) != EXPECTED_REGISTRY_ROWS or set(slots) != set(range(EXPECTED_REGISTRY_ROWS)):
        raise ValueError("type-slot artifact must contain contiguous indices 0..4895 exactly")
    controls = _read_controls(known_opcodes_csv)

    cmd_base, cmd_ids, rejected_cmd_bases = _find_cmd_array(data)
    flag_base, flags, binary_runs = _find_flag_array(data, cmd_ids, controls)

    index_by_cmd = {cmd: i for i, cmd in enumerate(cmd_ids)}
    control_results: dict[str, object] = {}
    for cmd, expected in sorted(controls.items()):
        index = index_by_cmd[cmd]
        observed = flags[index]
        if observed != expected:
            raise ValueError(
                f"direction control CmdId {cmd} expected flag {expected}, observed {observed}"
            )
        control_results[str(cmd)] = {
            "present": True,
            "index": index,
            "expected_flag": expected,
            "observed_flag": observed,
            "matched": True,
        }

    summary: dict[str, object] = {
        "exe_sha256": exe_sha,
        "row_count": EXPECTED_REGISTRY_ROWS,
        "unique_cmd_ids": len(set(cmd_ids)),
        "cmd_blob_file_offset": f"0x{cmd_base:X}",
        "flag_blob_file_offset": f"0x{flag_base:X}",
        "flag_counts": {"0": flags.count(0), "1": flags.count(1)},
        "binary_runs_scanned": binary_runs,
        "rejected_cmd_blob_bases": [f"0x{x:X}" for x in rejected_cmd_bases[:20]],
        "controls": control_results,
        "anchors": {
            "2232": {"cmd_id": cmd_ids[2232], "flag": flags[2232], "type_slot_rva": slots[2232]},
            "3118": {"cmd_id": cmd_ids[3118], "flag": flags[3118], "type_slot_rva": slots[3118]},
        },
        "complete": len(set(cmd_ids)) == EXPECTED_REGISTRY_ROWS,
        "status": "static-verified-native-registry-arrays",
    }
    if not summary["complete"]:
        raise ValueError("native registry array recovery did not produce 4,896 unique CmdIds")

    output_csv.parent.mkdir(parents=True, exist_ok=True)
    with output_csv.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=COLUMNS)
        writer.writeheader()
        for index, (cmd, flag) in enumerate(zip(cmd_ids, flags, strict=True)):
            writer.writerow(
                {
                    "index": index,
                    "cmd_id": cmd,
                    "registry_flag": flag,
                    "direction": "C2S" if flag == 1 else "S2C",
                    "type_slot_rva": slots[index],
                    "status": "static-verified",
                    "evidence": "7.1 native ushort[4896] CmdId blob + byte[4896] flag blob + indexed type-slot constructor",
                }
            )

    if summary_json is None:
        summary_json = output_csv.with_suffix(".summary.json")
    summary_json.write_text(json.dumps(summary, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return summary


def main() -> None:
    p = argparse.ArgumentParser(
        description="Recover the exact pinned-7.1 native CmdId/flag arrays and join indexed type slots."
    )
    p.add_argument("exe", type=Path)
    p.add_argument("type_slots_csv", type=Path)
    p.add_argument("known_opcodes_csv", type=Path)
    p.add_argument("output_csv", type=Path)
    p.add_argument("--summary", type=Path)
    args = p.parse_args()
    result = recover_registry_arrays_71(
        args.exe,
        args.type_slots_csv,
        args.known_opcodes_csv,
        args.output_csv,
        summary_json=args.summary,
    )
    print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
