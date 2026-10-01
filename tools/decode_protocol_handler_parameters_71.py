from __future__ import annotations

import argparse
import csv
import hashlib
import json
import mmap
from pathlib import Path

from genshinre.mhy71 import (
    BODY_SKIP,
    EMBEDDED_HEADER_RVA,
    EMBEDDED_HEADER_SIZE,
    EXPECTED_EXE_SHA256,
    EXPECTED_METADATA_SHA256,
    _header_layout,
)
from genshinre.pe import PEImage

MASK32 = 0xFFFFFFFF
MASK64 = 0xFFFFFFFFFFFFFFFF

# Recovered from the exact 7.1 global executable around RVA 0x5287EE.
# The native loop indexes 8-byte parameter records with r12=parameter_index,
# derives a per-index key, and decodes record[0] into an IL2CPP runtime type index.
PARAMETER_RECORD_STRIDE = 8
PARAM_KEY_MUL1 = 0xA291
PARAM_KEY_ADD1 = 0x48B5FFB1
PARAM_KEY_XOR1 = 0x19E1D47A
PARAM_KEY_MUL2 = 0x56E732D7
PARAM_KEY_SHIFT = 0x15
PARAM_KEY_ADD2 = 0x7B48E804
PARAM_TYPE_XOR = 0x31BF59F3

KNOWN_HANDLER_OWNER = "LLCGIEDMIIG"
KNOWN_HANDLER_CONTROLS = {
    22899: ("DoSetPlayerBornDataNotify", 0x0C227790),
    3064: ("PlayerNicknameNotify", 0x0C23BA20),
    20824: ("SetPlayerNameRsp", 0x0C2513A0),
}


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(8 * 1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _parse_int(value: str | None) -> int | None:
    text = (value or "").strip()
    if not text:
        return None
    try:
        return int(text, 0)
    except ValueError:
        return None


def _sx32(value: int) -> int:
    value &= MASK32
    return value if value < 0x80000000 else value - 0x100000000


def parameter_type_key(parameter_index: int) -> int:
    rax = (parameter_index * PARAM_KEY_MUL1) & MASK64
    rax = (rax + _sx32(PARAM_KEY_ADD1)) & MASK64
    rax ^= _sx32(PARAM_KEY_XOR1) & MASK64
    mixed = (rax * _sx32(PARAM_KEY_MUL2)) & MASK64
    return ((mixed >> PARAM_KEY_SHIFT) + PARAM_KEY_ADD2) & MASK32


def decode_parameter_type_index(parameter_index: int, raw_type_word: int) -> int:
    return parameter_type_key(parameter_index) ^ raw_type_word ^ PARAM_TYPE_XOR


def _load_csv(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))


def _runtime_type_maps(path: Path) -> tuple[dict[str, list[int]], dict[int, set[str]]]:
    by_name: dict[str, list[int]] = {}
    by_index: dict[int, set[str]] = {}
    for row in _load_csv(path):
        name = (row.get("type_name") or "").strip()
        index = _parse_int(row.get("type_index"))
        if not name or index is None:
            continue
        by_name.setdefault(name, []).append(index)
        by_index.setdefault(index, set()).add(name)
    return by_name, by_index


def main() -> None:
    p = argparse.ArgumentParser(
        description="Decode exact 7.1 MHY parameter type records and find protocol handler consumers."
    )
    p.add_argument("exe", type=Path)
    p.add_argument("metadata", type=Path)
    p.add_argument("registry_csv", type=Path)
    p.add_argument("methods_csv", type=Path)
    p.add_argument("runtime_types_csv", type=Path)
    p.add_argument("candidate_csv", type=Path)
    p.add_argument("output_json", type=Path)
    p.add_argument("--control-cmd", action="append", default=[])
    p.add_argument("--allow-unknown-sample", action="store_true")
    args = p.parse_args()

    exe_sha = _sha256(args.exe)
    metadata_sha = _sha256(args.metadata)
    if not args.allow_unknown_sample:
        if exe_sha != EXPECTED_EXE_SHA256:
            raise SystemExit(f"unexpected executable SHA-256: {exe_sha}")
        if metadata_sha != EXPECTED_METADATA_SHA256:
            raise SystemExit(f"unexpected metadata SHA-256: {metadata_sha}")

    registry_rows = _load_csv(args.registry_csv)
    registry = {int(row["cmd_id"], 0): row for row in registry_rows}
    candidate_ids = [int(row["cmd_id"], 0) for row in _load_csv(args.candidate_csv)]
    control_ids = [int(value, 0) for value in args.control_cmd]
    focus_ids = list(dict.fromkeys(candidate_ids + control_ids))

    missing = [cmd for cmd in focus_ids if cmd not in registry]
    if missing:
        raise SystemExit(f"CmdIds missing from registry: {missing}")

    by_name, runtime_names = _runtime_type_maps(args.runtime_types_csv)
    focus_runtime_index_to_cmds: dict[int, set[int]] = {}
    runtime_indices_by_cmd: dict[int, list[int]] = {}
    for cmd in focus_ids:
        type_name = (registry[cmd].get("type_name") or "").strip()
        indices = sorted(set(by_name.get(type_name, [])))
        runtime_indices_by_cmd[cmd] = indices
        for index in indices:
            focus_runtime_index_to_cmds.setdefault(index, set()).add(cmd)

    hits_by_cmd: dict[int, list[dict[str, object]]] = {cmd: [] for cmd in focus_ids}
    decoded_parameter_count = 0
    unknown_runtime_type_count = 0

    with PEImage(args.exe) as image, args.metadata.open("rb") as metadata_file:
        header = image.read_rva(EMBEDDED_HEADER_RVA, EMBEDDED_HEADER_SIZE)
        layout = _header_layout(header)
        parameter_base = BODY_SKIP + int(layout["parameter_offset"])
        metadata = mmap.mmap(metadata_file.fileno(), 0, access=mmap.ACCESS_READ)
        try:
            with args.methods_csv.open("r", encoding="utf-8-sig", newline="") as f:
                for row in csv.DictReader(f):
                    parameter_start = _parse_int(row.get("parameter_start"))
                    parameter_count = _parse_int(row.get("parameter_count"))
                    if parameter_start is None or parameter_count is None or parameter_count <= 0:
                        continue
                    for ordinal in range(parameter_count):
                        parameter_index = parameter_start + ordinal
                        offset = parameter_base + parameter_index * PARAMETER_RECORD_STRIDE
                        if offset < 0 or offset + 4 > len(metadata):
                            continue
                        raw_word = int.from_bytes(metadata[offset : offset + 4], "little")
                        type_index = decode_parameter_type_index(parameter_index, raw_word)
                        decoded_parameter_count += 1
                        if type_index not in runtime_names:
                            unknown_runtime_type_count += 1
                        cmds = focus_runtime_index_to_cmds.get(type_index)
                        if not cmds:
                            continue
                        hit = {
                            "method_index": row.get("method_index", ""),
                            "method_rva": row.get("rva", ""),
                            "owner_type": row.get("type_name", ""),
                            "method_name": row.get("method_name", ""),
                            "parameter_start": parameter_start,
                            "parameter_count": parameter_count,
                            "parameter_ordinal": ordinal,
                            "parameter_index": parameter_index,
                            "raw_type_word": f"0x{raw_word:08X}",
                            "decoded_runtime_type_index": type_index,
                            "decoded_runtime_type_names": sorted(runtime_names.get(type_index, set())),
                            "known_handler_owner": row.get("type_name", "") == KNOWN_HANDLER_OWNER,
                        }
                        for cmd in cmds:
                            hits_by_cmd[cmd].append(hit)
        finally:
            metadata.close()

    candidate_set = set(candidate_ids)
    rows = []
    for cmd in focus_ids:
        reg = registry[cmd]
        hits = hits_by_cmd[cmd]
        owner_hits = [h for h in hits if h["known_handler_owner"]]
        rows.append(
            {
                "cmd_id": cmd,
                "role": "candidate" if cmd in candidate_set else "control",
                "semantic_name": reg.get("semantic_name", ""),
                "type_name": reg.get("type_name", ""),
                "runtime_type_indices": runtime_indices_by_cmd[cmd],
                "parameter_hit_count": len(hits),
                "known_handler_owner_hit_count": len(owner_hits),
                "known_handler_owner_hits": owner_hits,
                "all_hits": hits,
            }
        )

    control_validation = []
    controls_ok = True
    for cmd, (semantic_name, expected_rva) in KNOWN_HANDLER_CONTROLS.items():
        if cmd not in hits_by_cmd:
            continue
        exact = [
            hit
            for hit in hits_by_cmd[cmd]
            if hit["known_handler_owner"]
            and _parse_int(str(hit.get("method_rva", ""))) == expected_rva
        ]
        ok = bool(exact)
        controls_ok &= ok
        control_validation.append(
            {
                "cmd_id": cmd,
                "semantic_name": semantic_name,
                "expected_handler_owner": KNOWN_HANDLER_OWNER,
                "expected_handler_rva": f"0x{expected_rva:X}",
                "matched": ok,
                "matches": exact,
            }
        )

    report = {
        "sample": "7.1.0-global/windows-x64",
        "exe_sha256": exe_sha,
        "metadata_sha256": metadata_sha,
        "parameter_record_stride": PARAMETER_RECORD_STRIDE,
        "parameter_type_formula": {
            "native_anchor_rva": "0x5287EE",
            "raw_type_word_offset": 0,
            "mul1": f"0x{PARAM_KEY_MUL1:X}",
            "add1": f"0x{PARAM_KEY_ADD1:X}",
            "xor1": f"0x{PARAM_KEY_XOR1:X}",
            "mul2": f"0x{PARAM_KEY_MUL2:X}",
            "shift": PARAM_KEY_SHIFT,
            "add2": f"0x{PARAM_KEY_ADD2:X}",
            "type_xor": f"0x{PARAM_TYPE_XOR:X}",
        },
        "decoded_parameter_count": decoded_parameter_count,
        "unknown_runtime_type_count": unknown_runtime_type_count,
        "control_validation_passed": controls_ok,
        "control_validation": control_validation,
        "rows": rows,
        "notes": [
            "8-byte parameter record stride and type-index decode are taken from the exact 7.1 global native loop around RVA 0x5287EE",
            "known handler controls must match before candidate hits are promoted as protocol evidence",
            f"{KNOWN_HANDLER_OWNER} is the confirmed owner type for the current born/nickname/name-response packet handlers",
        ],
    }
    args.output_json.parent.mkdir(parents=True, exist_ok=True)
    args.output_json.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    print("controls_ok", controls_ok)
    for item in control_validation:
        print(item["cmd_id"], item["semantic_name"], "matched=", item["matched"])
    print("cmd role type param-hits handler-owner-hits")
    for row in rows:
        print(
            row["cmd_id"], row["role"], row["type_name"],
            row["parameter_hit_count"], row["known_handler_owner_hit_count"],
        )
        for hit in row["known_handler_owner_hits"][:12]:
            print(
                "  ", hit["method_rva"],
                f"{hit['owner_type']}.{hit['method_name']}",
                "param", hit["parameter_ordinal"],
                "runtime", hit["decoded_runtime_type_index"],
            )

    if control_validation and not controls_ok:
        raise SystemExit("known S2C handler parameter controls did not validate")


if __name__ == "__main__":
    main()
