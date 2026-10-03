from __future__ import annotations

import bisect
import csv
import json
import re
from pathlib import Path

from .pe import PEImage

# Exact pattern observed in the 7.0/7.1 scene-handler comparison: a 64-bit
# MOV loads the delegate/table entry into RCX from [base + disp32].  Keep this
# intentionally narrow; unsupported instruction shapes are ignored rather than
# guessed.
_MOV_R64_MEM_DISP32 = re.compile(rb"[\x48-\x4F]\x8B[\x80-\xBF].{4}", re.DOTALL)
_GPR64 = (
    "rax",
    "rcx",
    "rdx",
    "rbx",
    "rsp",
    "rbp",
    "rsi",
    "rdi",
    "r8",
    "r9",
    "r10",
    "r11",
    "r12",
    "r13",
    "r14",
    "r15",
)


def decode_scene_handler_slot_load(
    code: bytes,
    offset: int,
    instruction_rva: int,
) -> dict[str, object] | None:
    """Decode the verified ``mov rcx, qword ptr [base + disp32]`` shape.

    Supported instructions use REX.W, opcode 8B, ModRM mod=10 and a direct
    base register without SIB.  The destination must be RCX.  This is a
    research extractor for a known dispatch-consumer shape, not a general x86
    disassembler.
    """

    if offset < 0 or offset + 7 > len(code):
        return None

    rex = code[offset]
    if not 0x48 <= rex <= 0x4F:  # REX.W must be set.
        return None
    if code[offset + 1] != 0x8B:
        return None

    modrm = code[offset + 2]
    if (modrm >> 6) != 0b10:
        return None
    rm = modrm & 0x07
    if rm == 0x04:  # SIB is deliberately unsupported by the narrow decoder.
        return None

    reg = (modrm >> 3) & 0x07
    destination_code = reg | (0x08 if rex & 0x04 else 0)
    base_code = rm | (0x08 if rex & 0x01 else 0)
    if _GPR64[destination_code] != "rcx":
        return None

    displacement = int.from_bytes(
        code[offset + 3 : offset + 7], "little", signed=True
    )
    return {
        "instruction_rva": instruction_rva,
        "length": 7,
        "rex": f"0x{rex:02X}",
        "opcode": "0x8B",
        "modrm": f"0x{modrm:02X}",
        "destination_register": "rcx",
        "base_register": _GPR64[base_code],
        "slot_displacement": displacement,
        "instruction_hex": code[offset : offset + 7].hex(),
    }


def scan_scene_handler_slot_loads(
    code: bytes,
    *,
    base_rva: int,
    slot_start: int,
    slot_end: int,
    slot_alignment: int = 8,
) -> list[dict[str, object]]:
    """Scan a method body for verified scene-handler slot loads.

    ``slot_start``/``slot_end`` form a half-open displacement range.  Results
    are additionally alignment-gated to suppress byte-signature false hits.
    """

    if base_rva < 0:
        raise ValueError("base RVA must be non-negative")
    if slot_start < 0 or slot_end <= slot_start:
        raise ValueError("slot displacement range must be non-negative and non-empty")
    if slot_alignment <= 0:
        raise ValueError("slot alignment must be positive")

    rows: list[dict[str, object]] = []
    for match in _MOV_R64_MEM_DISP32.finditer(code):
        item = decode_scene_handler_slot_load(
            code,
            match.start(),
            base_rva + match.start(),
        )
        if item is None:
            continue
        slot = int(item["slot_displacement"])
        if not slot_start <= slot < slot_end:
            continue
        if slot % slot_alignment:
            continue
        rows.append(item)
    return rows


def _load_registry_by_type(registry_csv: Path) -> dict[str, dict[str, object]]:
    result: dict[str, dict[str, object]] = {}
    with registry_csv.open("r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        fields = set(reader.fieldnames or ())
        missing = {"cmd_id", "type_name"} - fields
        if missing:
            raise ValueError(
                f"{registry_csv} missing required columns: {', '.join(sorted(missing))}"
            )
        for line_no, row in enumerate(reader, start=2):
            type_name = str(row.get("type_name") or "").strip()
            if not type_name:
                continue
            raw_cmd = str(row.get("cmd_id") or "").strip()
            try:
                cmd_id = int(raw_cmd, 0)
            except ValueError as exc:
                raise ValueError(
                    f"{registry_csv}:{line_no}: bad cmd_id {raw_cmd!r}"
                ) from exc
            current = {
                "cmd_id": cmd_id,
                "type_name": type_name,
                "semantic_name": str(row.get("semantic_name") or ""),
                "direction": str(row.get("direction") or ""),
            }
            previous = result.get(type_name)
            if previous is not None and previous["cmd_id"] != cmd_id:
                raise ValueError(
                    f"{registry_csv}:{line_no}: conflicting CmdIds for {type_name}"
                )
            result[type_name] = current
    return result


def _load_owner_methods(
    methods_csv: Path,
    owner_type: str,
    *,
    max_method_body: int,
) -> tuple[list[dict[str, object]], int]:
    if max_method_body <= 0:
        raise ValueError("max method body must be positive")

    all_rvas: list[int] = []
    owner_rows: list[dict[str, object]] = []
    with methods_csv.open("r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        fields = set(reader.fieldnames or ())
        required = {
            "method_index",
            "type_name",
            "method_name",
            "rva",
            "parameter_types",
        }
        missing = required - fields
        if missing:
            raise ValueError(
                f"{methods_csv} missing required columns: {', '.join(sorted(missing))}"
            )

        for line_no, row in enumerate(reader, start=2):
            raw_rva = str(row.get("rva") or "").strip()
            if not raw_rva:
                continue
            try:
                rva = int(raw_rva, 0)
            except ValueError as exc:
                raise ValueError(
                    f"{methods_csv}:{line_no}: bad rva {raw_rva!r}"
                ) from exc
            if rva <= 0:
                continue
            all_rvas.append(rva)
            if str(row.get("type_name") or "") != owner_type:
                continue
            try:
                method_index = int(str(row.get("method_index") or ""), 0)
            except ValueError as exc:
                raise ValueError(
                    f"{methods_csv}:{line_no}: bad method_index {row.get('method_index')!r}"
                ) from exc
            raw_params = str(row.get("parameter_types") or "[]")
            try:
                params = json.loads(raw_params)
            except json.JSONDecodeError as exc:
                raise ValueError(
                    f"{methods_csv}:{line_no}: invalid parameter_types JSON"
                ) from exc
            if not isinstance(params, list):
                raise ValueError(
                    f"{methods_csv}:{line_no}: parameter_types must be a JSON array"
                )
            owner_rows.append(
                {
                    "method_position": len(owner_rows),
                    "method_index": method_index,
                    "method_name": str(row.get("method_name") or ""),
                    "rva": rva,
                    "parameter_types": params,
                }
            )

    starts = sorted(set(all_rvas))
    for row in owner_rows:
        start = int(row["rva"])
        i = bisect.bisect_right(starts, start)
        natural_end = starts[i] if i < len(starts) else start + max_method_body
        capped_end = min(natural_end, start + max_method_body)
        row["end_rva"] = capped_end
        row["body_truncated"] = capped_end < natural_end
    return owner_rows, len(starts)


def extract_scene_handler_slots(
    exe: Path,
    methods_csv: Path,
    registry_csv: Path,
    owner_type: str,
    slot_start: int,
    slot_end: int,
    *,
    slot_alignment: int = 8,
    max_method_body: int = 0x10000,
) -> dict[str, object]:
    """Join scene-owner methods to protocol identities and delegate slots."""

    registry = _load_registry_by_type(registry_csv)
    owner_methods, global_method_start_count = _load_owner_methods(
        methods_csv,
        owner_type,
        max_method_body=max_method_body,
    )

    eligible = 0
    scanned = 0
    rows: list[dict[str, object]] = []
    with PEImage(exe) as image:
        for method in owner_methods:
            params = method["parameter_types"]
            if not isinstance(params, list) or len(params) != 1:
                continue
            parameter_type = params[0]
            if not isinstance(parameter_type, str):
                continue
            identity = registry.get(parameter_type)
            if identity is None:
                continue
            eligible += 1

            start = int(method["rva"])
            end = int(method["end_rva"])
            size = end - start
            if size <= 0:
                continue
            blob = image.read_rva(start, size)
            if len(blob) != size:
                raise ValueError(
                    f"truncated method body read at RVA 0x{start:X}: "
                    f"expected {size} bytes, got {len(blob)}"
                )
            scanned += 1
            hits = scan_scene_handler_slot_loads(
                blob,
                base_rva=start,
                slot_start=slot_start,
                slot_end=slot_end,
                slot_alignment=slot_alignment,
            )
            if not hits:
                continue

            slots = sorted({int(hit["slot_displacement"]) for hit in hits})
            rows.append(
                {
                    "slots": [f"0x{slot:X}" for slot in slots],
                    "cmd_id": identity["cmd_id"],
                    "type_name": parameter_type,
                    "semantic_name": identity["semantic_name"],
                    "direction": identity["direction"],
                    "owner_type": owner_type,
                    "method_name": method["method_name"],
                    "method_index": method["method_index"],
                    "method_position": method["method_position"],
                    "rva": f"0x{start:X}",
                    "size": size,
                    "body_truncated": method["body_truncated"],
                    "hits": [
                        {
                            **hit,
                            "instruction_rva": f"0x{int(hit['instruction_rva']):X}",
                            "slot_displacement": f"0x{int(hit['slot_displacement']):X}",
                        }
                        for hit in hits
                    ],
                }
            )

    rows.sort(
        key=lambda row: (
            min(int(slot, 0) for slot in row["slots"]),
            int(row["method_index"]),
        )
    )
    return {
        "owner_type": owner_type,
        "slot_start": f"0x{slot_start:X}",
        "slot_end": f"0x{slot_end:X}",
        "range_semantics": "half-open",
        "slot_alignment": slot_alignment,
        "max_method_body": max_method_body,
        "decoder": "REX.W MOV rcx,[base+disp32], direct base register, no SIB",
        "global_method_start_count": global_method_start_count,
        "owner_method_count": len(owner_methods),
        "eligible_protocol_method_count": eligible,
        "scanned_protocol_method_count": scanned,
        "row_count": len(rows),
        "unique_slot_count": len(
            {slot for row in rows for slot in row["slots"]}
        ),
        "rows": rows,
        "notes": [
            "Only one-parameter owner methods whose parameter type exists in registry.csv are scanned.",
            "The decoder intentionally recognizes only the scene-handler slot-load shape verified in the 7.0/7.1 investigation.",
            "Rows are static candidate relations; semantic promotion still requires independent protocol evidence.",
        ],
    }
