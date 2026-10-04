from __future__ import annotations

import argparse
import bisect
import csv
import json
from pathlib import Path

from capstone import CS_AC_READ, CS_AC_WRITE, CS_ARCH_X86, CS_MODE_64, Cs
from capstone.x86 import X86_OP_MEM

from genshinre.pe import PEImage
from genshinre.sampleidentity import require_sha256, sha256_file


def parse_int(text: str) -> int:
    return int(text, 0)


def access_name(access: int) -> str:
    read = bool(access & CS_AC_READ)
    write = bool(access & CS_AC_WRITE)
    if read and write:
        return "read-write"
    if read:
        return "read"
    if write:
        return "write"
    return "unknown"


def load_method_index(
    methods_csv: Path,
    *,
    type_name: str | None,
    type_definition_index: int | None,
) -> tuple[list[int], dict[int, list[dict[str, str]]]]:
    all_starts: list[int] = []
    selected: dict[int, list[dict[str, str]]] = {}

    with methods_csv.open("r", encoding="utf-8-sig", newline="") as f:
        for line_no, row in enumerate(csv.DictReader(f), start=2):
            text = str(row.get("rva", "")).strip()
            if not text:
                continue
            try:
                rva = int(text, 0)
            except ValueError as exc:
                raise ValueError(f"{methods_csv}:{line_no}: invalid method RVA {text!r}") from exc
            if rva <= 0:
                continue

            all_starts.append(rva)

            matches_name = type_name is None or row.get("type_name") == type_name
            matches_index = True
            if type_definition_index is not None:
                raw_index = str(row.get("type_definition_index", "")).strip()
                try:
                    row_index = int(raw_index, 0)
                except ValueError:
                    matches_index = False
                else:
                    matches_index = row_index == type_definition_index

            if matches_name and matches_index:
                selected.setdefault(rva, []).append(dict(row))

    all_starts.sort()
    return all_starts, selected


def compact_method(row: dict[str, str]) -> dict[str, object]:
    return {
        "method_index": row.get("method_index", ""),
        "type_definition_index": row.get("type_definition_index", ""),
        "type_name": row.get("type_name", ""),
        "method_name": row.get("method_name", ""),
        "parameter_count": row.get("parameter_count", ""),
        "parameter_types": row.get("parameter_types", ""),
        "return_type": row.get("return_type", ""),
        "rva": row.get("rva", ""),
    }


def scan_field_displacements(
    exe: Path,
    methods_csv: Path,
    *,
    offsets: list[int],
    type_name: str | None = None,
    type_definition_index: int | None = None,
    expected_sha256: str | None = None,
    context: int = 6,
    max_method_body: int = 0x10000,
) -> dict[str, object]:
    if not offsets:
        raise ValueError("at least one offset is required")
    if type_name is None and type_definition_index is None:
        raise ValueError("type_name or type_definition_index is required")
    if any(offset < 0 for offset in offsets):
        raise ValueError("offsets must be non-negative")
    if context < 0:
        raise ValueError("context must be non-negative")
    if max_method_body <= 0:
        raise ValueError("max_method_body must be positive")

    exe_sha256 = (
        sha256_file(exe)
        if expected_sha256 is None
        else require_sha256(exe, expected_sha256, label="executable")
    )
    target_offsets = set(offsets)
    all_starts, selected = load_method_index(
        methods_csv,
        type_name=type_name,
        type_definition_index=type_definition_index,
    )

    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    hits: list[dict[str, object]] = []

    with PEImage(exe) as image:
        image_base = image.image_base

        for start in sorted(selected):
            pos = bisect.bisect_right(all_starts, start)
            next_start = all_starts[pos] if pos < len(all_starts) else start + max_method_body
            end = min(next_start, start + max_method_body)
            if end <= start:
                continue

            try:
                body = image.read_rva(start, end - start)
            except Exception:
                continue

            instructions = list(md.disasm(body, image_base + start))
            for index, insn in enumerate(instructions):
                matching_operands = []
                for operand_index, operand in enumerate(insn.operands):
                    if operand.type != X86_OP_MEM:
                        continue
                    displacement = int(operand.mem.disp)
                    if displacement not in target_offsets:
                        continue
                    matching_operands.append(
                        {
                            "operand_index": operand_index,
                            "displacement": f"0x{displacement:X}",
                            "base_register": (
                                insn.reg_name(operand.mem.base) if operand.mem.base else ""
                            ),
                            "index_register": (
                                insn.reg_name(operand.mem.index) if operand.mem.index else ""
                            ),
                            "scale": operand.mem.scale,
                            "access": access_name(operand.access),
                        }
                    )

                if not matching_operands:
                    continue

                lo = max(0, index - context)
                hi = min(len(instructions), index + context + 1)
                hits.append(
                    {
                        "method_rva": f"0x{start:X}",
                        "method": [compact_method(row) for row in selected[start]],
                        "instruction_rva": f"0x{insn.address - image_base:X}",
                        "mnemonic": insn.mnemonic,
                        "op_str": insn.op_str,
                        "bytes": bytes(insn.bytes).hex(),
                        "operands": matching_operands,
                        "context": [
                            {
                                "rva": f"0x{x.address - image_base:X}",
                                "mnemonic": x.mnemonic,
                                "op_str": x.op_str,
                            }
                            for x in instructions[lo:hi]
                        ],
                    }
                )

    return {
        "exe": str(exe),
        "exe_sha256": exe_sha256,
        "methods_csv": str(methods_csv),
        "selector": {
            "type_name": type_name,
            "type_definition_index": type_definition_index,
        },
        "offsets": [f"0x{offset:X}" for offset in offsets],
        "selected_method_start_count": len(selected),
        "hit_count": len(hits),
        "hits": hits,
        "notes": [
            "A displacement match is only a candidate object-field access.",
            "The base register must be traced to the relevant object instance before assigning field semantics.",
            "Read/write classification comes from Capstone operand metadata and should be verified from surrounding instructions when promotion depends on it.",
            "Offset equality across unrelated types or client versions is not semantic evidence.",
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Scan methods of one IL2CPP type for x86-64 memory operands using selected displacements."
    )
    parser.add_argument("exe", type=Path)
    parser.add_argument("methods_csv", type=Path)
    parser.add_argument("output_json", type=Path)
    parser.add_argument("--type-name")
    parser.add_argument("--type-definition-index", type=parse_int)
    parser.add_argument(
        "--offset",
        action="append",
        type=parse_int,
        default=[],
        help="Object displacement to scan for, repeatable (for example 0x108).",
    )
    parser.add_argument("--expected-sha256")
    parser.add_argument("--context", type=int, default=6)
    parser.add_argument("--max-method-body", type=parse_int, default=0x10000)
    args = parser.parse_args()

    result = scan_field_displacements(
        args.exe,
        args.methods_csv,
        offsets=args.offset,
        type_name=args.type_name,
        type_definition_index=args.type_definition_index,
        expected_sha256=args.expected_sha256,
        context=args.context,
        max_method_body=args.max_method_body,
    )

    args.output_json.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(result, indent=2, ensure_ascii=False) + "\n"
    args.output_json.write_text(text, encoding="utf-8")
    print(
        f"selected {result['selected_method_start_count']} method starts; "
        f"found {result['hit_count']} displacement hits"
    )


if __name__ == "__main__":
    main()
