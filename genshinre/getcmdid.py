from __future__ import annotations

import csv
import hashlib
import json
from collections import Counter
from pathlib import Path

from .metadata import load_methods
from .mhy71 import EXPECTED_EXE_SHA256
from .pe import PEImage

CANDIDATE_COLUMNS = (
    "cmd_id",
    "type_name",
    "type_definition_index",
    "method_name",
    "get_cmd_id_rva",
    "pattern",
    "status",
    "evidence",
)


def decode_constant_return(code: bytes) -> tuple[int, str] | None:
    """Recognize deliberately narrow x86/x64 constant-return stubs."""

    offset = 0
    if code.startswith(b"\xF3\x0F\x1E\xFA"):
        offset = 4
    while offset < len(code) and code[offset] == 0x90 and offset < 12:
        offset += 1

    pattern: str
    cursor: int
    if offset + 4 <= len(code) and code[offset : offset + 2] == b"\x66\xB8":
        value = int.from_bytes(code[offset + 2 : offset + 4], "little", signed=False)
        cursor = offset + 4
        pattern = "mov-ax-imm16"
    elif offset + 5 <= len(code) and code[offset] == 0xB8:
        value = int.from_bytes(code[offset + 1 : offset + 5], "little", signed=False)
        cursor = offset + 5
        pattern = "mov-eax-imm32"
    else:
        return None

    nop_start = cursor
    while cursor < len(code) and code[cursor] == 0x90 and cursor - nop_start < 8:
        cursor += 1
    if cursor < len(code) and code[cursor] == 0xC3:
        return value, f"{pattern}-ret"
    if cursor + 2 < len(code) and code[cursor] == 0xC2:
        return value, f"{pattern}-ret-imm16"
    return None


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(8 * 1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def scan_constant_cmdids(
    exe: Path,
    methods_csv: Path,
    output_csv: Path,
    summary_json: Path | None = None,
    min_cmd_id: int = 1,
    max_cmd_id: int = 65535,
) -> dict[str, object]:
    exe_sha = _sha256(exe)
    if exe_sha != EXPECTED_EXE_SHA256:
        raise ValueError(f"unexpected GenshinImpact.exe SHA-256: {exe_sha}")

    rows = load_methods(methods_csv)
    candidates: list[dict[str, str]] = []
    readable_methods = 0
    seen: set[tuple[str, str, int]] = set()

    with PEImage(exe) as image:
        for line_no, row in enumerate(rows, start=2):
            rva_text = str(row.get("rva", "")).strip()
            if not rva_text:
                continue
            try:
                rva = int(rva_text, 0)
            except ValueError as exc:
                raise ValueError(
                    f"{methods_csv}:{line_no}: invalid method RVA {rva_text!r}"
                ) from exc
            if rva <= 0:
                continue
            key = (str(row.get("type_name", "")), str(row.get("method_name", "")), rva)
            if key in seen:
                continue
            seen.add(key)
            code = image.read_rva(rva, 32)
            if not code:
                raise ValueError(
                    f"{methods_csv}:{line_no}: method RVA 0x{rva:X} is unreadable in exact sample"
                )
            readable_methods += 1
            decoded = decode_constant_return(code)
            if decoded is None:
                continue
            cmd_id, pattern = decoded
            if not min_cmd_id <= cmd_id <= max_cmd_id:
                continue
            candidates.append(
                {
                    "cmd_id": str(cmd_id),
                    "type_name": str(row.get("type_name", "")),
                    "type_definition_index": str(row.get("type_definition_index", "")),
                    "method_name": str(row.get("method_name", "")),
                    "get_cmd_id_rva": f"0x{rva:X}",
                    "pattern": pattern,
                    "status": "CANDIDATE",
                    "evidence": "constant-return method body",
                }
            )

    candidates.sort(
        key=lambda row: (int(row["cmd_id"]), row["type_name"], row["get_cmd_id_rva"])
    )
    output_csv.parent.mkdir(parents=True, exist_ok=True)
    with output_csv.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=CANDIDATE_COLUMNS)
        writer.writeheader()
        writer.writerows(candidates)

    counts = Counter(int(row["cmd_id"]) for row in candidates)
    duplicates = {str(cmd): count for cmd, count in sorted(counts.items()) if count > 1}
    anchor_rows = [
        row
        for row in candidates
        if row["cmd_id"] == "26105"
        and row["type_name"] == "HJDNCHODGOL"
        and int(row["get_cmd_id_rva"], 0) == 0x10587260
    ]
    anchor_found = bool(anchor_rows)
    summary: dict[str, object] = {
        "exe": str(exe),
        "exe_sha256": exe_sha,
        "methods_csv": str(methods_csv),
        "method_rows": len(rows),
        "readable_unique_methods": readable_methods,
        "candidate_rows": len(candidates),
        "unique_cmd_ids": len(counts),
        "duplicate_cmd_ids": duplicates,
        "cmd_id_range": [min_cmd_id, max_cmd_id],
        "anchor_26105_HJDNCHODGOL_0x10587260": anchor_found,
        "status": "candidate-scan-only",
        "notes": [
            "constant-return methods include non-protocol code; this file is not a canonical registry",
            "Genshin 7.1 GetCmdId controls include 16-bit AX immediate returns",
            "the preserved 26105/HJDNCHODGOL anchor is mandatory for the exact-sample scan",
        ],
    }
    if summary_json is None:
        summary_json = output_csv.with_suffix(".summary.json")
    summary_json.parent.mkdir(parents=True, exist_ok=True)
    summary_json.write_text(
        json.dumps(summary, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    if not anchor_found:
        raise ValueError(
            "GetCmdId scan failed mandatory 26105/HJDNCHODGOL/0x10587260 anchor"
        )
    return summary
