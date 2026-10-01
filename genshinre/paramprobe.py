from __future__ import annotations

import argparse
import csv
import hashlib
import json
import mmap
from pathlib import Path

from .mhy71 import (
    BODY_SKIP,
    EMBEDDED_HEADER_RVA,
    EMBEDDED_HEADER_SIZE,
    EXPECTED_EXE_SHA256,
    EXPECTED_METADATA_SHA256,
    _header_layout,
)
from .pe import PEImage


DEFAULT_ANCHORS = (
    {
        "name": "DoSetPlayerBornDataNotify handler",
        "method_index": 322_028,
        "method_rva": None,
        "expected_type_name": "ONKOPMILDMF",
        "semantic_name": "DoSetPlayerBornDataNotify",
        "cmd_id": 22_899,
    },
    {
        "name": "PlayerNicknameNotify handler",
        "method_index": None,
        "method_rva": 0x0C23BA20,
        "expected_type_name": "PGAMFBPNNIC",
        "semantic_name": "PlayerNicknameNotify",
        "cmd_id": 3_064,
    },
    {
        "name": "SetPlayerNameRsp handler",
        "method_index": None,
        "method_rva": 0x0C2513A0,
        "expected_type_name": "OBOADLPIEPL",
        "semantic_name": "SetPlayerNameRsp",
        "cmd_id": 20_824,
    },
)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(8 * 1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _parse_int(value: str | int | None) -> int | None:
    if value is None:
        return None
    if isinstance(value, int):
        return value
    text = value.strip()
    if not text:
        return None
    return int(text, 0)


def _load_methods(path: Path) -> tuple[dict[int, dict[str, str]], dict[int, dict[str, str]]]:
    by_index: dict[int, dict[str, str]] = {}
    by_rva: dict[int, dict[str, str]] = {}
    with path.open("r", encoding="utf-8", newline="") as f:
        for row in csv.DictReader(f):
            index = _parse_int(row.get("method_index"))
            rva = _parse_int(row.get("rva"))
            if index is not None:
                by_index[index] = row
            if rva is not None:
                by_rva[rva] = row
    return by_index, by_rva


def _load_runtime_types(path: Path) -> dict[str, list[int]]:
    result: dict[str, list[int]] = {}
    with path.open("r", encoding="utf-8", newline="") as f:
        for row in csv.DictReader(f):
            name = str(row.get("type_name", "")).strip()
            index = _parse_int(row.get("type_index"))
            if name and index is not None:
                result.setdefault(name, []).append(index)
    return result


def _u32_words(blob: bytes) -> list[str]:
    return [
        f"0x{int.from_bytes(blob[offset:offset + 4], 'little'):08X}"
        for offset in range(0, len(blob) - 3, 4)
    ]


def _comparisons(blob: bytes, expected_indices: list[int]) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for word_offset in range(0, len(blob) - 3, 4):
        raw = int.from_bytes(blob[word_offset:word_offset + 4], "little")
        for expected in expected_indices:
            rows.append(
                {
                    "word_offset": word_offset,
                    "raw_u32": f"0x{raw:08X}",
                    "expected_type_index": expected,
                    "raw_xor_expected": f"0x{(raw ^ expected) & 0xFFFFFFFF:08X}",
                    "raw_minus_expected": f"0x{(raw - expected) & 0xFFFFFFFF:08X}",
                    "expected_minus_raw": f"0x{(expected - raw) & 0xFFFFFFFF:08X}",
                }
            )
    return rows


def probe_parameter_records_71(
    exe: Path,
    metadata_path: Path,
    methods_csv: Path,
    runtime_types_csv: Path,
    output_json: Path,
    allow_unknown_sample: bool = False,
) -> dict[str, object]:
    exe_sha = _sha256(exe)
    metadata_sha = _sha256(metadata_path)
    if not allow_unknown_sample:
        if exe_sha != EXPECTED_EXE_SHA256:
            raise ValueError(f"unexpected GenshinImpact.exe SHA-256: {exe_sha}")
        if metadata_sha != EXPECTED_METADATA_SHA256:
            raise ValueError(f"unexpected global-metadata.dat SHA-256: {metadata_sha}")

    methods_by_index, methods_by_rva = _load_methods(methods_csv)
    runtime_types = _load_runtime_types(runtime_types_csv)
    results: list[dict[str, object]] = []

    with PEImage(exe) as image, metadata_path.open("rb") as metadata_file:
        metadata = mmap.mmap(metadata_file.fileno(), 0, access=mmap.ACCESS_READ)
        try:
            header = image.read_rva(EMBEDDED_HEADER_RVA, EMBEDDED_HEADER_SIZE)
            layout = _header_layout(header)
            parameter_base = BODY_SKIP + int(layout["parameter_offset"])

            for anchor in DEFAULT_ANCHORS:
                row = None
                if anchor["method_index"] is not None:
                    row = methods_by_index.get(int(anchor["method_index"]))
                if row is None and anchor["method_rva"] is not None:
                    row = methods_by_rva.get(int(anchor["method_rva"]))

                expected_name = str(anchor["expected_type_name"])
                expected_indices = runtime_types.get(expected_name, [])
                item: dict[str, object] = {
                    **anchor,
                    "method_found": row is not None,
                    "expected_runtime_type_indices": expected_indices,
                    "records": {},
                }
                if row is None:
                    item["error"] = "method not found in methods.csv"
                    results.append(item)
                    continue

                method_index = _parse_int(row.get("method_index"))
                method_rva = _parse_int(row.get("rva"))
                parameter_start = _parse_int(row.get("parameter_start"))
                parameter_count = _parse_int(row.get("parameter_count"))
                item.update(
                    {
                        "resolved_method_index": method_index,
                        "resolved_method_rva": None if method_rva is None else f"0x{method_rva:X}",
                        "owner_type": row.get("type_name", ""),
                        "method_name": row.get("method_name", ""),
                        "parameter_start": parameter_start,
                        "parameter_count": parameter_count,
                    }
                )

                if parameter_start is None or parameter_count is None or parameter_count <= 0:
                    item["error"] = "method has no decoded parameter range"
                    results.append(item)
                    continue

                # Modern IL2CPP parameter definitions are normally 12 bytes
                # (nameIndex, token, typeIndex). 7.1 MHY transforms the record,
                # so preserve neighboring 8/12/16-byte interpretations until
                # the exact build-specific formula is recovered.
                for stride in (8, 12, 16):
                    stride_rows: list[dict[str, object]] = []
                    for ordinal in range(parameter_count):
                        parameter_index = parameter_start + ordinal
                        offset = parameter_base + parameter_index * stride
                        if offset < 0 or offset + stride > len(metadata):
                            stride_rows.append(
                                {
                                    "ordinal": ordinal,
                                    "parameter_index": parameter_index,
                                    "file_offset": f"0x{offset:X}",
                                    "error": "record outside metadata",
                                }
                            )
                            continue
                        blob = bytes(metadata[offset:offset + stride])
                        stride_rows.append(
                            {
                                "ordinal": ordinal,
                                "parameter_index": parameter_index,
                                "file_offset": f"0x{offset:X}",
                                "raw_hex": blob.hex(),
                                "u32_words": _u32_words(blob),
                                "expected_type_comparisons": _comparisons(blob, expected_indices),
                            }
                        )
                    item["records"][str(stride)] = stride_rows
                results.append(item)
        finally:
            metadata.close()

    result: dict[str, object] = {
        "sample": "7.1.0-global/windows-x64",
        "exe_sha256": exe_sha,
        "metadata_sha256": metadata_sha,
        "parameter_record_status": "probe-only; exact MHY transform unresolved",
        "anchors": results,
        "notes": [
            "The 12-byte view follows the modern Il2CppParameterDefinition layout: nameIndex, token, typeIndex.",
            "8- and 16-byte views are emitted as controls; do not treat any stride as confirmed solely from this probe.",
            "expected_runtime_type_indices come from the decoded IL2CPP runtime type array, not from typeDefinition indices.",
            "Use multiple anchors to infer any parameter-index-dependent transform before changing the native decoder.",
        ],
    }
    output_json.parent.mkdir(parents=True, exist_ok=True)
    output_json.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return result


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="python -m genshinre.paramprobe",
        description="Probe raw 7.1 MHY parameter records using confirmed packet-handler anchors.",
    )
    parser.add_argument("exe", type=Path)
    parser.add_argument("metadata", type=Path)
    parser.add_argument("methods_csv", type=Path)
    parser.add_argument("runtime_types_csv", type=Path)
    parser.add_argument("output_json", type=Path)
    parser.add_argument("--allow-unknown-sample", action="store_true")
    args = parser.parse_args()

    result = probe_parameter_records_71(
        args.exe,
        args.metadata,
        args.methods_csv,
        args.runtime_types_csv,
        args.output_json,
        allow_unknown_sample=args.allow_unknown_sample,
    )
    print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
