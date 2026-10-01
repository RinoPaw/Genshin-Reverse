from __future__ import annotations

import argparse
import csv
import hashlib
import json
import mmap
import struct
from pathlib import Path

from genshinre.mhy71 import (
    BODY_SKIP,
    EMBEDDED_HEADER_RVA,
    EMBEDDED_HEADER_SIZE,
    EXPECTED_EXE_SHA256,
    EXPECTED_METADATA_SHA256,
    MASK32,
    MASK64,
    _header_layout,
)
from genshinre.pe import PEImage


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(8 * 1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def parameter_key(index: int) -> int:
    # Recovered from the native 7.1 parameter decoder around RVA 0x52881C.
    value = (index * 0xA291 + 0x48B5FFB1) & MASK64
    value ^= 0x19E1D47A
    product = (value * 0x56E732D7) & MASK64
    return ((product >> 0x15) + 0x7B48E804) & MASK32


def decode_parameter_type_index(record: bytes, index: int) -> int:
    if len(record) < 8:
        raise ValueError("truncated 7.1 parameter record")
    encrypted_type = struct.unpack_from("<I", record, 0)[0]
    return (encrypted_type ^ parameter_key(index) ^ 0x31BF59F3) & MASK32


def load_runtime_types(path: Path) -> dict[int, str]:
    result: dict[int, str] = {}
    with path.open("r", encoding="utf-8-sig", newline="") as f:
        for row in csv.DictReader(f):
            raw_index = (row.get("type_index") or "").strip()
            if not raw_index:
                continue
            try:
                index = int(raw_index, 0)
            except ValueError:
                continue
            name = (row.get("type_name") or "").strip()
            if name:
                result[index] = name
    return result


def parse_int(value: str | None) -> int | None:
    text = (value or "").strip()
    if not text:
        return None
    try:
        return int(text, 0)
    except ValueError:
        return None


def main() -> None:
    p = argparse.ArgumentParser(description="Decode protected 7.1 MHY parameter type records.")
    p.add_argument("exe", type=Path)
    p.add_argument("metadata", type=Path)
    p.add_argument("methods_csv", type=Path)
    p.add_argument("runtime_types_csv", type=Path)
    p.add_argument("output_csv", type=Path)
    p.add_argument("summary_json", type=Path)
    p.add_argument("--allow-unknown-sample", action="store_true")
    args = p.parse_args()

    exe_sha = sha256(args.exe)
    metadata_sha = sha256(args.metadata)
    if not args.allow_unknown_sample:
        if exe_sha != EXPECTED_EXE_SHA256:
            raise SystemExit(f"unexpected exe sha256: {exe_sha}")
        if metadata_sha != EXPECTED_METADATA_SHA256:
            raise SystemExit(f"unexpected metadata sha256: {metadata_sha}")

    runtime_types = load_runtime_types(args.runtime_types_csv)
    with args.methods_csv.open("r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        fieldnames = list(reader.fieldnames or [])
        methods = list(reader)

    if "parameter_type_indices" not in fieldnames:
        fieldnames.append("parameter_type_indices")

    with PEImage(args.exe) as image:
        header = image.read_rva(EMBEDDED_HEADER_RVA, EMBEDDED_HEADER_SIZE)
        layout = _header_layout(header)
    parameter_base = BODY_SKIP + int(layout["parameter_offset"])

    decoded_parameter_count = 0
    unresolved_type_count = 0
    controls = {
        322028: "ONKOPMILDMF",  # DoSetPlayerBornDataNotify
        322116: "PGAMFBPNNIC",  # PlayerNicknameNotify
        322268: "OBOADLPIEPL",  # SetPlayerNameRsp
    }
    control_results: list[dict[str, object]] = []

    with args.metadata.open("rb") as mf:
        metadata = mmap.mmap(mf.fileno(), 0, access=mmap.ACCESS_READ)
        try:
            for row in methods:
                start = parse_int(row.get("parameter_start"))
                count = parse_int(row.get("parameter_count")) or 0
                type_indices: list[int] = []
                type_names: list[str] = []
                if start is not None and start >= 0 and count > 0:
                    for ordinal in range(count):
                        index = start + ordinal
                        offset = parameter_base + index * 8
                        if offset < 0 or offset + 8 > len(metadata):
                            raise SystemExit(
                                f"parameter record outside metadata: method={row.get('method_index')} index={index} offset=0x{offset:X}"
                            )
                        type_index = decode_parameter_type_index(metadata[offset : offset + 8], index)
                        type_indices.append(type_index)
                        name = runtime_types.get(type_index, f"type_index:{type_index}")
                        if name.startswith("type_index:"):
                            unresolved_type_count += 1
                        type_names.append(name)
                        decoded_parameter_count += 1
                row["parameter_type_indices"] = json.dumps(type_indices, separators=(",", ":"))
                row["parameter_types"] = json.dumps(type_names, ensure_ascii=False, separators=(",", ":"))

                method_index = parse_int(row.get("method_index"))
                if method_index in controls:
                    expected = controls[method_index]
                    passed = bool(type_names) and type_names[0] == expected
                    control_results.append(
                        {
                            "method_index": method_index,
                            "expected_type": expected,
                            "decoded_type_indices": type_indices,
                            "decoded_types": type_names,
                            "passed": passed,
                        }
                    )
        finally:
            metadata.close()

    if len(control_results) != len(controls) or not all(x["passed"] for x in control_results):
        raise SystemExit("parameter decoder control validation failed: " + json.dumps(control_results))

    args.output_csv.parent.mkdir(parents=True, exist_ok=True)
    with args.output_csv.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(methods)

    summary = {
        "sample": "7.1.0-global/windows-x64",
        "exe_sha256": exe_sha,
        "metadata_sha256": metadata_sha,
        "parameter_record_stride": 8,
        "parameter_base_file_offset": f"0x{parameter_base:X}",
        "decoded_parameter_count": decoded_parameter_count,
        "unresolved_runtime_type_count": unresolved_type_count,
        "controls": control_results,
        "formula": {
            "key": "((((index * 0xA291 + 0x48B5FFB1) ^ 0x19E1D47A) * 0x56E732D7 & MASK64) >> 0x15) + 0x7B48E804",
            "type_index": "record.word0 ^ key ^ 0x31BF59F3",
        },
        "evidence": "native decoder basic block around 0x52881C..0x52886E plus three independent confirmed handler controls",
    }
    args.summary_json.write_text(json.dumps(summary, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
