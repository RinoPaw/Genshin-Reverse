from __future__ import annotations

import argparse
import csv
import json
import mmap
from pathlib import Path

from genshinre.mhy71 import BODY_SKIP, EMBEDDED_HEADER_RVA, EMBEDDED_HEADER_SIZE, _header_layout
from genshinre.param71 import PARAMETER_RECORD_SIZE, decode_parameter_record
from genshinre.pe import PEImage


def load_csv(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))


def parse_int(text: str | None, default: int = -1) -> int:
    value = (text or "").strip()
    if not value:
        return default
    try:
        return int(value, 0)
    except ValueError:
        return default


def main() -> None:
    p = argparse.ArgumentParser(description="Decode all method parameter types for one 7.1 declaring type and map protocol CmdIds.")
    p.add_argument("exe", type=Path)
    p.add_argument("metadata", type=Path)
    p.add_argument("methods_csv", type=Path)
    p.add_argument("runtime_types_csv", type=Path)
    p.add_argument("registry_csv", type=Path)
    p.add_argument("owner_type")
    p.add_argument("output_json", type=Path)
    args = p.parse_args()

    runtime_names: dict[int, set[str]] = {}
    for row in load_csv(args.runtime_types_csv):
        idx = parse_int(row.get("type_index"))
        name = (row.get("type_name") or "").strip()
        if idx >= 0 and name:
            runtime_names.setdefault(idx, set()).add(name)

    cmd_by_type_name: dict[str, list[int]] = {}
    for row in load_csv(args.registry_csv):
        name = (row.get("type_name") or "").strip()
        cmd = parse_int(row.get("cmd_id"))
        if name and cmd >= 0:
            cmd_by_type_name.setdefault(name, []).append(cmd)

    owner_methods = [row for row in load_csv(args.methods_csv) if row.get("type_name") == args.owner_type]
    owner_methods.sort(key=lambda row: parse_int(row.get("rva"), 1 << 62))

    with PEImage(args.exe) as image:
        header = image.read_rva(EMBEDDED_HEADER_RVA, EMBEDDED_HEADER_SIZE)
        layout = _header_layout(header)
    parameter_base = BODY_SKIP + int(layout["parameter_offset"])

    output_rows = []
    with args.metadata.open("rb") as f:
        metadata = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
        try:
            for row in owner_methods:
                start = parse_int(row.get("parameter_start"))
                count = parse_int(row.get("parameter_count"), 0)
                parameters = []
                for ordinal in range(max(count, 0)):
                    index = start + ordinal
                    offset = parameter_base + index * PARAMETER_RECORD_SIZE
                    if index < 0 or offset < 0 or offset + PARAMETER_RECORD_SIZE > len(metadata):
                        parameters.append({"ordinal": ordinal, "parameter_index": index, "error": "out-of-range"})
                        continue
                    decoded = decode_parameter_record(metadata[offset : offset + PARAMETER_RECORD_SIZE], index)
                    type_index = int(decoded["type_index"])
                    names = sorted(runtime_names.get(type_index, set()))
                    cmd_ids = sorted({cmd for name in names for cmd in cmd_by_type_name.get(name, [])})
                    parameters.append(
                        {
                            "ordinal": ordinal,
                            "parameter_index": index,
                            "runtime_type_index": type_index,
                            "runtime_type_names": names,
                            "protocol_cmd_ids": cmd_ids,
                            "name_token": f"0x{int(decoded['name_token']):08X}",
                        }
                    )
                output_rows.append(
                    {
                        "method_index": row.get("method_index", ""),
                        "method_rva": row.get("rva", ""),
                        "method_name": row.get("method_name", ""),
                        "parameter_start": start,
                        "parameter_count": count,
                        "parameters": parameters,
                        "protocol_cmd_ids": sorted({cmd for param in parameters for cmd in param.get("protocol_cmd_ids", [])}),
                    }
                )
        finally:
            metadata.close()

    report = {
        "sample": "7.1.0-global/windows-x64",
        "owner_type": args.owner_type,
        "method_count": len(output_rows),
        "methods_with_protocol_parameters": sum(bool(row["protocol_cmd_ids"]) for row in output_rows),
        "parameter_base_file_offset": f"0x{parameter_base:X}",
        "methods": output_rows,
        "notes": [
            "parameter records use the exact-client 7.1 decoder in genshinre.param71",
            "protocol CmdIds are joined through runtime type names to the current static registry",
            "source-order/local-RVA clusters can then be tested against known request senders and response handlers",
        ],
    }
    args.output_json.parent.mkdir(parents=True, exist_ok=True)
    args.output_json.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    print("owner", args.owner_type, "methods", len(output_rows))
    for row in output_rows:
        rva = parse_int(row.get("method_rva"))
        if row["protocol_cmd_ids"] or (0xF044000 <= rva <= 0xF052000):
            params = []
            for param in row["parameters"]:
                names = "|".join(param.get("runtime_type_names", [])) or f"type_index:{param.get('runtime_type_index')}"
                cmds = ",".join(str(x) for x in param.get("protocol_cmd_ids", []))
                params.append(f"{names}[{cmds}]")
            print(row["method_rva"], row["method_name"], " :: ", "; ".join(params))


if __name__ == "__main__":
    main()
