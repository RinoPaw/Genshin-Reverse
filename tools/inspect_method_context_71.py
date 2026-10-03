from __future__ import annotations

import argparse
import bisect
import csv
import json
from pathlib import Path

from capstone import Cs, CS_ARCH_X86, CS_MODE_64

from genshinre.nativeprofile import PROFILE_71
from genshinre.pe import PEImage
from genshinre.sampleidentity import require_profile_exe


def parse_int(text: str | None) -> int | None:
    value = (text or "").strip()
    if not value:
        return None
    try:
        return int(value, 0)
    except ValueError:
        return None


def load_methods(path: Path) -> list[tuple[int, dict[str, str]]]:
    rows: list[tuple[int, dict[str, str]]] = []
    with path.open("r", encoding="utf-8-sig", newline="") as f:
        for line_no, row in enumerate(csv.DictReader(f), start=2):
            text = (row.get("rva") or "").strip()
            if not text:
                continue
            try:
                rva = int(text, 0)
            except ValueError as exc:
                raise ValueError(f"{path}:{line_no}: invalid method RVA {text!r}") from exc
            if rva > 0:
                rows.append((rva, row))
    rows.sort(key=lambda item: item[0])
    return rows


def main() -> None:
    p = argparse.ArgumentParser(description="Inspect exact native method bodies and metadata neighbors.")
    p.add_argument("exe", type=Path)
    p.add_argument("methods_csv", type=Path)
    p.add_argument("output_json", type=Path)
    p.add_argument("--focus", action="append", default=[], help="LABEL:RVA, repeatable")
    p.add_argument("--neighbor-count", type=int, default=8)
    p.add_argument("--max-body", type=lambda x: int(x, 0), default=0x1800)
    args = p.parse_args()

    exe_sha256 = require_profile_exe(args.exe, PROFILE_71)
    methods = load_methods(args.methods_csv)
    starts = [rva for rva, _ in methods]
    md = Cs(CS_ARCH_X86, CS_MODE_64)

    def method_index_for(rva: int) -> int | None:
        i = bisect.bisect_right(starts, rva) - 1
        if i < 0:
            return None
        end = starts[i + 1] if i + 1 < len(starts) else starts[i] + args.max_body
        return i if starts[i] <= rva < end else None

    def method_desc(i: int) -> dict[str, object]:
        rva, row = methods[i]
        end = starts[i + 1] if i + 1 < len(starts) else rva + args.max_body
        return {
            "rva": f"0x{rva:X}",
            "end_rva": f"0x{end:X}",
            "size_to_next_method": end - rva,
            "type_name": row.get("type_name", ""),
            "method_name": row.get("method_name", ""),
            "method_index": row.get("method_index", ""),
            "type_definition_index": row.get("type_definition_index", ""),
            "parameter_start": row.get("parameter_start", ""),
            "parameter_count": row.get("parameter_count", ""),
            "return_type": row.get("return_type", ""),
        }

    report: dict[str, object] = {
        "profile": PROFILE_71.identity,
        "exe_sha256": exe_sha256,
        "focus": {},
        "notes": [],
    }
    with PEImage(args.exe) as image:
        for spec in args.focus:
            if ":" not in spec:
                raise SystemExit(f"bad --focus {spec!r}; expected LABEL:RVA")
            label, rva_text = spec.split(":", 1)
            rva = int(rva_text, 0)
            idx = method_index_for(rva)
            if idx is None:
                report["focus"][label] = {"requested_rva": f"0x{rva:X}", "owner": None}
                continue
            owner = method_desc(idx)
            start = starts[idx]
            end = starts[idx + 1] if idx + 1 < len(starts) else start + args.max_body
            size = min(max(end - start, 1), args.max_body)
            blob = image.read_rva(start, size)
            if len(blob) != size:
                raise ValueError(
                    f"method body read truncated at 0x{start:X}: expected {size}, got {len(blob)}"
                )
            insns = []
            for insn in md.disasm(blob, image.image_base + start):
                irva = insn.address - image.image_base
                call_target = None
                call_owner = None
                if insn.mnemonic == "call" and insn.op_str.startswith("0x"):
                    try:
                        absolute = int(insn.op_str, 16)
                        target = absolute - image.image_base if absolute >= image.image_base else absolute
                        call_target = f"0x{target:X}"
                        target_idx = method_index_for(target)
                        call_owner = None if target_idx is None else method_desc(target_idx)
                    except ValueError:
                        pass
                insns.append(
                    {
                        "rva": f"0x{irva:X}",
                        "mnemonic": insn.mnemonic,
                        "op_str": insn.op_str,
                        "bytes": insn.bytes.hex(),
                        "direct_call_target_rva": call_target,
                        "direct_call_target_owner": call_owner,
                    }
                )

            owner_type = str(owner["type_name"])
            neighbors = []
            lo = max(0, idx - args.neighbor_count)
            hi = min(len(methods), idx + args.neighbor_count + 1)
            for j in range(lo, hi):
                item = method_desc(j)
                item["same_declaring_type"] = item["type_name"] == owner_type
                item["relative_index"] = j - idx
                neighbors.append(item)

            report["focus"][label] = {
                "requested_rva": f"0x{rva:X}",
                "owner": owner,
                "neighbors": neighbors,
                "disasm": insns,
            }

    report["notes"] = [
        "method bodies are bounded by the next metadata method RVA and capped by --max-body",
        "direct call targets are annotated with the nearest decoded metadata method owner when available",
        "neighbor methods are useful for testing whether candidate handlers share a local RPC/lifecycle cluster",
    ]
    args.output_json.parent.mkdir(parents=True, exist_ok=True)
    args.output_json.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    for label, item in report["focus"].items():
        print("===", label, item.get("requested_rva"), "===")
        print("owner", item.get("owner"))
        for neighbor in item.get("neighbors", []):
            if neighbor["same_declaring_type"]:
                print(
                    " neighbor", neighbor["relative_index"], neighbor["rva"],
                    neighbor["type_name"], neighbor["method_name"],
                    "pc=", neighbor["parameter_count"],
                )
        for insn in item.get("disasm", []):
            print(insn["rva"], insn["mnemonic"], insn["op_str"])


if __name__ == "__main__":
    main()
