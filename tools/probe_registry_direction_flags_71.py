from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
from pathlib import Path

ROW_COUNT = 4896
EXPECTED_EXE_SHA256 = "08a3086d5f3fe695f01dab61efa42e442006b18e5e475b2520df356f6a073b7d"


def load_csv(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(8 * 1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def main() -> None:
    p = argparse.ArgumentParser(
        description="Recover the 7.1 registry direction byte array from published registry indices."
    )
    p.add_argument("exe", type=Path)
    p.add_argument("registry_csv", type=Path)
    p.add_argument("known_opcodes_csv", type=Path)
    p.add_argument("candidate_csv", type=Path)
    p.add_argument("output_json", type=Path)
    p.add_argument("--flags-csv", type=Path)
    p.add_argument("--allow-unknown-sample", action="store_true")
    args = p.parse_args()

    digest = sha256(args.exe)
    if not args.allow_unknown_sample and digest != EXPECTED_EXE_SHA256:
        raise SystemExit(f"unexpected executable SHA-256: {digest}")

    registry = load_csv(args.registry_csv)
    if len(registry) != ROW_COUNT:
        raise SystemExit(f"expected {ROW_COUNT} registry rows, got {len(registry)}")
    indices = sorted(int(r["index"], 0) for r in registry)
    if indices != list(range(ROW_COUNT)):
        raise SystemExit("registry indices are not contiguous 0..4895")
    by_cmd = {int(r["cmd_id"], 0): r for r in registry}

    controls: list[dict[str, object]] = []
    for row in load_csv(args.known_opcodes_csv):
        direction = str(row.get("direction", "")).strip().upper()
        if direction not in {"C2S", "S2C"}:
            continue
        cmd = int(row["cmd_id"], 0)
        reg = by_cmd.get(cmd)
        if reg is None:
            continue
        controls.append(
            {
                "cmd_id": cmd,
                "semantic_name": row.get("semantic_name", ""),
                "index": int(reg["index"], 0),
                "expected_flag": 1 if direction == "C2S" else 0,
                "direction": direction,
            }
        )

    if len(controls) < 4:
        raise SystemExit(f"need at least four direction controls, got {len(controls)}")
    one_controls = [c for c in controls if int(c["expected_flag"]) == 1]
    zero_controls = [c for c in controls if int(c["expected_flag"]) == 0]
    if not one_controls or not zero_controls:
        raise SystemExit("direction controls must contain both C2S and S2C examples")

    data = args.exe.read_bytes()
    anchor_index = int(one_controls[0]["index"])
    candidates: dict[int, bytes] = {}
    binary_runs = 0

    for match in re.finditer(rb"[\x00\x01]{4896,}", data):
        binary_runs += 1
        start, end = match.span()
        run = data[start:end]
        pos = run.find(b"\x01")
        while pos >= 0:
            base = start + pos - anchor_index
            if base >= start and base + ROW_COUNT <= end:
                window = data[base : base + ROW_COUNT]
                if all(window[int(c["index"])] == int(c["expected_flag"]) for c in controls):
                    candidates.setdefault(base, window)
            pos = run.find(b"\x01", pos + 1)

    candidate_meta = []
    for base, flags in sorted(candidates.items()):
        candidate_meta.append(
            {
                "file_offset": f"0x{base:X}",
                "zeros": flags.count(0),
                "ones": flags.count(1),
                "controls": [
                    {**c, "observed_flag": flags[int(c["index"])]} for c in controls
                ],
            }
        )

    result: dict[str, object] = {
        "exe_sha256": digest,
        "row_count": ROW_COUNT,
        "binary_run_count": binary_runs,
        "control_count": len(controls),
        "controls": controls,
        "candidate_count": len(candidates),
        "flag_array_candidates": candidate_meta,
        "status": "unique" if len(candidates) == 1 else "unresolved",
        "method": (
            "scan exact 4,896-byte binary windows, align them by published registry indices, "
            "and require all independent current-version Req/Rsp direction controls"
        ),
        "notes": [
            "the probe does not depend on recovering the adjacent CmdId array",
            "flag semantics are inherited only from independently confirmed C2S/S2C controls",
            "zero or multiple matches remain unresolved and must not be promoted to protocol evidence",
        ],
    }

    if len(candidates) == 1:
        base, flags = next(iter(candidates.items()))
        candidate_ids = {int(r["cmd_id"], 0) for r in load_csv(args.candidate_csv)}
        response_rows = []
        for cmd in sorted(candidate_ids):
            reg = by_cmd[cmd]
            index = int(reg["index"], 0)
            flag = flags[index]
            response_rows.append(
                {
                    "cmd_id": cmd,
                    "index": index,
                    "type_name": reg.get("type_name", ""),
                    "registry_flag": flag,
                    "direction": "C2S" if flag == 1 else "S2C",
                    "type_definition_index": reg.get("type_definition_index", ""),
                    "type_slot_rva": reg.get("type_slot_rva", ""),
                    "get_cmd_id_rva": reg.get("get_cmd_id_rva", ""),
                    "xref_count": reg.get("xref_count", ""),
                    "xref_method_count": reg.get("xref_method_count", ""),
                }
            )
        result["flag_array_file_offset"] = f"0x{base:X}"
        result["response_candidate_count"] = len(response_rows)
        result["response_s2c_count"] = sum(r["direction"] == "S2C" for r in response_rows)
        result["response_c2s_count"] = sum(r["direction"] == "C2S" for r in response_rows)
        result["response_candidates"] = response_rows

        if args.flags_csv is not None:
            args.flags_csv.parent.mkdir(parents=True, exist_ok=True)
            with args.flags_csv.open("w", encoding="utf-8", newline="") as f:
                cols = ["index", "cmd_id", "type_name", "registry_flag", "direction"]
                w = csv.DictWriter(f, fieldnames=cols)
                w.writeheader()
                for reg in sorted(registry, key=lambda r: int(r["index"], 0)):
                    index = int(reg["index"], 0)
                    flag = flags[index]
                    w.writerow(
                        {
                            "index": index,
                            "cmd_id": reg["cmd_id"],
                            "type_name": reg.get("type_name", ""),
                            "registry_flag": flag,
                            "direction": "C2S" if flag == 1 else "S2C",
                        }
                    )

    args.output_json.parent.mkdir(parents=True, exist_ok=True)
    args.output_json.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2, ensure_ascii=False))

    if len(candidates) != 1:
        raise SystemExit(f"expected exactly one direction flag array, got {len(candidates)}")


if __name__ == "__main__":
    main()
