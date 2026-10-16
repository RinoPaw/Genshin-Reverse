"""Static direct-call mapping around 7.1 game graphics settings UI owners.

All addresses are derived from the exact pinned executable and metadata, not
portable offsets. Output is a candidate map, not a verified dropdown hook.
Capstone is optional and imported only when this research command runs.
"""
from __future__ import annotations

import argparse
import bisect
import csv
import json
from collections import defaultdict
from pathlib import Path

from genshinre.pe import PEImage
from tools.probe_graphics_aa_menu import DEFAULT_SAMPLE, verify_sample

# UI-facing classes first, postprocessing enums and consumer as context.
DEFAULT_OWNERS = (18970, 13019, 18971, 9330, 9450, 9384)


def load_method_owners(methods_csv: Path, indices: tuple[int, ...]):
    """Read metadata once and preserve shared-RVA aliases and exact method bounds."""
    selected_indices = set(indices)
    starts: dict[int, list[dict[str, str]]] = defaultdict(list)
    focus: dict[int, list[dict[str, str]]] = defaultdict(list)
    with methods_csv.open("r", encoding="utf-8-sig", newline="") as stream:
        for row in csv.DictReader(stream):
            raw_rva = row.get("rva") or ""
            if not raw_rva:
                continue
            try:
                rva = int(raw_rva, 0)
            except ValueError:
                continue
            if rva <= 0:
                continue
            compact = {
                key: row.get(key, "")
                for key in ("type_definition_index", "type_name", "method_index",
                            "method_name", "rva", "parameter_types", "return_type")
            }
            starts[rva].append(compact)
            if int(row.get("type_definition_index") or "-1") in selected_indices:
                focus[rva].append(compact)
    return sorted(starts), starts, focus


def nearest_owner(rva: int, starts: list[int],
                  by_rva: dict[int, list[dict[str, str]]], *,
                  max_owner_size: int = 0x10000):
    """A bounded *candidate* owner, not proof of a function's actual end."""
    pos = bisect.bisect_right(starts, rva) - 1
    if pos < 0:
        return None
    start = starts[pos]
    next_start = starts[pos + 1] if pos + 1 < len(starts) else start + max_owner_size
    if rva - start >= max_owner_size or rva >= next_start:
        return None
    return {"start_rva": f"0x{start:X}", "metadata": by_rva[start]}


def extract_direct_edges(
    code: bytes, *, image_base: int, start_rva: int,
    starts: list[int], by_rva: dict[int, list[dict[str, str]]],
    max_edges: int = 120,
):
    """Decode aligned Capstone instructions and resolve only direct branch targets."""
    if max_edges < 1:
        raise ValueError("max_edges must be positive")
    try:
        from capstone import Cs, CS_ARCH_X86, CS_MODE_64
        from capstone.x86 import X86_OP_IMM
    except ImportError as exc:
        raise RuntimeError("Capstone is required: python -m pip install capstone") from exc
    disassembler = Cs(CS_ARCH_X86, CS_MODE_64)
    disassembler.detail = True
    edges = []
    total = 0
    decoded_bytes = 0
    for insn in disassembler.disasm(code, image_base + start_rva):
        decoded_bytes += insn.size
        if insn.mnemonic not in ("call", "jmp"):
            continue
        immediate = next((int(op.imm) for op in insn.operands
                          if op.type == X86_OP_IMM), None)
        if immediate is None:
            continue  # virtual and delegate calls are not resolved
        total += 1
        if len(edges) >= max_edges:
            continue
        target = immediate - image_base if immediate >= image_base else immediate
        edges.append({
            "site_rva": f"0x{insn.address - image_base:X}",
            "kind": insn.mnemonic,
            "target_rva": f"0x{target:X}",
            "target_owner_candidate": nearest_owner(target, starts, by_rva),
        })
    return {
        "direct_branch_count": total,
        "truncated": total > len(edges),
        "decoded_bytes": decoded_bytes,
        "edges": edges,
    }


def analyze(
    exe: Path, *,
    sample_dir: Path = DEFAULT_SAMPLE,
    owners: tuple[int, ...] = DEFAULT_OWNERS,
    max_body: int = 0x1800,
    max_edges: int = 120,
) -> dict[str, object]:
    if not owners:
        raise ValueError("at least one owner required")
    if max_body < 32:
        raise ValueError("max_body too small")
    identity = verify_sample(exe, sample_dir / "hashes.json")
    if not identity["matches_pinned_7_1_sample"]:
        raise ValueError("exact 7.1 sample required")
    starts, by_rva, focus = load_method_owners(sample_dir / "metadata/methods.csv", owners)
    report: dict[str, object] = {
        "schema_version": 1, "topic": "graphics-aa-ui-direct-edges",
        "state": "CANDIDATE_COLLECTION",
        "identity": identity, "owners": list(owners), "max_body": max_body,
        "limitations": [
            "Candidate method end is the next distinct metadata RVA, bounded by max_body.",
            "Virtual dispatch, indirect calls, event subscriptions, and asset-defined dropdowns are not resolved.",
            "A direct call graph does not by itself identify option IDs or persistence.",
            "No executable bytes are written and no game process is attached.",
        ],
        "method_count": sum(len(rows) for rows in focus.values()),
        "unique_method_rvas": len(focus), "methods": [],
    }
    with PEImage(exe) as image:
        for index, rva in enumerate(sorted(focus)):
            pos = bisect.bisect_right(starts, rva)
            next_start = starts[pos] if pos < len(starts) else rva + max_body
            natural_size = max(0, next_start - rva)
            size = min(natural_size, max_body)
            code = image.read_rva(rva, size)
            # Non-executable or unbacked offsets get explicit empty/no-code evidence.
            edges = extract_direct_edges(
                code, image_base=image.image_base, start_rva=rva,
                starts=starts, by_rva=by_rva, max_edges=max_edges,
            ) if code else {"direct_branch_count": 0, "truncated": False,
                             "decoded_bytes": 0, "edges": []}
            report["methods"].append({
                "rva": f"0x{rva:X}",
                "metadata": focus[rva],
                "aliases_at_same_rva": len(by_rva[rva]),
                "next_metadata_rva": f"0x{next_start:X}",
                "natural_size": natural_size,
                "read_size": len(code),
                "body_truncated": natural_size > max_body,
                **edges,
            })
    return report


def main():
    parser = argparse.ArgumentParser(description="Exact-7.1 graphics UI static call edges")
    parser.add_argument("exe", type=Path)
    parser.add_argument("--sample-dir", type=Path, default=DEFAULT_SAMPLE)
    parser.add_argument("--owner", type=int, action="append",
                        help="Exact IL2CPP type index; repeatable")
    parser.add_argument("--max-body", type=lambda s: int(s, 0), default=0x1800)
    parser.add_argument("--max-edges", type=int, default=120)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = analyze(args.exe, sample_dir=args.sample_dir,
                     owners=tuple(args.owner or DEFAULT_OWNERS),
                     max_body=args.max_body, max_edges=args.max_edges)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n",
                           encoding="utf-8")
    print(f"Written {args.output}: {report['method_count']} methods "
          f"at {report['unique_method_rvas']} RVAs")


if __name__ == "__main__":
    main()
