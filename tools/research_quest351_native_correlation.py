from __future__ import annotations

import bisect
import csv
import json
from collections import defaultdict
from pathlib import Path

from capstone import CS_ARCH_X86, CS_MODE_64, Cs
from capstone.x86 import X86_OP_IMM

from genshinre.pe import PEImage

QUEST_CORE_TYPE = 61791
QUEST_ID = 351


def load_methods(path: Path):
    rows: list[dict[str, object]] = []
    by_rva: dict[int, list[dict[str, str]]] = defaultdict(list)
    quest_targets: set[int] = set()
    with path.open('r', encoding='utf-8-sig', newline='') as f:
        for row in csv.DictReader(f):
            try:
                rva = int(row.get('rva') or '0', 0)
            except ValueError:
                continue
            if rva <= 0:
                continue
            by_rva[rva].append(row)
            if int(row.get('type_definition_index') or -1) == QUEST_CORE_TYPE:
                quest_targets.add(rva)
    starts = sorted(by_rva)
    return starts, by_rva, quest_targets


def compact(row: dict[str, str]) -> dict[str, object]:
    return {
        'method_index': int(row['method_index']),
        'type_definition_index': int(row.get('type_definition_index') or -1),
        'type_name': row.get('type_name', ''),
        'method_name': row.get('method_name', ''),
        'rva': row.get('rva', ''),
        'parameter_types': json.loads(row.get('parameter_types') or '[]'),
    }


def owner(starts, by_rva, rva: int):
    i = bisect.bisect_right(starts, rva) - 1
    if i < 0:
        return None
    start = starts[i]
    end = starts[i + 1] if i + 1 < len(starts) else start + 0x10000
    if not (start <= rva < end):
        return None
    return start, end, by_rva[start]


def direct_target(image_base: int, insn):
    if insn.mnemonic != 'call':
        return None
    for op in insn.operands:
        if op.type == X86_OP_IMM:
            v = int(op.imm)
            return v - image_base if v >= image_base else v
    return None


def main() -> None:
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument('exe', type=Path)
    p.add_argument('methods_csv', type=Path)
    p.add_argument('output_json', type=Path)
    args = p.parse_args()

    starts, by_rva, quest_targets = load_methods(args.methods_csv)
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    candidates: list[dict[str, object]] = []

    with PEImage(args.exe) as image:
        base = image.image_base
        for i, start in enumerate(starts[:-1]):
            end = starts[i + 1]
            size = end - start
            if size <= 0 or size > 0x8000:
                continue
            try:
                blob = image.read_rva(start, size)
            except Exception:
                continue
            # Cheap prefilter: 351 encoded as imm32 or imm16/low bytes must occur.
            if b'\x5f\x01' not in blob:
                continue
            insns = list(md.disasm(blob, base + start))
            literal_sites: list[int] = []
            quest_calls: list[tuple[int, int]] = []
            for insn in insns:
                irva = insn.address - base
                for op in insn.operands:
                    if op.type == X86_OP_IMM and int(op.imm) == QUEST_ID:
                        literal_sites.append(irva)
                        break
                target = direct_target(base, insn)
                if target in quest_targets:
                    quest_calls.append((irva, target))
            if not literal_sites or not quest_calls:
                continue
            # Keep only functions where a quest-core call is reasonably close to 351.
            close = [(ls, cs, ct) for ls in literal_sites for cs, ct in quest_calls if abs(cs - ls) <= 0x180]
            if not close:
                continue
            rows = by_rva[start]
            item = {
                'caller_rva': f'0x{start:X}',
                'caller_metadata': [compact(r) for r in rows],
                'literal_351_sites': [f'0x{x:X}' for x in literal_sites],
                'quest_core_calls': [
                    {
                        'site_rva': f'0x{site:X}',
                        'target_rva': f'0x{target:X}',
                        'target_metadata': [compact(r) for r in by_rva.get(target, [])],
                    }
                    for site, target in quest_calls
                ],
                'close_pairs': [
                    {'literal_rva': f'0x{ls:X}', 'call_site_rva': f'0x{cs:X}', 'target_rva': f'0x{ct:X}'}
                    for ls, cs, ct in close
                ],
            }
            # Context around every relevant literal/call site.
            sites = sorted(set(literal_sites + [x for x, _ in quest_calls]))
            contexts = []
            for site in sites:
                ix = next((j for j, insn in enumerate(insns) if insn.address - base == site), None)
                if ix is None:
                    continue
                lo, hi = max(0, ix - 12), min(len(insns), ix + 13)
                contexts.append({
                    'site_rva': f'0x{site:X}',
                    'instructions': [
                        {'rva': f'0x{insn.address-base:X}', 'mnemonic': insn.mnemonic, 'op_str': insn.op_str}
                        for insn in insns[lo:hi]
                    ],
                })
            item['contexts'] = contexts
            candidates.append(item)

    payload = {
        'quest_core_type_definition_index': QUEST_CORE_TYPE,
        'quest_id': QUEST_ID,
        'candidate_count': len(candidates),
        'candidates': candidates,
    }
    args.output_json.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
    print(f'candidates={len(candidates)}')
    for c in candidates:
        print('\nCALLER', c['caller_rva'], c['caller_metadata'])
        print('351', c['literal_351_sites'])
        for q in c['quest_core_calls']:
            print(' quest call', q['site_rva'], '->', q['target_rva'], q['target_metadata'])
        for ctx in c['contexts']:
            print(' context', ctx['site_rva'])
            for insn in ctx['instructions']:
                print('  ', insn['rva'], insn['mnemonic'], insn['op_str'])


if __name__ == '__main__':
    main()
