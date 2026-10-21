#!/usr/bin/env python3
"""Rebuild verified original 7.1 Gadget field vectors from the exact Raw export.

Only original GadgetExcelConfigData bytes, the pinned 7.1 native decoder and
literal name searches contribute. No community labels or payout data are used.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path

from genshinre.gadgetbin import SCHEMA, scan_gadget_raw_export
from genshinre.nativeprofile import PROFILE_71

RAW_SHA256 = 'a35e3f3ed04f950cb6302099d12aa71e23ece21d8fe578950347d9318f769e35'
OUTPUT = Path('versions/7.1.0-global/analyses/progression/economy/7.1-native-gadget-field-vectors.json')


def entry(row):
    return {
        'preWrapperKeyAt0x30': row.gadget_id,
        'literalAt0x58': row.fields.get(0x58),
        'inheritedMask': f'0x{row.base_mask:X}',
        'gadgetMask': f'0x{row.mask:X}',
        'inheritedByOffset': {f'0x{k:X}': v for k, v in sorted(row.base_fields.items())},
        'gadgetByOffset': {f'0x{k:X}': v for k, v in sorted(row.fields.items())},
    }


def group(row):
    name = row.fields[0x58]
    if name.startswith('SceneObj_Chest'):
        return 'literal_SceneObj_Chest_prefix'
    if name.startswith('SearchPoint'):
        return 'literal_SearchPoint_prefix'
    return 'other_literal_names'


def coverage(rows):
    offsets = {loc for loc, _, _, _ in SCHEMA}
    booleans = {loc for loc, _, kind, _ in SCHEMA if kind == 'b'}
    result = {}
    for loc in sorted(offsets):
        present = [r.fields[loc] for r in rows if loc in r.fields]
        item = {'present': len(present), 'absent': len(rows) - len(present)}
        if loc in booleans:
            if any(type(v) is not bool for v in present):
                raise ValueError('non-boolean native byte')
            item.update(presentTrue=sum(v is True for v in present),
                        presentFalse=sum(v is False for v in present))
        else:
            canonical = Counter(json.dumps(v, ensure_ascii=False) for v in present)
            item['distinctEncodedValues'] = len(canonical)
            item['mostFrequent'] = [
                {'value': json.loads(v), 'count': count}
                for v, count in canonical.most_common(6)]
        result[f'0x{loc:X}'] = item
    return result


def audit(raw: bytes):
    if hashlib.sha256(raw).hexdigest() != RAW_SHA256:
        raise ValueError('not the pinned original Global 7.1 Gadget binary')
    scan = scan_gadget_raw_export(raw, expected_rows=30599)
    if len(scan.rows) != 30599:
        raise ValueError('incomplete original native table')
    population = [r for r in scan.rows if r.fields.get(0x6C) == 26]
    if len(population) != 309 or any(0x58 not in r.fields for r in population):
        raise ValueError('native type 26 controls changed')
    by_id = {r.gadget_id: r for r in population}
    for lv in range(1, 6):
        for n, variant in enumerate(('Default', 'Locked', 'Bramble', 'Frozen'), 1):
            key = 70210000 + lv * 10 + n
            if key not in by_id or by_id[key].fields[0x58] != f'SceneObj_Chest_{variant}_Lv{lv}':
                raise ValueError(f'original Gadget name control changed: {key}')
    groups = {name: [r for r in population if group(r) == name]
              for name in ('literal_SceneObj_Chest_prefix', 'literal_SearchPoint_prefix',
                           'other_literal_names')}
    if [len(rows) for rows in groups.values()] != [162, 21, 126]:
        raise ValueError('pinned original literal distribution changed')
    named_chest_outside = [
        r for r in scan.rows
        if 'Chest' in r.fields.get(0x58, '') and r.fields.get(0x6C) != 26
    ]
    return {
        'schemaVersion': 1,
        'status': 'EXACT_7_1_ORIGINAL_GADGET_FIELD_VECTORS__NO_REWARD_SEMANTICS',
        'source': {
            'exeSha256': PROFILE_71.exe_sha256,
            'officialBlock': '00/25539185.blk',
            'export': 'd65ab32f.dat', 'rawSha256': RAW_SHA256,
            'nativeInheritedReaderRva': '0xBD56F60',
            'nativeGadgetReaderRva': '0x10278E50',
            'nativeTableLoaderRva': '0x968F690',
            'decoder': 'genshinre/gadgetbin.py',
        },
        'controls': {
            'fullDecodedRows': len(scan.rows), 'unparsedBytes': 0,
            'numeric26Rows': len(population),
            'literalChestOutsideNumeric26Rows': len(named_chest_outside),
        },
        'numeric26LiteralGroups': {
            label: {'rows': len(rows), 'nativeFieldCoverage': coverage(rows)}
            for label, rows in groups.items()
        },
        'numeric26Records': [entry(r) for r in population],
        'literalChestOutsideNumeric26Records': [entry(r) for r in named_chest_outside],
        'limits': [
            'All row fields were decoded from the SHA-pinned original client binary.',
            '0x30 is the pre-wrapper scalar. Runtime key wrapper round trip unverified.',
            'Grouping is a case-sensitive literal-name research query, not a native reward enum.',
            'Candidate memory offsets are not serialized byte positions.',
            'Missing optional boolean fields are absent on wire, not false.',
            'No original scene-instance selector or server payout is claimed.',
        ],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--raw-export', required=True, type=Path)
    parser.add_argument('--output', type=Path, default=OUTPUT)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    report = audit(args.raw_export.read_bytes())
    if args.check:
        if json.loads(args.output.read_text(encoding='utf-8')) != report:
            raise SystemExit('pinned 7.1 Gadget field vectors diverged from original binary')
        print('PASS: 30599 original Gadget definitions; 309 type-26 field vectors')
    else:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2, ensure_ascii=False) + '\n',
                               encoding='utf-8')
        print(json.dumps(report['controls'], indent=2))


if __name__ == '__main__':
    main()
