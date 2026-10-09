#!/usr/bin/env python3
"""Reproduce a bounded Dungeon-config candidate trace from the pinned 7.1 client.

Requires capstone==5.0.9 and the official samples fetched by fetch-7.1-samples.sh.
No client asset rows, loader identity, reward distributions or runtime execution
are established by this trace.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
from importlib.metadata import version
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from genshinre.nativeprofile import PROFILE_71
from genshinre.pe import PEImage
from genshinre.pointerxref import scan_pointer_xrefs
from genshinre.callxref import scan_direct_call_xrefs

OUTPUT = ROOT / 'versions/7.1.0-global/windows-x64/analyses/dungeon-progression/client-config-candidate.json'
HASHES = {'GenshinImpact.exe': PROFILE_71.exe_sha256,
          'global-metadata.dat': PROFILE_71.metadata_sha256}
RESOURCE_BLOB = '92983c5d9d46bccf486b803b7cf65f2cdf9088cb'
READER = 0x12CA3BA0


def git_blob(raw: bytes) -> str:
    return hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()


def build(samples: Path, resource: Path) -> dict:
    import capstone
    from capstone.x86 import X86_OP_MEM, X86_REG_RBX
    if version('capstone') != '5.0.9':
        raise ValueError('reproducibility requires capstone==5.0.9')
    sample_evidence = {}
    for name, expected in HASHES.items():
        path = samples / name
        with path.open('rb') as stream:
            actual = hashlib.file_digest(stream, 'sha256').hexdigest()
        if actual != expected:
            raise ValueError(f'{name}: SHA-256 mismatch')
        sample_evidence[name] = {'sha256': actual, 'size': path.stat().st_size}
    source_raw = (resource / 'ExcelBinOutput/DungeonExcelConfigData.json').read_bytes()
    if git_blob(source_raw) != RESOURCE_BLOB:
        raise ValueError('DungeonExcelConfigData source blob mismatch')
    source = json.loads(source_raw)
    metadata = ROOT / 'versions/7.1.0-global/windows-x64/metadata'
    evidence = {}
    fields = []
    methods = []
    for name, destination in [('fields.csv', fields), ('methods.csv', methods)]:
        evidence[name] = git_blob((metadata / name).read_bytes())
        with (metadata / name).open(newline='', encoding='utf-8-sig') as stream:
            for row in csv.DictReader(stream):
                if row['type_definition_index'] in {'33015', '28775'}:
                    destination.append(row)
    owner = [r for r in fields if r['type_definition_index'] == '33015']
    assert len(owner) == 67
    target = next(r for r in owner if r['field_name'] == 'IAOMJCLOIEL')
    assert target['field_index'] == '165131' and target['field_type'] == 'EEOPHKIFFPL'
    assert next(r for r in methods if r['method_index'] == '261095')['rva'] == '0x12CA3BA0'
    shared = sorted({key for row in source for key in row} & {r['field_name'] for r in owner})
    # Candidate ABI layout, not canonical field offsets: references=8, bool=1,
    # scalar/wrapper/enum candidates=4, object header=16. Reader stores corroborate
    # the displacement/width set; nested temporary RBX stores are also present.
    inferred = []
    offset = 0x10
    for row in owner:
        kind = row['field_type']
        width = 8 if kind in {'string', 'kind_0x1D', 'kind_0x15'} else 1 if kind == 'bool' else 4
        offset = (offset + width - 1) // width * width
        inferred.append({**row, 'candidateOffset': f'0x{offset:X}', 'candidateWidth': width})
        offset += width
    assert next(r for r in inferred if r['field_name'] == 'IAOMJCLOIEL')['candidateOffset'] == '0xE8'
    exe = samples / 'GenshinImpact.exe'
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    decoder.detail = True
    excerpts = {}
    with PEImage(exe) as image:
        instructions = list(decoder.disasm(image.read_rva(READER, 0x12CA6960 - READER), READER))
        stores = set()
        for ins in instructions:
            if ins.mnemonic == 'mov' and ins.operands:
                dest = ins.operands[0]
                if dest.type == X86_OP_MEM and dest.mem.base == X86_REG_RBX and dest.mem.index == 0:
                    stores.add((dest.mem.disp, dest.size))
        for row in inferred:
            assert (int(row['candidateOffset'], 16), row['candidateWidth']) in stores, row
        ranges = {'targetReadAndStore': (0x12CA5384, 0x12CA53F5),
                  'wrapperEncode': (0xBB16020, 0xBB160C0),
                  'wrapperDecode': (0xBB15F50, 0xBB15FF4)}
        for name, (start, end) in ranges.items():
            seq = ([i for i in instructions if start <= i.address < end]
                   if name == 'targetReadAndStore' else decoder.disasm(image.read_rva(start, end-start), start))
            excerpts[name] = [{'rva': f'0x{i.address:X}', 'instructionHex': i.bytes.hex(),
                               'mnemonic': i.mnemonic, 'operands': i.op_str} for i in seq]
        exact = {i.address: i.bytes.hex() for i in instructions}
        for rva, expected in {0x12CA5389: 'f7c700200000', 0x12CA53CA: 'ba2f0cbb2d',
                              0x12CA53CF: '33541820', 0x12CA53E7: 'e8340ce7f8',
                              0x12CA53EF: '8983e8000000'}.items():
            assert exact[rva] == expected
        holder_value = int.from_bytes(image.read_rva(0x2A6EAC8, 8), 'little')
        assert holder_value == image.image_base + READER
    example = next(r for r in source if r.get('id') == 4434)
    return {
        'schemaVersion': 1, 'target': 'Genshin Impact 7.1.0 Global Windows x64',
        'status': 'PARTIAL',
        'scope': 'static native reader evidence; semantic owner and field binding remain HIGH_CONFIDENCE candidates',
        'samples': sample_evidence,
        'source': {'repository': 'RinoPaw/AstaPS-Resource',
                   'commit': 'b0f3a2791607cab2a4c24cb9ef249dd2d94d7ffd',
                   'DungeonExcelConfigDataGitBlobSha': RESOURCE_BLOB, 'example': example},
        'generator': {'script': 'scripts/collect-7.1-client-dungeon-config.py',
                      'capstoneDistributionVersion': version('capstone'),
                      'capstoneBindingVersion': capstone.__version__,
                      'toolGitBlobShas': {name: git_blob((ROOT/name).read_bytes()) for name in
                          ['scripts/collect-7.1-client-dungeon-config.py', 'genshinre/pe.py',
                           'genshinre/callxref.py', 'genshinre/pointerxref.py', 'genshinre/xrefs.py',
                           'genshinre/nativeprofile.py']},
                      'metadataGitBlobShas': evidence,
                      'command': 'python scripts/collect-7.1-client-dungeon-config.py --samples inputs/7.1.0-global --resource-root /path/to/AstaPS-Resource --check'},
        'ownerCandidate': {'typeName': 'LGLHLMDKIEO', 'typeDefinitionIndex': 33015,
                           'sharedObfuscatedResourceKeys': shared,
                           'readerMethodIndex': 261095, 'readerRva': '0x12CA3BA0',
                           'fieldCount': 67, 'fields': inferred,
                           'layoutStatus': 'ABI_CANDIDATE_ALL_67_DISPLACEMENT_WIDTH_PAIRS_PRESENT',
                           'layoutLimit': 'metadata offsets are empty; store set is not a per-field dataflow proof'},
        'targetCandidate': {'fieldName': 'IAOMJCLOIEL', 'fieldIndex': 165131,
                            'semanticStatus': 'SOURCE_DROP_ROOT_KEY_CANDIDATE',
                            'candidateObjectOffset': '0xE8', 'storageType': 'EEOPHKIFFPL',
                            'storageFields': [r for r in fields if r['type_definition_index'] == '28775'],
                            'nativeRead': {'presenceMaskBit': 13, 'byteWidth': 4,
                                           'decode': 'little_endian_uint32 XOR 0x2DBB0C2F',
                                           'absentValueBeforeWrapping': 0, 'wrapperEncodeRva': '0xBB16020',
                                           'storeInstructionRva': '0x12CA53EF'},
                            'memoryWrapper': 'byte permutation tables plus runtime XOR key; stored wrapper bits are not the source integer'},
        'instructions': excerpts,
        'directCallScan': scan_direct_call_xrefs(exe, [READER, 0x12CA6960]),
        'pointerScan': scan_pointer_xrefs(exe, READER, READER+1),
        'unresolved': ['native asset path and loading/dispatch owner',
                       'native Dungeon 4434 row and raw serialized value',
                       'consumer that interprets the candidate value as a drop-root ID',
                       'claim request/response binding and runtime observation',
                       'missing DropTable/DropSubTable rows, quantities and native probabilities'],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--samples', type=Path, required=True)
    parser.add_argument('--resource-root', type=Path, required=True)
    parser.add_argument('--output', type=Path, default=OUTPUT)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    result = build(args.samples, args.resource_root)
    if args.check:
        if json.loads(args.output.read_text()) != result:
            raise SystemExit('native Dungeon candidate trace differs from snapshot')
        print('PASS: pinned native Dungeon candidate trace')
    else:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n')
        print(f'Wrote {args.output}')


if __name__ == '__main__':
    main()
