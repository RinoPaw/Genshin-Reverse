#!/usr/bin/env python3
"""Collect exact design-index path probes and extracted Dungeon asset identities."""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from genshinre.assetindex import parse_asset_index, query_asset_paths, unwrap_mihoyo_bin_data
from genshinre.nativeprofile import PROFILE_71
from genshinre.dungeonbin import SCHEMA, scan_dungeon_table

OUTPUT = ROOT / 'versions/7.1.0-global/windows-x64/analyses/dungeon-progression/asset-path-probes.json'
INDEX_SHA256 = 'fe1e1ce970e3aa72e764b0894d94a684b7a49edc9f3ae6a32c4d7f38d8a64712'
BLOCK_MD5 = {31049741: 'a390222739d22aafb110019d10bff7e8',
             25539185: '8ce0bb0ac5ec42315f0f98d52e5d7c73'}
CONTROLS = ['QuestExcelConfigData', 'DungeonExcelConfigData', 'DailyDungeonConfigData',
            'DungeonEntryExcelConfigData', 'RewardPreviewExcelConfigData']
DROP_NAMES = ['DropTableExcelConfigData', 'DropSubTableExcelConfigData', 'DropMaterialExcelConfigData',
              'DropTable', 'DropSubTable', 'DropMaterial', 'DungeonDropExcelConfigData',
              'DungeonDropConfigData', 'DungeonDrop', 'DropExcelConfigData', 'DropConfigData']
PREFIXES = ['Data/_ExcelBinOutput/', 'Data/_BinOutput/', 'Data/_Server/', 'Data/Server/',
            'Server/', 'ExcelBinOutput/']


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def git_blob(raw: bytes) -> str:
    return hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()


def build(samples: Path, dungeon_resource: Path) -> dict:
    blocks = {}
    for block, expected in BLOCK_MD5.items():
        raw = (samples / f'{block}.blk').read_bytes()
        if hashlib.md5(raw).hexdigest() != expected:
            raise ValueError(f'block {block}: official manifest MD5 mismatch')
        blocks[str(block)] = {'groupId': 0, 'manifestMd5': expected, 'size': len(raw), 'sha256': sha(raw)}
    raw_index = (samples / 'design-index-export/MiHoYoBinData/0000006f.dat').read_bytes()
    if sha(raw_index) != INDEX_SHA256:
        raise ValueError('exact design AssetIndex export SHA-256 mismatch')
    index = parse_asset_index(raw_index)
    rows = query_asset_paths(index, ['Data/_ExcelBinOutput/'+name for name in CONTROLS])
    asset_payloads = {}
    for row in rows:
        if row['status'] != 'HASH_RESOLVED' or row['blockId'] != 25539185 or row['groupId'] != 0:
            raise ValueError(f'control asset location mismatch: {row}')
        raw = (samples / 'excel-export/MiHoYoBinData' / (str(row['exportedName'])+'.dat')).read_bytes()
        payload = unwrap_mihoyo_bin_data(raw)
        row['export'] = {'rawSize': len(raw), 'rawSha256': sha(raw),
                         'payloadSize': len(payload), 'payloadSha256': sha(payload)}
        asset_payloads[row['path']] = payload
    quest = rows[0]['export']
    if quest['payloadSha256'] != '07ab4816ee1eaa68fefd636b92dcfa923fe58a15731d18de0c0fb26863791fe5':
        raise ValueError('independent published QuestExcel payload control mismatch')
    probes = query_asset_paths(index, [prefix+name for prefix in PREFIXES for name in DROP_NAMES])
    payload = asset_payloads['Data/_ExcelBinOutput/DungeonExcelConfigData']
    scan = scan_dungeon_table(payload, allow_opaque_header=True)
    ids = [row.fields.get(0xD4) for row in scan.rows]
    if None in ids or len(set(ids)) != len(ids):
        raise ValueError('Dungeon scan has absent or duplicate ID candidates')
    resource_raw = dungeon_resource.read_bytes()
    expected_blob = '92983c5d9d46bccf486b803b7cf65f2cdf9088cb'
    if git_blob(resource_raw) != expected_blob:
        raise ValueError('pinned Dungeon resource blob mismatch')
    source_rows = json.loads(resource_raw)
    source_by_id = {row['id']: row for row in source_rows}
    if set(ids) != set(source_by_id) or len(ids) != len(source_rows):
        raise ValueError('native candidate ID set differs from pinned resource')
    aliases = {0xD4: 'id', 0xDC: 'sceneId', 0xE8: 'IAOMJCLOIEL',
               0xD0: 'limitLevel', 0x5C: 'passRewardPreviewID', 0x68: 'statueCostCount',
               0x104: 'nameTextMapHash', 0x108: 'levelRevise', 0x40: 'entryPicPath',
               0x88: 'cityID', 0xCC: 'dayEnterCount', 0x58: 'gearDescTextMapHash',
               0xE4: 'displayNameTextMapHash', 0xC0: 'descTextMapHash',
               0x70: 'quitSettleCountdownTime', 0x74: 'passCond', 0x94: 'failSettleCountdownTime',
               0xB0: 'settleCountdownTime', 0xBC: 'showLevel', 0x7C: 'reviveMaxCount',
               0xA8: 'statueCostID', 0x98: 'LBFFJMPGCBN', 0x110: 'KNKLKDNGEGI',
               0x80: 'PHGJMAKCFHE', 0x10C: 'EHLOPBNGBIM', 0x18: 'DILPLNIBBJF'}
    agreement = []
    for offset, alias in aliases.items():
        compared = 0
        for row in scan.rows:
            source_row = source_by_id[row.fields[0xD4]]
            if offset in row.fields:
                if row.fields[offset] != source_row.get(alias, 0):
                    raise ValueError(f'wire/source disagreement: {row.fields[0xD4]} {alias}')
                compared += 1
        agreement.append({'offset': f'0x{offset:X}', 'sourceAlias': alias,
                          'presentRowsCompared': compared, 'mismatches': 0})
    bindings = []
    for dungeon_id in [4434, 4437]:
        row = next(row for row in scan.rows if row.fields[0xD4] == dungeon_id)
        bindings.append({
            'dungeonIdCandidate': dungeon_id, 'rowStart': row.start, 'rowEnd': row.end,
            'rootFieldOffset': '0xE8', 'decodedRoot': row.fields[0xE8],
            'rootSpan': list(row.spans[0xE8]),
            'sceneIdCandidate': row.fields[0xDC], 'limitLevelCandidate': row.fields[0xD0],
            'previewIdCandidate': row.fields[0x5C], 'costCountCandidate': row.fields[0x68],
            'status': 'ROW_WIRE_BOUND_SEMANTICS_SOURCE_DEPENDENT',
        })
    row_wire = {
        'status': 'ROW_WIRE_DECODED_HEADER_UNRESOLVED',
        'reader': {'owner': 'LGLHLMDKIEO', 'method': 'GMENPOPMKAA', 'rva': '0x12CA3BA0',
                   'exeSha256': PROFILE_71.exe_sha256,
                   'metadataSha256': PROFILE_71.metadata_sha256},
        'headerHex': scan.header_hex, 'headerCountDecoded': False,
        'observedRowCount': len(scan.rows), 'bytesConsumed': scan.bytes_consumed,
        'payloadSize': len(payload), 'trailingBytes': len(payload)-scan.bytes_consumed,
        'uniqueIdCandidateCount': len(set(ids)),
        'fieldReadOrder': [f'0x{field[0]:X}' for field in SCHEMA],
        'fieldPresentCounts': {f'0x{field[0]:X}': sum(field[0] in row.fields for row in scan.rows)
                               for field in SCHEMA},
        'targetBindings': bindings,
        'sourceComparison': {
            'repository': 'RinoPaw/AstaPS-Resource',
            'commit': 'b0f3a2791607cab2a4c24cb9ef249dd2d94d7ffd',
            'path': 'ExcelBinOutput/DungeonExcelConfigData.json', 'gitBlobSha': expected_blob,
            'idSetsEqual': True, 'rowCount': len(source_rows), 'fieldAgreement': agreement,
            'limit': 'aliases validated against this projection; native consumer semantics unproven',
        },
        'limits': ['opaque four-byte table header; scanning to EOF does not decode its count',
                   'unsigned scalar wire values, not enum names or wrapper memory representation',
                   'semantic aliases require independently pinned source comparison',
                   'source root reference is not the drop table or a native consumer'],
    }
    tools = ['scripts/collect-7.1-dungeon-assets.py', 'genshinre/assetindex.py', 'genshinre/nativeprofile.py', 'genshinre/binconfig.py', 'genshinre/dungeonbin.py']
    return {
        'schemaVersion': 1, 'target': 'Genshin Impact 7.1.0 Global Windows x64',
        'scope': 'exact asset identities and Dungeon row wire scan; table header and drop distribution unresolved',
        'source': {'manifestUrl': PROFILE_71.sophon_manifest_url,
                   'chunkPrefix': PROFILE_71.sophon_chunk_prefix, 'blocks': blocks,
                   'index': {'exportedName': '0000006f', 'rawSize': len(raw_index), 'rawSha256': sha(raw_index),
                             'payloadSha256': sha(unwrap_mihoyo_bin_data(raw_index)),
                             'nameCount': len(index.names), 'blockReferenceCount': len(index.block_refs),
                             'blockCount': len(index.block_groups)}},
        'exporter': {'repository': 'EIHRTeam/AnimeStudio', 'release': 'v1.0.0-CI',
                     'archive': 'AnimeStudio.CLI-1.0.0-CI-linux-x64.tar.gz',
                     'archiveSha256': '12e2dfb2ab35880eda4274fcd393091d47e204d4b6e4b5838421fa3b4d1720a1',
                     'runtime': 'Microsoft.NETCore.App 10.0.0 Linux x64',
                     'arguments': '--game GI --types MiHoYoBinData --export_type Raw --logger_flags Error'},
        'generator': {'script': tools[0], 'toolGitBlobShas': {p:git_blob((ROOT/p).read_bytes()) for p in tools},
                      'command': 'python scripts/collect-7.1-dungeon-assets.py --samples inputs/7.1.0-global --dungeon-resource ../AstaPS-Resource/ExcelBinOutput/DungeonExcelConfigData.json --check'},
        'controls': rows, 'dropPathProbes': probes,
        'summary': {'controlCount': len(rows), 'dropPathCount': len(probes),
                    'dropPathHashAbsentCount': sum(r['status']=='HASH_ABSENT' for r in probes)},
        'dungeonRowWire': row_wire,
        'limitations': ['40-bit hash membership alone is not semantic path ownership',
                        'absence applies only to listed paths in this exact design index',
                        'alternative names, separate indexes and server-only tables remain possible',
                        'Dungeon table header count and native consumer remain unresolved',
                        'no missing roots, item quantities or native probabilities recovered'],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--samples', required=True, type=Path)
    parser.add_argument('--dungeon-resource', required=True, type=Path)
    parser.add_argument('--output', type=Path, default=OUTPUT)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    result = build(args.samples, args.dungeon_resource)
    if args.check:
        if json.loads(args.output.read_text()) != result:
            raise SystemExit('Dungeon asset probes differ from snapshot')
        print('PASS: exact design index, control assets and finite drop-path probes')
    else:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(result, indent=2, ensure_ascii=False)+'\n')
        print(f'Wrote {args.output}')


if __name__ == '__main__':
    main()
