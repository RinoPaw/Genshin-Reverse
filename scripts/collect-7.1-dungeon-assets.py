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


def build(samples: Path) -> dict:
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
    leads = []
    for root in [82162700, 82165000]:
        # Source-selected byte searches are leads, not parsed rows or ID ownership.
        encoded = (root ^ 0x2DBB0C2F).to_bytes(4, 'little')
        offsets = []
        pos = 0
        while True:
            pos = payload.find(encoded, pos)
            if pos < 0:
                break
            offsets.append(pos)
            pos += 1
        leads.append({'sourceRootId': root, 'encodedNeedleHex': encoded.hex(),
                      'payloadOffsets': offsets, 'status': 'CANDIDATE_BYTE_MATCH',
                      'limit': 'no row boundary, Dungeon ID binding or field identity established'})
    tools = ['scripts/collect-7.1-dungeon-assets.py', 'genshinre/assetindex.py', 'genshinre/nativeprofile.py']
    return {
        'schemaVersion': 1, 'target': 'Genshin Impact 7.1.0 Global Windows x64',
        'scope': 'exact path-hash membership and raw-export identities; no full Dungeon decode or native drop distribution',
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
                      'command': 'python scripts/collect-7.1-dungeon-assets.py --samples inputs/7.1.0-global --check'},
        'controls': rows, 'dropPathProbes': probes,
        'summary': {'controlCount': len(rows), 'dropPathCount': len(probes),
                    'dropPathHashAbsentCount': sum(r['status']=='HASH_ABSENT' for r in probes)},
        'byteLeads': leads,
        'limitations': ['40-bit hash membership alone is not semantic path ownership',
                        'absence applies only to listed paths in this exact design index',
                        'alternative names, separate indexes and server-only tables remain possible',
                        'Dungeon row framing and full reader schema remain unresolved',
                        'no missing roots, item quantities or native probabilities recovered'],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--samples', required=True, type=Path)
    parser.add_argument('--output', type=Path, default=OUTPUT)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    result = build(args.samples)
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
