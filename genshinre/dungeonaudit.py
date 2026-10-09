"""Static reward-path audit of the pinned AstaPS implementation.

This predicts configured paths, not live claims or native Genshin probabilities.
It deliberately does not map IAOMJCLOIEL into Java's unaliased statueDrop.
"""
from __future__ import annotations

from collections import Counter
from fractions import Fraction
import hashlib
import json
import math
from pathlib import Path

SERVER_COMMIT = 'b1c5af21a26deaaa9983f485d98cd32e5693e64e'
SERVER_FILES = {
    "src/main/java/emu/grasscutter/data/common/ItemParamData.java": "c7723597626c5e894af76b05fb6d85e9cba89ff7",
    "src/main/java/emu/grasscutter/data/common/ItemParamStringData.java": "7f864fc9efc259e167026a25b6d0e27dadd38bd5",
    "src/main/java/emu/grasscutter/data/excels/RewardPreviewData.java": "dad51e911d32736b4aca8129f488c5a1c9c7496f",
    "data/DungeonDrop.json": "7fdd3b01d7b4fedc5837eae776502aeffc2fe3ed",
    "src/main/java/emu/grasscutter/data/ResourceLoader.java": "d8620d9a8983e7e4e0ac642e10d52a1201fb63cc",
    "src/main/java/emu/grasscutter/data/common/DropItemData.java": "401162f91f9ee28b802c0b7dc3df29fe2fcd3449",
    "src/main/java/emu/grasscutter/data/excels/DropTableData.java": "e2f1cd15b8ba6a01a2f95eadaa38229422554f55",
    "src/main/java/emu/grasscutter/data/excels/dungeon/DungeonData.java": "ad4d651c9233ff971b75370b4895da90bd8ef176",
    "src/main/java/emu/grasscutter/game/drop/DropSystem.java": "e8269faca8b46a771f2214242edceaee0f35abb2",
    "src/main/java/emu/grasscutter/game/dungeons/DungeonDropEntry.java": "80e7b80af7e356b2b79a53f8231e9ff4fe99cf3c",
    "src/main/java/emu/grasscutter/game/dungeons/DungeonDropLoader.java": "2ec3db990d5390fb2f07f14831f417b5a93b6a10",
    "src/main/java/emu/grasscutter/game/dungeons/DungeonManager.java": "e919b5e502b3649fab2b509faa8ef475e0b7ae53",
    "src/main/java/emu/grasscutter/game/dungeons/MaterialDomainTripleHelper.java": "f4761839f44e27f8dc6ede372a59cd9c61b66ba8",
    "src/main/java/emu/grasscutter/game/dungeons/ReliquaryDomainBonusHelper.java": "cc916b09f084a42be3636a4a5bb48b7b62da8e4c",
    "src/main/java/emu/grasscutter/utils/JsonUtils.java": "9de7c579fb09780801866106ae0c7f893fe9fd97",
    "src/main/java/emu/grasscutter/utils/Utils.java": "3ce9afdf7bd46cecba44e5c5359149faaa7d16b0"
}
SKIP_BOOST = {101, 102, 104, 105, 201, 202, 203, 204}
MATERIAL_SUBTYPES = {'DUNGEON_SUB_TALENT', 'DUNGEON_SUB_WEAPON'}


def git_blob(raw: bytes) -> str:
    return hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()


def indexed(rows: list[dict], key: str) -> dict[int, dict]:
    out = {r[key]: r for r in rows if r.get(key)}
    if len(out) != sum(bool(r.get(key)) for r in rows):
        raise ValueError(f'duplicate {key}')
    return out


def selection(size: int, weights: list | None, label: str) -> tuple[list[Fraction], list[str]]:
    """Utils.drawRandomListElement: mismatched/singleton weights mean uniform."""
    if size <= 0:
        return [], [label + '_EMPTY_CANDIDATES']
    if weights is None or len(weights) <= 1 or len(weights) != size:
        issues = [label + '_WEIGHTS_IGNORED'] if weights is not None and size > 1 else []
        return [Fraction(1, size)] * size, issues
    if any(type(w) is not int or w < 0 for w in weights) or sum(weights) <= 0:
        return [], [label + '_INVALID_WEIGHTS']
    if sum(weights) >= 2147483647:
        return [], [label + '_WEIGHT_SUM_OVERFLOW']
    return [Fraction(w, sum(weights)) for w in weights], []


def analyze_group(entry: dict, boost: bool) -> dict:
    counts, items = entry.get('counts'), entry.get('items')
    issues = []
    if (not isinstance(counts, list) or not counts or
            any(type(c) is not int for c in counts) or counts[0] < 0 or
            counts[-1] < counts[0] or counts[-1]-counts[0] > 100000):
        return {'issues': ['INVALID_COUNT_RANGE'], 'items': items}
    candidates = list(range(counts[0], counts[-1]+1))
    cp, errs = selection(len(candidates), entry.get('probabilities'), 'COUNT')
    issues.extend(errs)
    if not isinstance(items, list) or not items or any(type(i) is not int or i <= 0 for i in items):
        issues.append('INVALID_ITEMS')
        if items == [] and cp and all(c > 0 or p == 0 for c, p in zip(candidates, cp)):
            issues.append('EMPTY_ITEMS_GUARANTEED_DRAW_EXCEPTION')
        return {'issues': issues, 'items': items, 'countRange': [counts[0], counts[-1]]}
    ip, errs = selection(len(items), entry.get('itemProbabilities'), 'ITEM')
    # A single item is directly stacked, so its item weights are never read.
    if len(items) > 1:
        issues.extend(errs)
    else:
        ip = [Fraction(1)]
    out = {'items': items, 'countRange': [counts[0], counts[-1]],
           'coopDouble': bool(entry.get('mpDouble')), 'issues': issues}
    if cp:
        mean = sum((c*p for c, p in zip(candidates, cp)), Fraction(0))
        out['baseCountMean'] = float(mean)
        out['basePositiveCountPossible'] = any(c > 0 and p > 0 for c, p in zip(candidates, cp))
        if ip:
            out['soloOriginalResinExpectedByItem'] = [
                {'itemId': item, 'baseMean': float(mean*p),
                 'postBoostMeanIfMaterialOrItemDataMissing': float(mean*p*(3 if boost and item not in SKIP_BOOST else 1))}
                for item, p in zip(items, ip)]
    return out



def runtime_preview_items(entries: list[dict]) -> list[dict]:
    """RewardPreviewData.onLoad filtering and ItemParamStringData conversion."""
    result = []
    for entry in entries:
        if entry.get('id', 0) <= 0 or entry.get('count') in (None, ''):
            continue
        count = str(entry['count'])
        if ';' in count:
            amount = int(count.split(';')[-1])
        elif '.' in count:
            amount = math.ceil(float(count))
        else:
            amount = int(count)
        result.append({'itemId': entry['id'], 'count': max(amount, 1)})
    return result


def audit_dungeon_rewards(dungeons: list[dict], previews: list[dict],
                          server_drops: list[dict], resource_drop_ids: set[int]) -> dict:
    indexed(dungeons, 'id')
    preview_map = indexed(previews, 'id')
    server = indexed(server_drops, 'dungeonId')
    # DungeonDropLoader skips empty rows rather than loading an empty proxy.
    server = {i: r for i, r in server.items() if r.get('drops')}
    selected = sorted((r for r in dungeons if r.get('type') in
                       {'DUNGEON_DAILY_FIGHT', 'DUNGEON_BOSS'}), key=lambda r: r['id'])
    family_items = {subtype: set() for subtype in MATERIAL_SUBTYPES}
    for dungeon in selected:
        subtype = dungeon.get('subType')
        if subtype in family_items:
            family_items[subtype].update(
                int(p['id']) for p in preview_map.get(dungeon.get('passRewardPreviewID'), {}).get('previewItems', [])
                if p.get('id', 0) > 1000)
    rows = []
    for d in selected:
        did, subtype = d['id'], d.get('subType')
        preview = preview_map.get(d.get('passRewardPreviewID'))
        preview_entries = preview.get('previewItems', []) if preview else []
        preview_items = [int(p['id']) for p in preview_entries if p.get('id', 0) > 0]
        runtime_preview = runtime_preview_items(preview_entries)
        has_preview = bool(runtime_preview)
        runtime_root = d.get('statueDrop', 0) or 0
        source_root = d.get('IAOMJCLOIEL', 0) or 0
        route = ('INITIAL_GATE_REJECT' if not has_preview and runtime_root <= 0 else
                 'SERVER_PROXY' if did in server else
                 'RESOURCE_TABLE_CANDIDATE' if runtime_root in resource_drop_ids and runtime_root > 0 else
                 'PREVIEW_FALLBACK' if has_preview else 'NULL_PREVIEW_RISK')
        issues = []
        if source_root and not runtime_root:
            issues.append('SOURCE_ROOT_NOT_BOUND_TO_JAVA_STATUE_DROP')
        if route == 'PREVIEW_FALLBACK':
            issues.append('PREVIEW_USED_AS_REWARD')
            if not preview_items:
                issues.append('PREVIEW_HAS_NO_VALID_ITEMS')
        groups = []
        if route == 'SERVER_PROXY':
            groups = [analyze_group(e, subtype in MATERIAL_SUBTYPES) for e in server[did]['drops']]
            for g in groups:
                issues.extend(g['issues'])
            item_ids = {i for g in groups for i in (g.get('items') or []) if type(i) is int}
            if subtype in MATERIAL_SUBTYPES:
                unexpected = sorted(item_ids - set(preview_items) - SKIP_BOOST)
                if unexpected:
                    issues.append('MATERIAL_ITEMS_OUTSIDE_OWN_PREVIEW')
            elif subtype == 'DUNGEON_SUB_RELIQUARY':
                unexpected = sorted(item_ids & set.union(*family_items.values()))
                if unexpected:
                    issues.append('RELIQUARY_PROXY_CONTAINS_MATERIAL_DOMAIN_ITEMS')
            else:
                unexpected = []
            if groups and all(g.get('basePositiveCountPossible') is False for g in groups):
                issues.append('PROXY_ALL_COUNTS_ZERO')
        else:
            unexpected = []
        row = {'dungeonId': did, 'type': d['type'], 'subType': subtype,
               'stateType': d.get('stateType'), 'configuredPrimaryRoute': route,
               'sourceRoot': source_root or None, 'javaStatueDrop': runtime_root,
               'sourceRootPresentInResourceTable': source_root in resource_drop_ids if source_root else None,
               'previewId': d.get('passRewardPreviewID'), 'sourcePreviewItemIds': preview_items,
               'runtimePreviewItemIds': [p['itemId'] for p in runtime_preview],
               'unexpectedMaterialItemIds': unexpected, 'issues': sorted(set(issues))}
        if 'EMPTY_ITEMS_GUARANTEED_DRAW_EXCEPTION' in issues:
            row['configuredClaimRisk'] = 'rollRewards throws before inventory add; handleCost runs first, no rollback here'
        if groups:
            # Full large artifact pools are already identified by the pinned server blob.
            # Keep fingerprints and a small sample rather than repeating thousands of means.
            for group in groups:
                pool = group.get('items') or []
                expectations = group.pop('soloOriginalResinExpectedByItem', None)
                if expectations is not None:
                    group['postBoostCountMeanIfMaterialOrItemDataMissing'] = sum(
                        e['postBoostMeanIfMaterialOrItemDataMissing'] for e in expectations)
                if len(pool) > 10:
                    group['itemCount'] = len(pool)
                    group['itemIdsSha256'] = hashlib.sha256(
                        json.dumps(pool, separators=(',', ':')).encode()).hexdigest()
                    group['itemIdSample'] = pool[:5]
                    del group['items']
            row['proxyGroups'] = groups
        if route == 'PREVIEW_FALLBACK':
            row['previewFallbackSoloRewardsBeforeBonus'] = runtime_preview
            if subtype in MATERIAL_SUBTYPES and not any(p['itemId'] in family_items[subtype] for p in runtime_preview):
                row['issues'].append('PREVIEW_FALLBACK_OMITS_DOMAIN_MATERIALS')
            row['previewIdsRemovedByCountFilter'] = sorted(set(preview_items)-{p['itemId'] for p in runtime_preview})
            row['condensedResinFallbackDoublesRewards'] = False
        if subtype in MATERIAL_SUBTYPES:
            row['materialBonus'] = {'factor': 3, 'condition': 'ITEM_MATERIAL, or absent ItemData and itemId >= 1000; exempt IDs excluded'}
        if subtype == 'DUNGEON_SUB_RELIQUARY':
            row['reliquaryBonus'] = {'removesItem': 105005, 'addsIfNo105003Or105002':
                                    [{'itemId': 105003, 'range': [6, 12]}, {'itemId': 105002, 'range': [7, 10]}]}
        rows.append(row)
    group_models = {}
    for row in rows:
        if 'proxyGroups' in row:
            refs = []
            for group in row.pop('proxyGroups'):
                canonical = json.dumps(group, sort_keys=True, separators=(',', ':')).encode()
                key = hashlib.sha256(canonical).hexdigest()
                group_models[key] = group
                refs.append(key)
            row['proxyGroupModelIds'] = refs
    issue_counts = Counter(i for row in rows for i in row['issues'])
    routes = Counter(row['configuredPrimaryRoute'] for row in rows)
    subtypes = sorted({row['subType'] or 'NONE' for row in rows})
    return {'summary': {'dungeonCount': len(rows), 'routes': dict(sorted(routes.items())),
                        'issuesByDungeonCount': dict(sorted(issue_counts.items())),
                        'bySubType': {s: dict(Counter(r['configuredPrimaryRoute'] for r in rows
                                                    if (r['subType'] or 'NONE') == s)) for s in subtypes},
                        'proxyRowsOutsideSelectedDungeons': sorted(server.keys()-{r['dungeonId'] for r in rows})},
            'dungeons': rows, 'proxyGroupModels': dict(sorted(group_models.items()))}


def audit_dungeon_directories(resource_root: Path, server_root: Path, *, resource_source: str) -> dict:
    server_evidence = {}
    for path, expected in SERVER_FILES.items():
        actual = git_blob((server_root/path).read_bytes())
        if actual != expected:
            raise ValueError(f'{path}: reward model requires pinned AstaPS {SERVER_COMMIT}; blob {actual} != {expected}')
        server_evidence[path] = {'gitBlobSha': actual}
    resource_paths = ['ExcelBinOutput/DungeonExcelConfigData.json',
                      'ExcelBinOutput/RewardPreviewExcelConfigData.json',
                      'Server/DropTableExcelConfigData.json', 'Server/DropSubTableExcelConfigData.json']
    tables, evidence = {}, {}
    for path in resource_paths:
        raw = (resource_root/path).read_bytes()
        tables[path] = json.loads(raw)
        evidence[path] = {'gitBlobSha': git_blob(raw), 'rowCount': len(tables[path])}
    result = audit_dungeon_rewards(tables[resource_paths[0]], tables[resource_paths[1]],
                                   json.loads((server_root/'data/DungeonDrop.json').read_bytes()),
                                   {r['id'] for path in resource_paths[2:] for r in tables[path]})
    return {'schemaVersion': 1, 'target': 'AstaPS configured Dungeon reward paths',
            'evidence': 'B: pinned server implementation and resource projection; not native drop probabilities or live gameplay verification',
            'source': {'server': {'repository': 'RinoPaw/AstaPS', 'commit': SERVER_COMMIT, 'files': server_evidence},
                       'resource': {'label': resource_source, 'files': evidence}},
            'assumptions': ['these JSON files are deployed and loaded successfully',
                            'DungeonData JSON uses unaliased statueDrop; IAOMJCLOIEL is not remapped',
                            'RewardPreviewData filters out entries without count; decimals ceil and ranges use last endpoint; no plugin override',
                            'proxy groups describe solo original-resin base rolls before bonus; material boost is conditional on ItemData'],
            'limitations': ['no dungeon reachability, pass-condition, inventory validity or live claim validation',
                            'resource graph path is a candidate only; its roll outcome is not simulated',
                            'preview fallback ignores condensed-resin doubling; count-less materials are filtered before fallback',
                            'reliquary piece/set mappings are not available for exact preview comparison',
                            'custom bonuses are server behavior and do not establish official drop rates'],
            'generator': {'module': 'genshinre.dungeonaudit',
                          'toolGitBlobShas': {p: git_blob((Path(__file__).parent.parent/p).read_bytes())
                                             for p in ['genshinre/dungeonaudit.py', 'genshinre/cli.py']}},
            **result}
