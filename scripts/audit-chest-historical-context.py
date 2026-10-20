#!/usr/bin/env python3
"""Read-only, offline historical ChestDrop source comparison. No native 7.1 claims."""
from __future__ import annotations
import argparse
import csv
import hashlib
import json
from pathlib import Path

EARLY_COLUMNS = ('最小等级','总索引','掉落ID','掉落次数','产出来源类型')
ARRANGEMENT_COLUMNS = ('类别','掉落标签','布设上限')

def tsv(path: Path, expected=None):
    with path.open(encoding='utf-8-sig', newline='') as f:
        reader = csv.DictReader(f, delimiter='\t')
        header = tuple(reader.fieldnames or ())
        if expected is not None and header != expected:
            raise ValueError(f'{path}: unexpected columns {header!r}')
        out = []
        for lineno, row in enumerate(reader, 2):
            if None in row or any(v is None for v in row.values()):
                raise ValueError(f'{path}: malformed row {lineno}')
            out.append(row)
    return out

def git_blob(path: Path):
    raw = path.read_bytes()
    return hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()

def historical_pairs(early, later, *, full=False):
    """Compare historical level/tag selections, keeping type codes as raw evidence."""
    from collections import Counter
    def keyed(rows, label):
        out = {}
        for row in rows:
            k = (row['最小等级'], row['总索引'])
            if k in out:
                raise ValueError(f'{label} duplicate level/tag: {k}')
            out[k] = row
        return out
    a, b = keyed(early, 'early'), keyed(later, 'later')
    common = a.keys() & b.keys()
    equal = {k for k in common if (a[k]['掉落ID'], a[k]['掉落次数'])
             == (b[k]['掉落ID'], b[k]['掉落次数'])}
    order = lambda k: (k[1], int(k[0]))
    different = sorted(common - equal, key=order)
    transitions = Counter((a[k]['产出来源类型'], b[k]['产出来源类型']) for k in common)
    result = {
        'earlierRows': len(early), 'laterRows': len(later),
        'sameLevelAndTag': len(common), 'sameRootAndCount': len(equal),
        'differentRootOrCount': len(different),
        'earlierOnlyKeys': len(a.keys()-b.keys()), 'laterOnlyKeys': len(b.keys()-a.keys()),
        'changedExamples': [{'level': level, 'tag': tag,
                             'earlierRoot': a[(level,tag)]['掉落ID'],
                             'laterRoot': b[(level,tag)]['掉落ID']}
                            for level,tag in different[:12]],
        'sourceTypeTransitions': [
            {'earlierCode': x, 'laterCode': y, 'matchedKeys': n}
            for (x,y),n in sorted(transitions.items())],
        'sourceTypeComparable': False,
        'note': 'Observed source-type pairs describe shared keys, not a universal numeric-code translation or native schema.'
    }
    if full:
        result['changedRows'] = [
            {'minLevel': int(level), 'tag': tag,
             'earlierRoot': int(a[(level,tag)]['掉落ID']),
             'laterRoot': int(b[(level,tag)]['掉落ID']),
             'earlierCount': int(a[(level,tag)]['掉落次数']),
             'laterCount': int(b[(level,tag)]['掉落次数']),
             'earlierSourceType': a[(level,tag)]['产出来源类型'],
             'laterSourceType': b[(level,tag)]['产出来源类型'],
             'laterCategory': b[(level,tag)].get('类别','')}
            for level,tag in different]
        result['earlierOnlyRows'] = [a[k] for k in sorted(a.keys()-b.keys(), key=order)]
        result['laterOnlyRows'] = [b[k] for k in sorted(b.keys()-a.keys(), key=order)]
    return result

def arrangement_audit(later, limits):
    tags={r['总索引'] for r in later}
    limit={r['掉落标签'] for r in limits if r['类别']=='0'}
    return {'arrangementRows':len(limits),'textTagRows':sum(r['类别']=='0' for r in limits),
            'otherCategoryRows':sum(r['类别']!='0' for r in limits),
            'distinctChestDropTags':len(tags),'tagsAlsoInLimit':len(tags & limit),
            'chestDropTagsAbsentFromLimit':len(tags-limit),
            'limitTagsAbsentFromChestDrop':len(limit-tags),
            'placementPolicyValidated':False}

def table_audit(later, tree, leaf):
    def index(rows,kind):
        out={}
        for r in rows:
            k=r['掉落ID']
            if not k or k in out: raise ValueError(f'{kind}: duplicate/empty node {k!r}')
            out[k]=r
        return out
    trees,leaves=index(tree,'tree'),index(leaf,'leaf')
    if trees.keys() & leaves.keys(): raise ValueError('Tree/leaf ID collision')
    nodes={**trees,**leaves}
    roots={r['掉落ID'] for r in later}

    def signature(root):
        cache={}
        visiting=set()
        reached=set()
        def expand(node_id):
            row=nodes.get(node_id)
            if row is None: return ('unverified-terminal',node_id)
            if node_id in visiting: raise ValueError(f'cycle at {node_id}')
            if node_id in cache: return cache[node_id]
            visiting.add(node_id)
            reached.add(node_id)
            edges=[]
            for i in range(1,31):
                child=row.get(f'子掉落{i}ID','')
                if child:
                    edges.append((row.get(f'子掉落{i}数量区间',''),
                                  row.get(f'子掉落{i}权重',''),expand(child)))
            result=(row.get('随机方式',''),row.get('掉落层级',''),
                    row.get('节点类型',''),row.get('是否掉落地面',''),
                    row.get('产出来源类型',''),edges)
            visiting.remove(node_id)
            cache[node_id]=result
            return result
        value=json.dumps(expand(root),ensure_ascii=False,separators=(',',':'))
        return hashlib.sha256(value.encode()).hexdigest(),len(reached)

    sample=[]
    for level in ('1','26'):
        pair=[]
        for tag in ('战斗低级蒙德','解谜低级蒙德'):
            matches=[r for r in later if r['最小等级']==level and r['总索引']==tag]
            if len(matches)!=1: raise ValueError(f'expected one {tag} at level {level}')
            root=matches[0]['掉落ID']
            digest,count=signature(root)
            pair.append({'tag':tag,'root':root,'nodeCount':count,'expandedHistoricalGraphSha256':digest})
        sample.append({'minLevel':int(level),'combat':pair[0],'puzzle':pair[1],
                       'sameExpandedHistoricalGraph':pair[0]['expandedHistoricalGraphSha256']==pair[1]['expandedHistoricalGraphSha256']})
    return {'treeRows':len(tree),'leafRows':len(leaf),'uniqueHistoricalRoots':len(roots),
            'rootsInTree':len(roots & trees.keys()),'rootsInLeaf':len(roots & leaves.keys()),
            'rootsAbsentFromBoth':sorted(roots-nodes.keys()),
            'sample':sample,'terminalItemIdentityValidated':False,'native71Verified':False}



def compare_selected_roots(older, newer, comparable_columns, selection):
    """Audit direct historical tree rows; no official 7.1 payout claim."""
    from collections import Counter

    chosen = {}
    seen_sources = set()
    for item in selection:
        if not isinstance(item, dict) or not all(k in item for k in ('root', 'tag', 'level')):
            raise ValueError('Selected root entry requires root/tag/level')
        ident = str(item['root'])
        if not ident.isdecimal() or int(ident) <= 0:
            raise ValueError(f'Invalid selected root ID: {ident}')
        source_key = (str(item['tag']), int(item['level']))
        if source_key in seen_sources:
            raise ValueError(f'Duplicate source tag/level: {source_key}')
        seen_sources.add(source_key)
        chosen.setdefault(ident, []).append(source_key)

    shared = sorted((k for k in chosen if k in older and k in newer), key=int)
    older_only = sorted((k for k in chosen if k in older and k not in newer), key=int)
    newer_only = sorted((k for k in chosen if k in newer and k not in older), key=int)
    neither = sorted((k for k in chosen if k not in older and k not in newer), key=int)
    deltas = {
        k: [c for c in sorted(comparable_columns) if older[k][c] != newer[k][c]]
        for k in shared
    }
    fields = Counter(c for k in shared for c in deltas[k])
    examples = []
    for ident in ('51010000', '51010500', '52010000', '52010500'):
        if ident in deltas:
            examples.append({
                'root': int(ident), 'changeCount': len(deltas[ident]),
                'changes': [
                    {'field': c, 'earlier': older[ident][c], 'later': newer[ident][c]}
                    for c in deltas[ident][:12]
                ],
            })
    return {
        'selectedSourceRows': len(selection),
        'distinctSelectedRoots': len(chosen),
        'sharedRoots': len(shared),
        'sharedRootsChanged': sum(bool(v) for v in deltas.values()),
        'sharedRootsUnchanged': sum(not v for v in deltas.values()),
        'earlierOnlyRoots': len(older_only), 'laterOnlyRoots': len(newer_only),
        'absentInBothTrees': len(neither),
        'absentInBothIds': [int(x) for x in neither],
        'changedFieldCounts': dict(sorted(fields.items())),
        'examples': examples,
        'evidenceClass': 'historical-server-compatibility',
        'native71Verified': False,
    }

def compare_tree_revisions(earlier, later, selected_roots=None):
    """Compare matching drop IDs using shared column names."""
    def indexed(rows, name):
        out = {}
        for row in rows:
            key = row['掉落ID']
            if not key or key in out:
                raise ValueError(f'{name}: duplicate or missing drop ID {key!r}')
            out[key] = row
        return out
    old, new = indexed(earlier, 'older'), indexed(later, 'newer')
    shared = old.keys() & new.keys()
    columns = set(earlier[0]) & set(later[0]) if earlier and later else set()
    payload = columns - {'产出来源类型'}
    count = sum(any(old[k][c] != new[k][c] for c in payload) for k in shared)
    sources = sum(old[k]['产出来源类型'] != new[k]['产出来源类型'] for k in shared)
    sample = {}
    if '51010500' in shared:
        sample = {c: {'older': old['51010500'].get(c), 'newer': new['51010500'].get(c)}
                  for c in ('子掉落1ID', '子掉落1数量区间')}
    result = {'olderRows': len(earlier), 'newerRows': len(later),
            'sharedDropIds': len(shared), 'changedPayloadOrStructure': count,
            'changedSourceType': sources, 'unchangedPayloadOrStructure': len(shared)-count,
            'example51010500': sample, 'native71Verified': False}
    if selected_roots is not None:
        result['selectedRoots'] = compare_selected_roots(old, new, payload, selected_roots)
    return result

def main():
    p=argparse.ArgumentParser(description=__doc__)
    names=('early','historical','arrangement','tree','leaf')
    for n in names:
        p.add_argument('--'+n,type=Path,required=True)
        p.add_argument('--'+n+'-blob')
    p.add_argument('--early-tree', type=Path)
    p.add_argument('--early-tree-blob')
    p.add_argument('--selected-roots', type=Path, help='JSON historical selector rows, requires --early-tree')
    p.add_argument('--detail-output',type=Path,help='Write complete early-vs-later delta to a JSON file')
    args=p.parse_args()
    paths={n:getattr(args,n) for n in names}
    blobs={n:git_blob(path) for n,path in paths.items()}
    for n in names:
        expected=getattr(args,n+'_blob')
        if expected and expected!=blobs[n]:
            p.error(f'{n} Git blob mismatch: expected {expected}, got {blobs[n]}')
    earlier=tsv(args.early,EARLY_COLUMNS)
    historical=tsv(args.historical,EARLY_COLUMNS+('类别',))
    limits=tsv(args.arrangement,ARRANGEMENT_COLUMNS)
    result={'earlierComparison':historical_pairs(earlier,historical),
            'tagArrangement':arrangement_audit(historical,limits),
            'dropTables':table_audit(historical,tsv(args.tree),tsv(args.leaf)),
            'gitBlobs':blobs,
            'sha256':{n:hashlib.sha256(path.read_bytes()).hexdigest() for n,path in paths.items()},
            'original71Authority':'UNRESOLVED'}
    if args.selected_roots and not args.early_tree:
        p.error('--selected-roots requires --early-tree')
    if args.early_tree:
        earlier_sha=git_blob(args.early_tree)
        if args.early_tree_blob and earlier_sha!=args.early_tree_blob:
            p.error('early-tree Git blob mismatch')
        selected = None
        if args.selected_roots:
            selected = json.loads(args.selected_roots.read_text(encoding='utf-8-sig'))
            if not isinstance(selected, list):
                p.error('--selected-roots must be a JSON array')
        result['earlierTreeRevision']=compare_tree_revisions(tsv(args.early_tree),tsv(args.tree),selected)
        if selected is not None:
            result['selectedRootsSha256']=hashlib.sha256(args.selected_roots.read_bytes()).hexdigest()
        result['gitBlobs']['earlierTree']=earlier_sha
        result['sha256']['earlierTree']=hashlib.sha256(args.early_tree.read_bytes()).hexdigest()
    elif args.early_tree_blob:
        p.error('--early-tree-blob requires --early-tree')
    if args.detail_output:
        details={
            'historicalDelta':historical_pairs(earlier,historical,full=True),
            'gitBlobs':result['gitBlobs'],
            'sha256':result['sha256'],
            'original71Authority':'UNRESOLVED'
        }
        args.detail_output.parent.mkdir(parents=True,exist_ok=True)
        args.detail_output.write_text(json.dumps(details,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(result,ensure_ascii=False,indent=2))

if __name__=='__main__':
    main()
