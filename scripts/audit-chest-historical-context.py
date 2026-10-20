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

def historical_pairs(early, later):
    def keyed(rows,label):
        out={}
        for row in rows:
            k=(row['最小等级'],row['总索引'])
            if k in out: raise ValueError(f'{label} duplicate level/tag: {k}')
            out[k]=row
        return out
    a,b=keyed(early,'early'),keyed(later,'later')
    common=a.keys() & b.keys()
    equal={k for k in common if (a[k]['掉落ID'],a[k]['掉落次数'])==(b[k]['掉落ID'],b[k]['掉落次数'])}
    different=sorted(common-equal)
    return {
        'earlierRows':len(early),'laterRows':len(later),
        'sameLevelAndTag':len(common),'sameRootAndCount':len(equal),
        'differentRootOrCount':len(different),
        'earlierOnlyKeys':len(a.keys()-b.keys()),'laterOnlyKeys':len(b.keys()-a.keys()),
        'changedExamples':[{'level':level,'tag':tag,'earlierRoot':a[(level,tag)]['掉落ID'],
                            'laterRoot':b[(level,tag)]['掉落ID']} for level,tag in different[:12]],
        'sourceTypeComparable':False,
        'note':'Source type is differently encoded in five-/six-column copies; do not equate codes.'
    }

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

def main():
    p=argparse.ArgumentParser(description=__doc__)
    names=('early','historical','arrangement','tree','leaf')
    for n in names:
        p.add_argument('--'+n,type=Path,required=True)
        p.add_argument('--'+n+'-blob')
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
    print(json.dumps(result,ensure_ascii=False,indent=2))

if __name__=='__main__':
    main()
