#!/usr/bin/env python3
"""Historical chest drop-ID coverage and combat/puzzle graph comparison.

Reads authored scene gadgets and version-pinned AstaPS-Resource tables.
The server tables predate native 7.1; graph identity does not prove item rates.
Read-only by default. This is not a source of official 7.1 probabilities.
"""
import argparse
import collections
import hashlib
import json
import re
from pathlib import Path

DEFAULT_ROOTS = Path(__file__).resolve().parents[1] / "versions/7.1.0-global/analyses/progression/economy/7.1-historical-chest-native-roots.json"
SCENES=(1,3,4,5,6,7,9,10,11)
GADGET=re.compile(r"\bgadget_id\s*=\s*(\d+)")
TAG=re.compile(r'\bdrop_tag\s*=\s*["\x27]([^"\x27]+)["\x27]')
CHEST_DROP=re.compile(r"\bchest_drop_id\s*=\s*(\d+)")
DROP=re.compile(r"\bdrop_id\s*=\s*(\d+)")
LEVEL=re.compile(r"\blevel\s*=\s*(\d+)")
AID=re.compile(r"\barea_id\s*=\s*(\d+)")
PREFAB=re.compile(r"^SceneObj_Chest_(?:(?:Default|Locked|Bramble|Frozen)_Lv[1245](?:_(?:UnderWater|AboveWater|Amphibious|V70|RemusLanternFish|FollowMove))?|Rock_Lv1)$")
TAG_PARTS=re.compile(r"^(雪山)?(解谜|战斗)(低级|中级|高级|超级)(.*)$")
NAMES={1:"蒙德",2:"璃月",3:"稻妻",4:"须弥",5:"枫丹",6:"纳塔",7:"挪德卡莱",8:"至冬",9:"至冬",99:"璃月",100:"璃月",101:"璃月",102:"璃月",103:"璃月",104:"璃月"}
def get_int(regex,line):
    match=regex.search(line)
    return int(match.group(1)) if match else 0
def run(resource_root: Path, roots_path: Path, output: Path | None = None):
    BASE = resource_root
    city=json.loads((BASE/"ExcelBinOutput/CityConfigData.json").read_text())
    area_region={a:NAMES[row["cityId"]] for row in city if row.get("cityId") in NAMES for a in row.get("areaIdVec",[])}
    gadgets={g["id"]:g for g in json.loads((BASE/"ExcelBinOutput/GadgetExcelConfigData.json").read_text()) if "id" in g}
    rows=collections.Counter()
    examples=collections.defaultdict(list)
    roots_by_region=collections.defaultdict(collections.Counter)
    drop_ids=collections.defaultdict(collections.Counter)
    for scene in SCENES:
        for file in (BASE/f"Scripts/Scene/{scene}").glob(f"scene{scene}_group*.lua"):
            for line in file.read_text(encoding="utf-8",errors="replace").splitlines():
                if "gadget_id" not in line:continue
                gid=get_int(GADGET,line)
                kind=gadgets.get(gid,{}).get("jsonName","")
                if not PREFAB.fullmatch(kind):continue
                tag_match=TAG.search(line)
                tag=tag_match.group(1) if tag_match else ""
                chest_id=get_int(CHEST_DROP,line)
                other_id=get_int(DROP,line)
                area=get_int(AID,line)
                region=("群岛" if scene in (4,9) else "稻妻" if scene==7 and area==210
                        else area_region.get(area) or "missing_area_id")
                if chest_id not in (0,1000100):
                    source="explicit_chest_id"
                elif other_id not in (0,1000100):
                    source="explicit_drop_id"
                elif chest_id==1000100 or other_id==1000100:
                    source="empty_sentinel"
                else:
                    source="no_drop_id"
                tag_state="tag" if tag else "no_tag"
                rows[(region,tag_state,source)]+=1
                if tag:roots_by_region[region]["tagged"]+=1
                if not tag:roots_by_region[region]["untagged"]+=1
                if source.startswith("explicit"):
                    explicit_id=chest_id if chest_id not in (0,1000100) else other_id
                    drop_ids[region][explicit_id]+=1
                if len(examples[(region,tag_state,source)])<4:
                    examples[(region,tag_state,source)].append(
                        {"scene":scene,"path":str(file.relative_to(BASE)),
                         "config":get_int(re.compile(r"\bconfig_id\s*=\s*(\d+)"),line),
                         "gadget":gid,"prefab":kind,"level":get_int(LEVEL,line),
                         "area_id":area,"tag":tag,"chest_drop_id":chest_id,"drop_id":other_id})
    print("NATIVE_CHEST_SOURCE_COUNTS", json.dumps(
        [{"region":r,"tag":t,"source":s,"count":count} for (r,t,s),count in sorted(rows.items())],
        ensure_ascii=False), flush=True)

    tabs={}
    row_counts={}
    dup=collections.Counter()
    for name in ("DropTableExcelConfigData.json","DropSubTableExcelConfigData.json"):
        entries=json.loads((BASE/"Server"/name).read_text(encoding="utf-8"))
        row_counts[name]=len(entries)
        print("NATIVE_TABLE_FORMAT",name,{"records":len(entries),"sample":entries[:2]},flush=True)
        for item in entries:
            key=item.get("id")
            if not isinstance(key,int):continue
            if key in tabs:
                dup[key]+=1
            tabs[key]=item
    missing=set()
    mem={}
    cycles=set()
    def digest(id_,stack=()):
        if id_ in mem:return mem[id_]
        if id_ in stack:
            cycles.add(id_);return f"CYCLE:{id_}"
        entry=tabs.get(id_)
        if entry is None:
            missing.add(id_);return None
        edges=[]
        for drop in entry.get("dropVec",[]) or []:
            item_id=drop.get("itemId")
            if not isinstance(item_id,int) or item_id==0:continue
            value=digest(item_id,stack+(id_,)) if item_id in tabs else None
            edges.append([value if value is not None else ["item",item_id],
                          drop.get("countRange"),drop.get("weight")])
        key=json.dumps([entry.get("randomType",0),entry.get("fallToGround",False),edges],
                       ensure_ascii=False,separators=(",",":"))
        fingerprint=hashlib.sha256(key.encode("utf-8")).hexdigest()
        mem[id_]=fingerprint
        return fingerprint
    roots=json.loads(roots_path.read_text(encoding="utf-8"))
    groups=collections.defaultdict(dict)
    for s in roots:
        m=TAG_PARTS.match(s["tag"])
        if not m:continue
        key=(bool(m.group(1)),m.group(3),m.group(4),s["level"])
        groups[key][m.group(2)]=s["root"]
    compared=[]
    for key,nodes in sorted(groups.items()):
        if "战斗" not in nodes or "解谜" not in nodes:continue
        a,b=nodes["战斗"],nodes["解谜"]
        f1,f2=digest(a),digest(b)
        compared.append({"snow":key[0],"quality":key[1],"region":key[2],"level":key[3],
                         "combatRoot":a,"puzzleRoot":b,
                         "sameGraph":f1==f2 and f1 is not None,
                         "combatKnown":f1 is not None,"puzzleKnown":f2 is not None})
    # Measure historical server tables without claiming 7.1-native provenance.
    native_roots={entry["root"] for entry in roots}
    root_nodes=set()
    terminal_ids=set()
    root_with_empty_vec=set()
    random_types=collections.Counter()
    count_examples=collections.Counter()
    node_types=collections.Counter()
    def traverse(node_id,visited):
        if node_id in visited or node_id not in tabs:return
        visited.add(node_id)
        root_nodes.add(node_id)
        row=tabs[node_id]
        node_types[row.get("nodeType",0)]+=1
        random_types[row.get("randomType",0)]+=1
        for v in row.get("dropVec",[]) or []:
            if not isinstance(v.get("itemId"),int):continue
            child=v["itemId"]
            count_examples[str(v.get("countRange"))]+=1
            if child in tabs:traverse(child,visited)
            elif child>0:terminal_ids.add(child)
    for root in native_roots:
        if root in tabs and not tabs[root].get("dropVec"):root_with_empty_vec.add(root)
        traverse(root,set())
    candidate_families=collections.Counter()
    for node_id in tabs:
        if 50000000<=node_id<55000000:
            candidate_families[str(node_id//1000000)]+=1
    # Show small source-authored rows: inspect differences before calling them
    # distinct item probabilities, which requires executing their nested graphs.
    chosen_tags=["战斗低级蒙德","解谜低级蒙德","战斗中级蒙德",
                 "解谜中级蒙德","战斗低级璃月","解谜低级璃月",
                 "战斗低级稻妻","解谜低级稻妻",
                 "战斗低级须弥","解谜低级须弥"]
    first_source={}
    for src in roots:
        if src["tag"] in chosen_tags and (src["tag"] not in first_source or
                                          src["level"]<first_source[src["tag"]]["level"]):
            first_source[src["tag"]]=src
    native_samples=[]
    for tag,source in sorted(first_source.items()):
        table=tabs.get(source["root"])
        native_samples.append({"tag":tag,**source,"randomType":table.get("randomType"),
            "nodeType":table.get("nodeType"),"dropVec":table.get("dropVec",[])[:40],
            "dropVecCount":len(table.get("dropVec",[]))} if table else {"tag":tag,**source,"missing":True})
    explicit_id_count=sum(sum(counter.values()) for counter in drop_ids.values())
    explicit_id_present=sum(n for counter in drop_ids.values() for id_,n in counter.items()
                            if id_ in tabs)
    explicit_id_nonempty=sum(n for counter in drop_ids.values() for id_,n in counter.items()
                             if id_ in tabs and tabs[id_].get("dropVec"))
    native_graph_summary={
        "fileRows":{"DropTable":row_counts["DropTableExcelConfigData.json"],
                    "DropSubTable":row_counts["DropSubTableExcelConfigData.json"]},
        "taggedSourceEntries":len(roots),"uniqueTaggedRoots":len(native_roots),
        "rootRowsPresent":sum(root in tabs for root in native_roots),
        "emptyRootRows":len(root_with_empty_vec),
        "reachableTableNodes":len(root_nodes),"reachableTerminalIds":len(terminal_ids),
        "terminalIdExamples":sorted(terminal_ids)[:80],
        "randomTypes":dict(random_types),
        "nodeTypes":dict(node_types),
        "countRangeMostCommon":count_examples.most_common(20),
        "candidate51to54millionFamilies":dict(candidate_families),
        "explicitSourceTotal":explicit_id_count,
        "explicitSourceIdPresent":explicit_id_present,
        "explicitSourceIdWithNonemptyTable":explicit_id_nonempty,
        "examples":native_samples,
        "warning":"DropTable is server resource, not proven current-client native reward roll. IDs matching family pattern alone do not establish scene linkage."
    }
    results={
        "nativeGraphSummary":native_graph_summary,
        "sourceCounts":[{"region":r,"tag":t,"source":s,"count":count} for (r,t,s),count in sorted(rows.items())],
        "pairedRoots":compared,
        "pairStats":{"total":len(compared),"same":sum(x["sameGraph"] for x in compared),
                     "different":sum(not x["sameGraph"] for x in compared)},
        "rootsMissing":sorted(missing)[:80],"nodeCycles":sorted(cycles)[:30],
        "duplicateTableIds":len(dup),
        "regionRootCoverage":{k:dict(v) for k,v in roots_by_region.items()},
        "examples":[{"region":r,"tag":t,"source":s,"items":samples}
                    for (r,t,s),samples in sorted(examples.items())],
        "explicitDropIdTop":{k:v.most_common(15) for k,v in drop_ids.items()},
    }
    if output is not None:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(results, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print("NATIVE_SOURCE_AUDIT_JSON_BEGIN",flush=True)
    print(json.dumps(results,ensure_ascii=False,separators=(",",":")),flush=True)
    print("NATIVE_SOURCE_AUDIT_JSON_END",flush=True)
    return results


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--resource-root", required=True, type=Path, help="Checked-out AstaPS-Resource root")
    parser.add_argument("--roots", type=Path, default=DEFAULT_ROOTS, help="Pinned historical tag/level/root snapshot")
    parser.add_argument("--output", type=Path, help="Write JSON outside resource tree; stdout always reports results")
    args = parser.parse_args()
    run(args.resource_root, args.roots, args.output)

