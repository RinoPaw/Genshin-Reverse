from __future__ import annotations
import argparse,json
from collections import Counter,defaultdict
from pathlib import Path
from typing import Any

def load(root: Path, raw: bool):
    rows={}
    for p in root.glob("*.json"):
        try:o=json.loads(p.read_text(encoding="utf-8"))
        except Exception:continue
        if not isinstance(o,dict):continue
        seq=o.get("JIJKODHIEED" if raw else "subQuests",[])
        if not isinstance(seq,list):continue
        for r in seq:
            if not isinstance(r,dict):continue
            sid=r.get("NFGFDHPPBIF" if raw else "subId")
            if isinstance(sid,int): rows[sid]=r
    return rows

def flat(r: dict[str,Any], raw: bool):
    out={}
    guide_key="HINHMGGLBBM" if raw else "guide"
    sid_key="NFGFDHPPBIF" if raw else "subId"
    for k,v in r.items():
        if k==sid_key: continue
        if k==guide_key and isinstance(v,dict):
            for gk,gv in v.items(): out[f"guide.{gk}"]=gv
        else: out[f"sub.{k}"]=v
    return out

def js(v): return json.dumps(v,ensure_ascii=False,sort_keys=True,separators=(",",":"))

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("raw71",type=Path)
    ap.add_argument("community71",type=Path)
    ap.add_argument("--output",type=Path,required=True)
    args=ap.parse_args()
    a=load(args.raw71,True); b=load(args.community71,False)
    common=sorted(set(a)&set(b))
    stats=defaultdict(lambda:{"present":0,"types":Counter(),"values":Counter(),"cand":defaultdict(Counter),"presence":set()})
    old_presence=defaultdict(set)
    for sid in common:
        fa=flat(a[sid],True); fb=flat(b[sid],False)
        for ok in fb: old_presence[ok].add(sid)
        for k,v in fa.items():
            s=stats[k]; s["present"]+=1; s["types"][type(v).__name__]+=1;s["values"][js(v)]+=1;s["presence"].add(sid)
            for ok,ov in fb.items():
                c=s["cand"][ok]; c["compared"]+=1
                if js(v)==js(ov): c["exact"]+=1
    report={"raw_rows":len(a),"community_rows":len(b),"common_rows":len(common),"fields":{}}
    for k,s in sorted(stats.items()):
        candidates=[]
        for ok,c in s["cand"].items():
            if c["exact"]:
                candidates.append({"field":ok,"exact":c["exact"],"compared":c["compared"],"ratio":c["exact"]/c["compared"]})
        candidates.sort(key=lambda x:(-x["ratio"],-x["exact"],x["field"]))
        pres=[]
        ps=s["presence"]
        for ok,ops in old_presence.items():
            inter=len(ps&ops); union=len(ps|ops)
            if inter:
                pres.append({"field":ok,"intersection":inter,"jaccard":inter/union,"current_covered":inter/len(ps),"community_covered":inter/len(ops)})
        pres.sort(key=lambda x:(-x["jaccard"],-x["intersection"],x["field"]))
        report["fields"][k]={
            "present":s["present"],"types":dict(s["types"]),"top_values":s["values"].most_common(8),
            "exact_candidates":candidates[:20],"presence_candidates":pres[:20],
        }
    args.output.write_text(json.dumps(report,ensure_ascii=False,indent=2)+"\n",encoding="utf-8")
    for k,x in report["fields"].items():
        leaf=k.split(".")[-1]
        if not (leaf.isupper() or len(leaf)==11): continue
        print("\n==",k,"present",x["present"],"types",x["types"],"==")
        print("top",x["top_values"][:5])
        print("exact",x["exact_candidates"][:8])
        print("presence",x["presence_candidates"][:5])
    return 0
if __name__=="__main__": raise SystemExit(main())
