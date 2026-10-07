from __future__ import annotations
import argparse,json
from collections import Counter,defaultdict
from pathlib import Path
from typing import Any

def load(root:Path):
    out={}
    for p in root.glob("*.json"):
        try:o=json.loads(p.read_text(encoding="utf-8"))
        except Exception:continue
        if isinstance(o,dict) and isinstance(o.get("id"),int):out[o["id"]]=o
    return out

def js(v):return json.dumps(v,ensure_ascii=False,sort_keys=True,separators=(",",":"))

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("raw",type=Path);ap.add_argument("community",type=Path)
    ap.add_argument("--output",type=Path,required=True)
    args=ap.parse_args()
    a=load(args.raw);b=load(args.community);common=sorted(set(a)&set(b))
    stats=defaultdict(lambda:{"present":0,"types":Counter(),"values":Counter(),"cand":defaultdict(Counter),"presence":set()})
    bp=defaultdict(set)
    for qid in common:
        ra=a[qid]; rb=b[qid]
        for k in rb:
            if k!="id":bp[k].add(qid)
        for k,v in ra.items():
            if k=="id":continue
            s=stats[k];s["present"]+=1;s["types"][type(v).__name__]+=1;s["values"][js(v)]+=1;s["presence"].add(qid)
            for bk,bv in rb.items():
                if bk=="id":continue
                c=s["cand"][bk];c["compared"]+=1
                if js(v)==js(bv):c["exact"]+=1
    rep={"raw_files":len(a),"community_files":len(b),"common":len(common),"fields":{}}
    for k,s in sorted(stats.items()):
        exact=[]
        for bk,c in s["cand"].items():
            if c["exact"]:
                exact.append({"field":bk,"exact":c["exact"],"compared":c["compared"],"ratio":c["exact"]/c["compared"]})
        exact.sort(key=lambda x:(-x["ratio"],-x["exact"],x["field"]))
        presence=[]
        ps=s["presence"]
        for bk,bs in bp.items():
            inter=len(ps&bs)
            if not inter:continue
            union=len(ps|bs)
            presence.append({"field":bk,"intersection":inter,"jaccard":inter/union,
                             "raw_covered":inter/len(ps),"community_covered":inter/len(bs)})
        presence.sort(key=lambda x:(-x["jaccard"],-x["intersection"],x["field"]))
        rep["fields"][k]={"present":s["present"],"types":dict(s["types"]),
                          "top_values":s["values"].most_common(8),
                          "exact_candidates":exact[:20],"presence_candidates":presence[:15]}
    args.output.write_text(json.dumps(rep,ensure_ascii=False,indent=2)+"\n",encoding="utf-8")
    for k,x in rep["fields"].items():
        if not (len(k)==11 and k.upper()==k):continue
        print("\n==",k,"present",x["present"],"types",x["types"],"==")
        print("top",x["top_values"][:4])
        print("exact",x["exact_candidates"][:8])
        print("presence",x["presence_candidates"][:5])
    return 0
if __name__=="__main__":raise SystemExit(main())
