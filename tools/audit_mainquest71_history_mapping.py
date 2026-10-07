from __future__ import annotations
import argparse, json
from collections import defaultdict
from pathlib import Path
from typing import Any

TARGETS = {
    "AFEAMKOGMBF","AHBDGODKBDF","DJADGDCICCB","FEBBDBPEFCE","HGDMKDGAJOM",
    "HGFFNBIGPJK","IACKBAAICMK","IBIILFJEHBC","IMGDIONBDMG","INFDFLBGLPD",
    "KJBJDKALING","KJOHNNANDBK","LCBNMMFPDFH","LLHHDHNBAGG","MNPJPMCNIIP",
}
IGNORE = {"id","subQuests","talks","dialogList"}

def load(root: Path) -> dict[int,dict[str,Any]]:
    out={}
    for p in root.glob("*.json"):
        try:o=json.loads(p.read_text(encoding="utf-8"))
        except Exception:continue
        if isinstance(o,dict) and isinstance(o.get("id"),int):
            out[o["id"]]=o
    return out

def canon(v:Any)->str:
    return json.dumps(v,ensure_ascii=False,sort_keys=True,separators=(",",":"))

def main()->int:
    ap=argparse.ArgumentParser()
    ap.add_argument("raw71",type=Path)
    ap.add_argument("sources",nargs="+",help="name=directory")
    ap.add_argument("--output",type=Path,required=True)
    args=ap.parse_args()
    raw=load(args.raw71)
    srcs={}
    for spec in args.sources:
        name,path=spec.split("=",1)
        srcs[name]=load(Path(path))
    rep={"raw_rows":len(raw),"sources":{},"fields":{}}
    for name,rows in srcs.items():
        rep["sources"][name]={"rows":len(rows),"common":len(set(raw)&set(rows))}
    for f in sorted(TARGETS):
        cur_ids={qid for qid,o in raw.items() if f in o}
        cand=defaultdict(lambda:defaultdict(int))
        examples=defaultdict(list)
        for name,rows in srcs.items():
            for qid in cur_ids & rows.keys():
                rv=raw[qid][f]; h=rows[qid]
                for hk,hv in h.items():
                    if hk in IGNORE: continue
                    cand[name][hk]+=1 if canon(rv)==canon(hv) else 0
                    if canon(rv)==canon(hv) and len(examples[(name,hk)])<5:
                        examples[(name,hk)].append({"id":qid,"value":rv})
        per={}
        combined=defaultdict(int)
        for name,rows in srcs.items():
            common=len(cur_ids & rows.keys())
            vals=[]
            for hk,exact in cand[name].items():
                if exact:
                    vals.append({"field":hk,"exact":exact,"current_present_with_source":common,
                                 "ratio": exact/common if common else 0.0})
                    combined[hk]+=exact
            vals.sort(key=lambda x:(-x["ratio"],-x["exact"],x["field"]))
            per[name]=vals[:20]
        comb=sorted(({"field":k,"exact_sum":v} for k,v in combined.items()),
                    key=lambda x:(-x["exact_sum"],x["field"]))
        rep["fields"][f]={"present71":len(cur_ids),"by_source":per,"combined":comb[:30],
                          "examples":{f"{a}:{b}":v for (a,b),v in examples.items()}}
    args.output.write_text(json.dumps(rep,ensure_ascii=False,indent=2)+"\n",encoding="utf-8")
    for f,x in rep["fields"].items():
        print("\n==",f,"present",x["present71"],"==")
        for name,vals in x["by_source"].items():
            print(name,[(v["field"],v["exact"],round(v["ratio"],4)) for v in vals[:8]])
    return 0

if __name__=="__main__": raise SystemExit(main())
