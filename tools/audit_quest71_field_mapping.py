from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

KNOWN_71_SUB = {
    "subId","mainId","order","descTextMapHash","showType","showGuide","guide",
    "isRewind","finishParent","finishCond","failCond","finishExec","failExec",
    "acceptCond","beginExec","finishCondComb","failCondComb","acceptCondComb",
}
KNOWN_71_GUIDE = {"type","param","guideScene","guideStyle","guideLayer"}

def load_rows(root: Path) -> dict[int, dict[str, Any]]:
    out={}
    for p in sorted(root.glob("*.json")):
        try:o=json.loads(p.read_text(encoding="utf-8"))
        except Exception:continue
        if not isinstance(o,dict):continue
        seq=o.get("subQuests")
        if not isinstance(seq,list):continue
        for r in seq:
            if isinstance(r,dict) and isinstance(r.get("subId"),int):
                out[r["subId"]]=r
    return out

def canon(v: Any) -> Any:
    if isinstance(v,dict):
        return {k:canon(x) for k,x in sorted(v.items())}
    if isinstance(v,list):
        return [canon(x) for x in v]
    return v

def j(v: Any) -> str:
    return json.dumps(canon(v),ensure_ascii=False,sort_keys=True,separators=(",",":"))

def unknown_paths(row: dict[str,Any]) -> dict[str,Any]:
    out={}
    for k,v in row.items():
        if k not in KNOWN_71_SUB:
            out[f"sub.{k}"]=v
    g=row.get("guide")
    if isinstance(g,dict):
        for k,v in g.items():
            if k not in KNOWN_71_GUIDE:
                out[f"guide.{k}"]=v
    return out

def old_paths(row: dict[str,Any]) -> dict[str,Any]:
    out={f"sub.{k}":v for k,v in row.items() if k!="guide"}
    g=row.get("guide")
    if isinstance(g,dict):
        out.update({f"guide.{k}":v for k,v in g.items()})
    return out

def main() -> int:
    ap=argparse.ArgumentParser()
    ap.add_argument("q71",type=Path)
    ap.add_argument("q70",type=Path)
    ap.add_argument("--output",type=Path,required=True)
    args=ap.parse_args()

    a=load_rows(args.q71); b=load_rows(args.q70)
    common=sorted(set(a)&set(b))
    stats=defaultdict(lambda: {
        "present":0,
        "types":Counter(),
        "values":Counter(),
        "candidates":defaultdict(lambda: Counter()),
    })

    for sid in common:
        ua=unknown_paths(a[sid])
        ob=old_paths(b[sid])
        for path,val in ua.items():
            s=stats[path]; s["present"]+=1
            s["types"][type(val).__name__]+=1
            s["values"][j(val)]+=1
            vj=j(val)
            for op,ov in ob.items():
                c=s["candidates"][op]
                c["compared"]+=1
                if vj==j(ov): c["exact"]+=1
                if op in ob: c["old_present"]+=1

    report={
        "rows_71":len(a),"rows_70":len(b),"common_rows":len(common),
        "fields":{}
    }
    for path,s in sorted(stats.items()):
        cands=[]
        for op,c in s["candidates"].items():
            if not c["exact"]: continue
            cands.append({
                "field":op,
                "exact":c["exact"],
                "compared":c["compared"],
                "exact_ratio":c["exact"]/c["compared"] if c["compared"] else 0,
            })
        cands.sort(key=lambda x:(-x["exact_ratio"],-x["exact"],x["field"]))
        report["fields"][path]={
            "present":s["present"],
            "types":dict(s["types"]),
            "top_values":s["values"].most_common(12),
            "exact_candidates":cands[:20],
        }

    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(json.dumps(report,ensure_ascii=False,indent=2)+"\n",encoding="utf-8")

    print("ROWS",report["rows_71"],report["rows_70"],report["common_rows"])
    for path,info in report["fields"].items():
        best=info["exact_candidates"][:5]
        print("\n",path,"present",info["present"],"types",info["types"])
        print("top",info["top_values"][:5])
        print("best",best)
    return 0

if __name__=="__main__":
    raise SystemExit(main())
