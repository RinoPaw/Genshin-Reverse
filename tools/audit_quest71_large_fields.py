from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


def load71(root: Path):
    rows={}
    for p in sorted(root.glob("*.json")):
        try:o=json.loads(p.read_text(encoding="utf-8"))
        except Exception:continue
        if not isinstance(o,dict):continue
        seq=o.get("JIJKODHIEED",[])
        if not isinstance(seq,list):continue
        for r in seq:
            if isinstance(r,dict) and isinstance(r.get("NFGFDHPPBIF"),int):
                rows[r["NFGFDHPPBIF"]]={"row":r,"file":p.stem}
    return rows


def load70(root: Path):
    rows={}
    for p in sorted(root.glob("*.json")):
        try:o=json.loads(p.read_text(encoding="utf-8"))
        except Exception:continue
        if not isinstance(o,dict):continue
        seq=o.get("subQuests",[])
        if not isinstance(seq,list):continue
        for r in seq:
            if isinstance(r,dict) and isinstance(r.get("subId"),int):
                rows[r["subId"]]={"row":r,"file":p.stem}
    return rows


def eq(a: Any,b: Any)->bool:
    return a==b


def sample(dst:list[dict[str,Any]], item:dict[str,Any], limit=40):
    if len(dst)<limit: dst.append(item)


def analyze_list_field(a,b,key71,candidates):
    st=Counter(); examples=defaultdict(list)
    for sid in sorted(set(a)&set(b)):
        r71=a[sid]["row"]; r70=b[sid]["row"]
        if key71 not in r71: continue
        v=r71[key71]; st["present71"]+=1
        present=[k for k in candidates if k in r70]
        if not present:
            st["no_candidate70"]+=1
            sample(examples["no_candidate70"],{"subId":sid,"main":a[sid]["file"],"value71":v})
            continue
        st["candidate70_any"]+=1
        for k in present:
            st[f"{k}.present"]+=1
            if eq(v,r70[k]):
                st[f"{k}.exact"]+=1
            else:
                st[f"{k}.different"]+=1
                sample(examples[f"{k}.different"],{
                    "subId":sid,"main":a[sid]["file"],"value71":v,"value70":r70[k],
                    "other70":{x:r70[x] for x in present if x!=k},
                })
        if len(present)>1:
            st["multiple_candidates_present"]+=1
            vals={k:json.dumps(r70[k],sort_keys=True,ensure_ascii=False) for k in present}
            if len(set(vals.values()))==1:
                st["multiple_candidates_equal"]+=1
            else:
                st["multiple_candidates_differ"]+=1
                matches=[k for k in present if eq(v,r70[k])]
                sample(examples["multiple_candidates_differ"],{
                    "subId":sid,"main":a[sid]["file"],"value71":v,
                    "values70":{k:r70[k] for k in present},"matches":matches,
                })
    return dict(st),dict(examples)


def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("raw71",type=Path)
    ap.add_argument("q70",type=Path)
    ap.add_argument("--output",type=Path,required=True)
    args=ap.parse_args()
    a=load71(args.raw71);b=load70(args.q70)

    fml=analyze_list_field(a,b,"FMLPOCDOFNH",["npcId","exclusiveNpcList","sharedNpcList"])
    nlik=analyze_list_field(a,b,"NLIKPBMIJJD",["exclusivePlaceList","HIABBDKJOHM"])

    report={
        "rows71":len(a),"rows70":len(b),"common":len(set(a)&set(b)),
        "FMLPOCDOFNH": {"stats":fml[0],"examples":fml[1]},
        "NLIKPBMIJJD": {"stats":nlik[0],"examples":nlik[1]},
    }
    args.output.write_text(json.dumps(report,ensure_ascii=False,indent=2)+"\n",encoding="utf-8")
    for key in ("FMLPOCDOFNH","NLIKPBMIJJD"):
        print("\n==",key,"==")
        print(json.dumps(report[key]["stats"],ensure_ascii=False,indent=2))
        for name,vals in report[key]["examples"].items():
            if vals:
                print("\n",name)
                print(json.dumps(vals[:10],ensure_ascii=False,indent=2))
    return 0

if __name__=="__main__":
    raise SystemExit(main())
