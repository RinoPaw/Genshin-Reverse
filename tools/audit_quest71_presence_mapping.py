from __future__ import annotations
import argparse,json
from collections import defaultdict
from pathlib import Path
from typing import Any

KNOWN71={
"subId","mainId","order","descTextMapHash","showType","showGuide","guide","isRewind","finishParent",
"finishCond","failCond","finishExec","failExec","acceptCond","beginExec","finishCondComb","failCondComb","acceptCondComb",
"guideHint","isMpBlock","subIdSet","sharedNpcList","stepDescTextMapHash","guideTipsTextMapHash","banType",
}

def load71(root):
 out={}
 for p in Path(root).glob("*.json"):
  try:o=json.loads(p.read_text(encoding="utf-8"))
  except:continue
  for r in o.get("JIJKODHIEED",[]) if isinstance(o,dict) else []:
   if isinstance(r,dict) and isinstance(r.get("NFGFDHPPBIF"),int): out[r["NFGFDHPPBIF"]]=r
 return out

def load70(root):
 out={}
 for p in Path(root).glob("*.json"):
  try:o=json.loads(p.read_text(encoding="utf-8"))
  except:continue
  for r in o.get("subQuests",[]) if isinstance(o,dict) else []:
   if isinstance(r,dict) and isinstance(r.get("subId"),int): out[r["subId"]]=r
 return out

def flat71(r):
 d={}
 for k,v in r.items():
  if k=="HINHMGGLBBM" and isinstance(v,dict):
   for gk,gv in v.items(): d["guide."+gk]=gv
  elif k not in {"NFGFDHPPBIF"}: d["sub."+k]=v
 return d

def flat70(r):
 d={}
 for k,v in r.items():
  if k=="guide" and isinstance(v,dict):
   for gk,gv in v.items(): d["guide."+gk]=gv
  elif k!="subId": d["sub."+k]=v
 return d

def main():
 ap=argparse.ArgumentParser();ap.add_argument("raw71",type=Path);ap.add_argument("q70",type=Path);ap.add_argument("--output",type=Path,required=True)
 a=load71(ap.parse_args().raw71)
 args=ap.parse_args()
 b=load70(args.q70)
 common=set(a)&set(b)
 pa=defaultdict(set);pb=defaultdict(set);types=defaultdict(set)
 for sid in common:
  for k,v in flat71(a[sid]).items(): pa[k].add(sid);types[k].add(type(v).__name__)
  for k,v in flat70(b[sid]).items(): pb[k].add(sid)
 unknown=[]
 known_raw={"sub.NFGFDHPPBIF"}
 # include only obfuscated-looking/current unresolved paths
 for k,s in pa.items():
  leaf=k.split(".")[-1]
  if leaf in KNOWN71 or leaf in {"id","series","titleTextMapHash","descTextMapHash"}: continue
  if not (leaf.isupper() or (len(leaf)==11 and leaf.upper()==leaf)): continue
  best=[]
  for ok,os in pb.items():
   inter=len(s&os)
   if not inter: continue
   union=len(s|os)
   j=inter/union
   precision=inter/len(s)
   recall=inter/len(os)
   if j>=0.02 or precision>=0.2 or recall>=0.2:
    best.append({"field":ok,"old_present":len(os),"intersection":inter,"jaccard":j,"current_covered":precision,"old_covered":recall})
  best.sort(key=lambda x:(-x["jaccard"],-min(x["current_covered"],x["old_covered"]),-x["intersection"],x["field"]))
  unknown.append({"field":k,"present":len(s),"types":sorted(types[k]),"best":best[:15]})
 unknown.sort(key=lambda x:-x["present"])
 rep={"rows71":len(a),"rows70":len(b),"common":len(common),"fields":unknown}
 args.output.write_text(json.dumps(rep,ensure_ascii=False,indent=2)+"\n",encoding="utf-8")
 for x in unknown:
  print("\n",x["field"],x["present"],x["types"])
  for y in x["best"][:8]: print(" ",y)
 return 0
if __name__=="__main__": raise SystemExit(main())
