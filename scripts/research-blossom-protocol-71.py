#!/usr/bin/env python3
"""Inspect native Global 7.1 protocol identities associated with imported blossom names.

Imported names are exploration candidates only; this script never promotes an opcode.
"""
from __future__ import annotations
import csv
import json
from pathlib import Path

ROOT = Path("versions/7.1.0-global/windows-x64")
SEMANTIC_TERMS = ("blossom", "leyline", "ley_line")
def records(p):
    with (ROOT / p).open(encoding="utf-8-sig", newline="") as f:
        yield from csv.DictReader(f)
def scan():
    controls = [r for r in records("registry/control-set.csv") if any(k in r.get("semantic_name","").lower() for k in SEMANTIC_TERMS)]
    native = {r["cmd_id"]:r for r in records("registry/registry.csv")}
    controls = sorted(controls, key=lambda x:int(x["cmd_id"]))
    focus = [native.get(c["cmd_id"]) for c in controls if c["cmd_id"] in native]
    by_type = {r["type_definition_index"]:r for r in focus}
    print("CONTROLS",json.dumps(controls,indent=2))
    print("REGISTRY_IDENTITIES",json.dumps(focus,indent=2))
    print("FOCUS_TYPES", len(by_type),flush=True)
    for p in ("metadata/types.csv","metadata/fields.csv","metadata/methods.csv","metadata/runtime-types.csv"):
        with (ROOT/p).open(encoding="utf-8-sig",newline="") as f:
            rd=csv.DictReader(f)
            header=rd.fieldnames
            sample=next(rd)
        print("CSV_SCHEMA",p,header,"SAMPLE",sample,flush=True)
    for p in ("metadata/types.csv","metadata/fields.csv","metadata/methods.csv"):
        hits=[]
        for r in records(p):
            if str(r.get("type_definition_index","")) in by_type or str(r.get("type_name","")) in {t["type_name"] for t in focus}:
                hits.append(r)
        print("FOCUS_ROWS",p,"count",len(hits),flush=True)
        for idx in by_type:
            ty=by_type[idx]
            matches=[h for h in hits if h.get("type_definition_index")==idx or h.get("type_name")==ty["type_name"]]
            print("TYPE",ty["cmd_id"],ty["type_name"],p,"count",len(matches),flush=True)
            for m in matches[:48]:
                print("  ROW",json.dumps(m,ensure_ascii=False),flush=True)

    referenced = {
        "HCDGGIDOEFA", "ELDHKOJPAIC", "MPDKBDDJAOE",
        "MPCLIAJOEJB", "JBHJMLHMHAC", "MNCLLNEAMHG",
    }
    refs=[]
    for row in records("metadata/fields.csv"):
        if row["field_type"] in referenced:
            refs.append(row)
    print("FIELDTYPE_REFERENCES",len(refs),flush=True)
    for name in sorted(referenced):
        hits=[x for x in refs if x["field_type"]==name]
        print("REFERENCED_TYPE",name,"count",len(hits),flush=True)
        for h in hits[:70]:
            print("  REF",json.dumps(h),flush=True)
    wanted_types=[x for x in records("metadata/types.csv") if x["type_name"] in referenced]
    print("REFERENCED_TYPE_DEFS",json.dumps(wanted_types,indent=2),flush=True)
    # Types that look like protobuf messages with a single nested field of the
    # exact same type as the imported response are potential marker notifications.
    print("SAME_FIELD_112",json.dumps([x for x in refs if x["field_type"]=="HCDGGIDOEFA"][:100]),flush=True)
if __name__ == "__main__":
    scan()
