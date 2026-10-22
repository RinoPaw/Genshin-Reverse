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
    # Original metadata method parameter types form a direct native relationship
    # between candidate packet identities and consumer/producer methods.
    candidate_names={r["type_name"] for r in focus}
    inbound=[]
    for row in records("metadata/methods.csv"):
        args=row.get("parameter_types","")
        if any('"' + name + '"' in args for name in candidate_names):
            inbound.append(row)
    # Native client consumer whose one-parameter handlers include imported
    # WorldOwnerBlossomScheduleInfoNotify / BlossomChestCreateNotify variants.
    # Nearby owner methods are structural search leads only.
    owner="CJEDOIPINHC"
    neighbor=[r for r in records("metadata/methods.csv")
              if r["type_name"]==owner]
    map_by_type={r["type_name"]:r for r in native.values()}
    control_by_id={c["cmd_id"]:c["semantic_name"] for c in records("registry/control-set.csv")}
    print("OWNER_METHOD_NEIGHBORHOOD",owner,"total",len(neighbor),flush=True)
    for row in neighbor:
        try: idx=int(row["method_index"])
        except ValueError:continue
        if not 266535 <= idx <= 266630:continue
        mapped=[]
        for tn,native_item in map_by_type.items():
            if '"' + tn + '"' in row.get("parameter_types",""):
                mapped.append({"cmd_id":native_item["cmd_id"],"type":tn,
                               "imported_hint":control_by_id.get(native_item["cmd_id"],"")})
        print("  OWNER",json.dumps({"index":idx,"method":row["method_name"],
              "rva":row["rva"],"params":row.get("parameter_types"),"ids":mapped}),flush=True)
    # Canonical xrefs connect registry type-slot identities to current-client
    # code sites. No historical semantic label is used as identity evidence.
    for target in ("registry/registry-slot-xrefs.csv",
                   "registry/registry-type-slots.csv"):
        data=list(records(target))
        print("XREF_SCHEMA",target,list(data[0]) if data else [],flush=True)
        for candidate in focus:
            slot=candidate.get("type_slot_rva","").lower()
            index=candidate.get("index","")
            match=[x for x in data if
                   x.get("type_slot_rva","").lower()==slot
                   or x.get("cmd_id","")==candidate["cmd_id"]
                   or (target.endswith("registry-type-slots.csv")
                       and x.get("index","")==index)]
            print("SLOT_XREF",target,candidate["cmd_id"],
                  "count",len(match),flush=True)
            for x in match[:20]:
                print("  XREF",json.dumps(x),flush=True)
    # Generic-instantiation type indexes can identify the same RepeatedField<T>
    # across otherwise obfuscated packet classes, unlike the shared open
    # generic HCDGGIDOEFA that appears on thousands of classes.
    native_by_typedef={x["type_definition_index"]:x for x in records("registry/registry.csv")}
    original_generic_indices={"505695","526432","653206","476942","476943"}
    shared=[x for x in records("metadata/fields.csv")
            if x["field_type_index"] in original_generic_indices]
    for type_index in sorted(original_generic_indices):
        rows_here=[x for x in shared if x["field_type_index"]==type_index]
        print("GENERIC_INSTANCE_INDEX",type_index,"fields",len(rows_here),flush=True)
        for x in rows_here[:80]:
            print("  GENERIC_USE",json.dumps({"field":x,
                "registered_packet":native_by_typedef.get(x["type_definition_index"])},
                ensure_ascii=False),flush=True)
    # Exact first-party code targets taken from receiver 0xC78CA80. Their native
    # declaring types and method signatures can identify the list *element*.
    method_targets={
       0x109AA8F0:"shared-item-factory",
       0x172F5790:"client-record-lookup",
       0xC791C50:"owner-register-element",
       0x17A4BB30:"collection-object-lookup",
       0xC791A20:"owner-state-reset",
       0xC790540:"owner-state-prepare",
       0xC78C110:"owner-marker-callback",
       0xFAA2010:"client-guard",
    }
    matched=[]
    for row in records("metadata/methods.csv"):
        rva=row.get("rva","")
        if not rva:continue
        try: addr=int(rva,0)
        except ValueError:continue
        if addr in method_targets:
            matched.append((method_targets[addr],row))
    print("NATIVE_CALL_CALLEE_SIGNATURES",len(matched),flush=True)
    for label,row in matched:
        print("  NATIVE_CALLEE",label,json.dumps(row),flush=True)
    owner_fields=[x for x in records("metadata/fields.csv")
                  if x.get("type_name") in {"CJEDOIPINHC","ABJOMOIIDHH","GIIGDONJFPJ","JBHJMLHMHAC"}]
    print("ORIGINAL_RECEIVER_AND_PACKET_FIELDS",len(owner_fields),flush=True)
    for row in owner_fields:
        print("  ORIGINAL_FIELD",json.dumps(row),flush=True)
    print("INBOUND_SIGNATURE_COUNTS",len(inbound),flush=True)

    for name in sorted(candidate_names):
        hits=[x for x in inbound if '"' + name + '"' in x.get("parameter_types","")]
        print("INBOUND_SIGNATURE_TYPE",name,"count",len(hits),flush=True)
        for item in hits[:60]:
            print("  INBOUND",json.dumps(item),flush=True)

if __name__ == "__main__":
    scan()
