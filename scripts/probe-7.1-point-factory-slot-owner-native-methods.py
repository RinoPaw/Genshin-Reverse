#!/usr/bin/env python3
"""Original 7.1 polymorphic factory slots: inspect three source method owners.

The method name JOBDNGNICNC is shared by three independent original
metadata classes. Three native methods carry exact RIP-relative references
to factory slots case 1 or case 14. This audit decodes entire source
method windows and retains contextual native instructions around every
positive-control RIP load. The method OWNER is not presumed to identify
the referenced class's runtime vtable, and no Scene/Point source-file
loader identity is assumed.
"""
from __future__ import annotations
import argparse
from bisect import bisect_right
import hashlib
import json
from pathlib import Path

from genshinre.callxref import _load_method_starts
from genshinre.nativeprofile import PROFILE_71
from genshinre.pe import PEImage
from genshinre.sampleidentity import require_sha256
from genshinre.xrefs import scan_rip_xrefs

SOURCE_REPORT="versions/7.1.0-global/analyses/progression/world/7.1-original-scene-point-factory-1-14-native-class-slot-xrefs.json"
SLOTS={1:0x57C37B0,14:0x57C1970}
TARGET_OWNERS=(
 (1,"OAGPJFNDNNG",118483,0xB4315B0,(0xB431635,0xB431692)),
 (1,"BFLGIHGLPBF",118533,0x11329530,(0x1132959D,)),
 (14,"NDPMDLJEOLG",445793,0x7ADC880,(0x7ADCA84,)),
)
METHODS_BLOB="a9c106a7fdd5fe97ad204d6f4641c1e2c8d5433a"
MAX_BODY=0x8000
MAX_NATIVE_INSTRUCTIONS=20000


def git_blob(path:Path)->str:
    h=hashlib.sha1()
    h.update(f"blob {path.stat().st_size}\0".encode("ascii"))
    with path.open("rb") as f:
        for data in iter(lambda:f.read(1<<20),b""):h.update(data)
    return h.hexdigest()


def validate_sources(methods:Path,prior:Path):
    if git_blob(methods)!=METHODS_BLOB:
        raise ValueError("original source methods CSV blob drift")
    prior_data=json.loads(prior.read_text(encoding="utf-8"))
    if (prior_data["originalExeSha256"]!=PROFILE_71.exe_sha256
        or prior_data["originalMethodMetadataGitBlob"]!=METHODS_BLOB
        or {int(k):int(v["nativeClassSlotRva"],16)
            for k,v in prior_data["nativeClassSlotReferencesByFactoryCase"].items()}!=SLOTS):
        raise ValueError("original source 7.1 factory slot xref report drift")
    starts,by_rva=_load_method_starts(methods)
    source=prior_data["nativeClassSlotReferencesByFactoryCase"]
    for case,owner,index,rva,sites in TARGET_OWNERS:
        rows=by_rva.get(rva,[])
        if len(rows)!=1 or (rows[0]["type_name"],int(rows[0]["method_index"]),rows[0]["method_name"])!=(owner,index,"JOBDNGNICNC"):
            raise ValueError(f"original source class/method identity drift for {owner}")
        verified={int(x["instructionRva"],16) for x in source[str(case)]["exactOriginalCodeReferences"]
                  if x["exactOriginalMetadataMethodOwners"][0]["originalTypeName"]==owner
                     and x["exactOriginalMetadataMethodOwners"][0]["originalMethodName"]=="JOBDNGNICNC"}
        if verified!=set(sites):
            raise ValueError(f"original source method native class-slot site drift for {owner}")
    return starts,by_rva



def scan_original_direct_slot_writes(pe:PEImage,starts:list[int],owners:dict,md)->dict:
    """Validate exact RIP-relative 64-bit native MOV stores to original class slots."""
    from capstone.x86 import X86_OP_MEM,X86_REG_RIP
    target_by_rva={slot:kind for kind,slot in SLOTS.items()}
    prefixes=[bytes((rex,0x89,modrm))
              for rex in (0x48,0x4C)
              for modrm in (0x05,0x0D,0x15,0x1D,0x25,0x2D,0x35,0x3D)]
    candidates={kind:[] for kind in SLOTS}
    seen=set()
    for section in pe.sections:
        if not(section.characteristics&0x20000000):continue
        data=pe.read_rva(section.virtual_address,section.raw_size)
        for prefix in prefixes:
            pos=0
            while (hit:=data.find(prefix,pos))>=0:
                pos=hit+1
                if hit+7>len(data):continue
                site=section.virtual_address+hit
                disp=int.from_bytes(data[hit+3:hit+7],"little",signed=True)
                dest=site+7+disp
                if dest not in target_by_rva or site in seen:continue
                seen.add(site)
                idx=bisect_right(starts,site)-1
                raw={"instructionRva":f"0x{site:X}",
                     "originalInstructionBytes":data[hit:hit+7].hex(),
                     "nativeDestinationSlotRva":f"0x{dest:X}",
                     "nativeInstructionAligned":False,
                     "originalMethodOwners":[]}
                if idx>=0:
                    start=starts[idx]
                    size=site+7-start
                    if 7<=size<=MAX_BODY:
                        body=pe.read_rva(start,size)
                        for x in md.disasm(body,pe.image_base+start):
                            if x.address-pe.image_base!=site:continue
                            if bytes(x.bytes)!=data[hit:hit+7] or x.mnemonic!="mov":
                                break
                            first=x.operands[0]
                            if first.type!=X86_OP_MEM or first.mem.base!=X86_REG_RIP:
                                break
                            if site+x.size+first.mem.disp!=dest:break
                            raw["nativeInstructionAligned"]=True
                            raw["nativeInstruction"]=f"{x.mnemonic} {x.op_str}"
                            raw["originalMethodOwners"]=[
                                {"typeName":o["type_name"],"methodName":o["method_name"],
                                 "methodIndex":int(o["method_index"])}
                                for o in owners.get(start,[])]
                            break
                candidates[target_by_rva[dest]].append(raw)
    out={}
    for kind,slot in SLOTS.items():
        section=next((s for s in pe.sections if
          s.virtual_address<=slot<s.virtual_address+max(s.virtual_size,s.raw_size)),None)
        binary=pe.read_rva(slot,8)
        rows=candidates[kind]
        out[str(kind)]={
            "originalStaticClassSlotRva":f"0x{slot:X}",
            "sourcePESection":section.name if section else None,
            "sourceSlotFileBackedQword":len(binary)==8,
            "sourceStaticSlotBytes":binary.hex() if len(binary)==8 else None,
            "originalNativeRipStoreByteCandidates":len(rows),
            "originalVerifiedAlignedNativeRipStores":sum(x["nativeInstructionAligned"] for x in rows),
            "originalNativeRipSlotStoreCandidates":rows,
            "runtimeClassRegistrationWriteOwnerProven":False,
            "originalConcreteTypeDefinitionIndexProven":False
        }
    return out


def inspect(exe:Path,methods:Path,prior:Path)->dict:
    starts,owners=validate_sources(methods,prior)
    require_sha256(exe,PROFILE_71.exe_sha256,label="original Global 7.1 executable")
    from capstone import Cs,CS_ARCH_X86,CS_MODE_64
    from capstone.x86 import X86_OP_MEM,X86_REG_RIP
    md=Cs(CS_ARCH_X86,CS_MODE_64)
    md.detail=True
    decoded=[]
    with PEImage(exe) as pe:
        for case,owner,index,rva,sites in TARGET_OWNERS:
            i=bisect_right(starts,rva)
            if i>=len(starts):raise ValueError("missing original source method successor")
            next_start=starts[i]
            size=next_start-rva
            if size<=0 or size>MAX_BODY:
                raise ValueError(f"original method body bound exceeded for {owner}: {size}")
            buf=pe.read_rva(rva,size)
            if len(buf)!=size:raise ValueError("non-file-backed original native method")
            originals=list(md.disasm(buf,pe.image_base+rva))
            if not originals or len(originals)>MAX_NATIVE_INSTRUCTIONS:
                raise ValueError("original method decode outside expected bounds")
            opcodes=[{"rva":f"0x{x.address-pe.image_base:X}",
                      "mnemonic":x.mnemonic,
                      "operands":x.op_str,
                      "bytes":bytes(x.bytes).hex()} for x in originals]
            byaddr={x.address-pe.image_base:(i,x) for i,x in enumerate(originals)}
            witnesses=[]
            for addr in sites:
                if addr not in byaddr:raise ValueError("original source xref not on decoded instruction")
                ord,ins=byaddr[addr]
                mem=[x for x in ins.operands if x.type==X86_OP_MEM and x.mem.base==X86_REG_RIP]
                target=addr+ins.size+mem[0].mem.disp if len(mem)==1 else None
                if ins.mnemonic not in ("mov","lea") or target!=SLOTS[case]:
                    raise ValueError("source 7.1 class slot reference instruction semantics drift")
                witnesses.append({
                    "sourceLoadInstructionRva":f"0x{addr:X}",
                    "sourceLoadNativeInstruction":opcodes[ord],
                    "sourceClassSlotRva":f"0x{SLOTS[case]:X}",
                    "nativeBeforeAndAfterInstructions":opcodes[max(ord-18,0):min(len(opcodes),ord+28)],
                    "concreteClassOwnedByMethodNotProven":True,
                })
            calls=[{"rva":f"0x{x.address-pe.image_base:X}","instruction":f"{x.mnemonic} {x.op_str}"}
                   for x in originals if x.mnemonic=="call"]
            decoded.append({
                "originalFactoryNumericCase":case,
                "originalClassSlotRva":f"0x{SLOTS[case]:X}",
                "originalMethodOwnerType":owner,
                "originalOwnerMethodName":"JOBDNGNICNC",
                "originalOwnerMethodIndex":index,
                "originalMethodStartRva":f"0x{rva:X}",
                "originalNextMethodStartRva":f"0x{next_start:X}",
                "originalNativeMethodSizeBytes":size,
                "originalNativeMethodSha256":hashlib.sha256(buf).hexdigest(),
                "decodedNativeInstructionCount":len(originals),
                "sourceSlotLoadWitnesses":witnesses,
                "methodPrologueInstructions":opcodes[:35],
                "sourceCalls":calls[:250],
                "concreteClassIdentityResolved":False,
                "sourceVirtualElementReaderResolved":False,
            })
        slot_writes=scan_original_direct_slot_writes(pe,starts,owners,md)
    return {
        "schemaVersion":1,
        "status":"EXACT_7_1_SOURCE_FACTORY_1_14_SLOT_REFERENCE_OWNER_NATIVE_METHOD_CONTEXT__CLASS_IDENTITY_PENDING",
        "originalExeSha256":PROFILE_71.exe_sha256,
        "originalMethodsGitBlob":METHODS_BLOB,
        "originalSourceFactorySlotReferencesReport":SOURCE_REPORT,
        "originalMethodWindows":decoded,
        "sourceOriginalDirectNativeClassSlotWrites":slot_writes,
        "verifiedExactNativeLoadCount":sum(len(r["sourceSlotLoadWitnesses"]) for r in decoded),
        "originalConcreteClassIdentityProven":False,
        "originalElementDeserializerSlotF8Resolved":False,
        "originalScenePointLoaderBindingProven":False,
        "originalChestPlacementOrLevelProven":False,
        "limitations":[
            "An original method referencing a runtime Il2CppClass slot is no proof that its declaring type equals the class in the slot.",
            "The same obfuscated method name JOBDNGNICNC occurs on multiple original metadata owners.",
            "Raw native method instruction context is original source evidence, but context alone does not establish vtable target, original Scene/Point loader or chest semantics.",
        ]
    }


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ("exe","methods","prior","output"):
        parser.add_argument("--"+name,type=Path,required=True)
    a=parser.parse_args()
    r=inspect(a.exe,a.methods,a.prior)
    a.output.parent.mkdir(parents=True,exist_ok=True)
    a.output.write_text(json.dumps(r,ensure_ascii=False,indent=2)+"\n",encoding="utf-8")
    print("ORIGINAL_METHOD_CONTEXT_BEGIN")
    print(json.dumps(r,ensure_ascii=False,indent=2))
    print("ORIGINAL_METHOD_CONTEXT_END")


if __name__=="__main__":main()
