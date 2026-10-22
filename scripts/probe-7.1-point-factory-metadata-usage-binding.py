#!/usr/bin/env python3
"""Original Global 7.1 metadata usage lists and factory class-slot holder census.

Uses EXACT original SHA-256-pinned exe and global-metadata.dat, and recovered
source-native 7.1 metadata usage-list/pair transforms from the original client.
Class pointers in executable .data BSS cannot be reconstructed by treating
RIP xrefs as type identities. Decode original source pair records and locate
exact raw file-backed address holders separately, without inventing a join.
"""
from __future__ import annotations
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

from genshinre.nativeprofile import PROFILE_71
from genshinre.pe import PEImage
from genshinre.sampleidentity import require_sha256

ROOT=Path(__file__).resolve().parents[1]
SRC=ROOT/"scripts/research_trace_7_1_literal_usage.py"
spec=importlib.util.spec_from_file_location("original_71_usage_decoder",SRC)
usage=importlib.util.module_from_spec(spec)
spec.loader.exec_module(usage)

FACTORY_REPORT="versions/7.1.0-global/analyses/progression/world/7.1-original-scene-point-array-element-factory-native-evidence.json"
SLOT_XREF_REPORT="versions/7.1.0-global/analyses/progression/world/7.1-original-scene-point-factory-1-14-native-class-slot-xrefs.json"
CASE_INDICES=(1,14)
CONTROL_SLOTS={
 "ConfirmedRegistrySlotUnlockTransPointReq":0x57E6498,
 "OriginalSceneTagClassSlot":0x57EA618,
 "MetadataRegistrationGlobal":usage.METADATA_REGISTRATION_GLOBAL_RVA,
}
MAX_HITS_PER_FORM=300
EXECUTABLE=0x20000000


def source_cases(factory:Path,prior:Path)->list[dict]:
    x=json.loads(factory.read_text(encoding="utf-8"))
    y=json.loads(prior.read_text(encoding="utf-8"))
    cases=x["originalFactory"]["sourceCases"]
    if (x["originalExeSha256"]!=PROFILE_71.exe_sha256 or
        x["originalFactory"]["exactAlignedNativeJumpCaseCount"]!=31 or
        y["originalExeSha256"]!=PROFILE_71.exe_sha256 or
        y["originalMethodMetadataGitBlob"]!="a9c106a7fdd5fe97ad204d6f4641c1e2c8d5433a" or
        [r["originalNumericCaseId"] for r in cases]!=list(range(31)) or
        any(int(y["nativeClassSlotReferencesByFactoryCase"][str(i)]["nativeClassSlotRva"],16)!=
            int(cases[i]["nativeRuntimeClassSlotRva"],16) for i in CASE_INDICES)):
        raise ValueError("exact original 7.1 factory class slot prior source drift")
    return cases


def audit_raw_slot_holders(pe:PEImage,cases:list[dict])->dict:
    slots={f"factory_case_{x['originalNumericCaseId']}":int(x["nativeRuntimeClassSlotRva"],16)
           for x in cases}
    slots.update(CONTROL_SLOTS)
    results={}
    for label,slot in slots.items():
        results[label]={
           "slotRva":f"0x{slot:X}",
           "originalImageVa":f"0x{pe.image_base+slot:X}",
           "nativeDirectQwordVAHolders":[],
           "sourceRawDwordRvaCandidates":[],
           "sourceRawDwordImageVaLow32Candidates":[],
           "runtimeSlotValueFileBacked":len(pe.read_rva(slot,8))==8,
        }
    # Exact literal byte pattern searches do not attribute a pointer's semantic
    # owner; this is a data-holder census, independent of x64 code RIP reads.
    for sec in pe.sections:
        if sec.characteristics&EXECUTABLE or sec.raw_size<4:continue
        raw=pe.read_rva(sec.virtual_address,sec.raw_size)
        for label,slot in slots.items():
            out=results[label]
            patterns=(
                ("nativeDirectQwordVAHolders",struct.pack("<Q",pe.image_base+slot),8),
                ("sourceRawDwordRvaCandidates",struct.pack("<I",slot),4),
                ("sourceRawDwordImageVaLow32Candidates",struct.pack("<I",(pe.image_base+slot)&0xFFFFFFFF),4)
            )
            for name,pattern,alignment in patterns:
                cursor=0
                while (pos:=raw.find(pattern,cursor))>=0:
                    cursor=pos+1
                    rva=sec.virtual_address+pos
                    if rva%alignment:continue
                    bucket=out[name]
                    if len(bucket)>=MAX_HITS_PER_FORM:
                        raise ValueError(f"too many original file-backed holder matches: {label} {name}")
                    bucket.append({"holderRva":f"0x{rva:X}","peSection":sec.name,
                                   "surroundingOriginalBytesHex":raw[max(0,pos-8):pos+len(pattern)+8].hex()})
    return {
      "testedFactoryCaseCount":31,
      "sourceFactoryCase1And14BothIncluded":True,
      "controlSlots":list(CONTROL_SLOTS),
      "rawHolderMatches":results,
      "sourceAll31FactoryCaseQwordVaHolderCount":sum(len(results[f"factory_case_{i}"]["nativeDirectQwordVAHolders"]) for i in range(31)),
      "sourceBothTargetCaseQwordVaHolders":sum(len(results[f"factory_case_{i}"]["nativeDirectQwordVAHolders"]) for i in CASE_INDICES),
      "fileBackedHolderProvesOriginalIL2CPPTypeIdentity":False,
    }


def decode_original_usage_tables(metadata:bytes,header:bytes)->dict:
    if len(header)!=PROFILE_71.embedded_header_size:
        raise ValueError("source original metadata header window mismatch")
    raw_list=usage.u32(header,usage.LIST_TABLE_HEADER_OFFSET)
    raw_pair=usage.u32(header,usage.PAIR_TABLE_HEADER_OFFSET)
    list_rel=raw_list^usage.LIST_TABLE_HEADER_XOR
    pair_rel=(raw_pair+usage.PAIR_TABLE_HEADER_ADD)&usage.M32
    probes=[]
    for body in (PROFILE_71.metadata_body_skip,0):
        list_pos=body+list_rel
        pair_pos=body+pair_rel
        report={
          "originalMetadataBodyBaseCandidate":f"0x{body:X}",
          "sourceDecodedUsageListTableFileOffsetCandidate":f"0x{list_pos:X}",
          "sourceDecodedUsagePairTableFileOffsetCandidate":f"0x{pair_pos:X}",
          "candidateTablesInsideMetadata":list_pos+8<len(metadata) and pair_pos+8<len(metadata),
          "nativeUsageListsConsistent":False
        }
        if report["candidateTablesInsideMetadata"]:
            try:
                starts=usage.discover_usage_list_starts(metadata,list_pos,pair_pos,max_lists=800000)
                if len(starts)>3 and starts[-1]<(len(metadata)-pair_pos)//8:
                    counts=[0]*8
                    examples={str(k):[] for k in range(8)}
                    max_src=[0]*8
                    dest_index_min=None
                    dest_index_max=None
                    source_limit_failures={str(k):0 for k in (1,3)}
                    final_usage_records=[]
                    suspicious_kind_zero_pairs=[]
                    for pair_index in range(starts[-1]):
                        kind,source,dest,_=usage.decode_usage_pair(metadata,pair_pos,pair_index)
                        counts[kind]+=1
                        max_src[kind]=max(max_src[kind],source)
                        dest_index_min=dest if dest_index_min is None else min(dest_index_min,dest)
                        dest_index_max=dest if dest_index_max is None else max(dest_index_max,dest)
                        if kind==1 and source>=PROFILE_71.runtime_type_count:
                            source_limit_failures["1"]+=1
                        if kind==3 and source>=PROFILE_71.method_count:
                            source_limit_failures["3"]+=1
                        if pair_index>=starts[-1]-20:
                            final_usage_records.append({
                                "pairIndex":pair_index,"nativeKind":kind,
                                "sourceIndex":source,"destinationIndex":dest})
                        if kind==0 and len(suspicious_kind_zero_pairs)<20:
                            suspicious_kind_zero_pairs.append(pair_index)
                        if len(examples[str(kind)])<4:
                            examples[str(kind)].append({"pairIndex":pair_index,"originalSourceIndex":source,
                                                     "originalUsageDestinationIndex":dest})
                    report.update({
                       "nativeUsageListsConsistent":True,
                       "originalUsageListCount":len(starts)-1,
                       "originalUsagePairCount":starts[-1],
                       "originalUsageKindsCount":{str(i):n for i,n in enumerate(counts)},
                       "originalUsageKindMaxSourceIndex":{str(i):n for i,n in enumerate(max_src)},
                       "originalUsageDestinationIndexBounds":[dest_index_min,dest_index_max],
                       "originalUsageKindSourceSamples":examples,
                       "sourceNativeRecoveredUsageListStartsSample":starts[:8],
                       "sourceValidIndexBoundaryViolationsForKinds1And3":source_limit_failures,
                       "sourceOriginalUsageListStartsTail":starts[-16:],
                       "sourceFinalTwentyDecodedPairs":final_usage_records,
                       "originalKindZeroPairIndices":suspicious_kind_zero_pairs,
                       "decodedKindZeroPairTailUnverified":True,
                       "sourceKind1MaximumEqualsOriginalRuntimeTypeCountMinusOne":max_src[1]==PROFILE_71.runtime_type_count-1,
                       "originalUsagePairDestinationsAreClassSlotRVAsProven":False
                    })
            except (ValueError,IndexError,OverflowError,struct.error) as exc:
                report["rejectedSourceCandidateReason"]=str(exc)[:200]
        probes.append(report)
    return {
      "originalClientHeaderRva":f"0x{PROFILE_71.embedded_header_rva:X}",
      "originalMetadataBodySkip":f"0x{PROFILE_71.metadata_body_skip:X}",
      "nativeSourceDecodedListRelativeOffset":f"0x{list_rel:X}",
      "nativeSourceDecodedPairRelativeOffset":f"0x{pair_rel:X}",
      "sourceMetadataCandidateProbes":probes,
      "originalMetadataUsageDestinationToClassSlotJoinProven":False
    }


def inspect(exe:Path,metadata:Path,factory:Path,prior:Path)->dict:
    cases=source_cases(factory,prior)
    require_sha256(exe,PROFILE_71.exe_sha256,label="original Global 7.1 executable")
    require_sha256(metadata,PROFILE_71.metadata_sha256,label="original Global 7.1 metadata")
    with PEImage(exe) as pe:
        header=pe.read_rva(PROFILE_71.embedded_header_rva,PROFILE_71.embedded_header_size)
        holders=audit_raw_slot_holders(pe,cases)
    data=metadata.read_bytes()
    if data[:4]!=b"MHY\0":raise ValueError("original 7.1 metadata MHY source header missing")
    decoded=decode_original_usage_tables(data,header)
    return {
       "schemaVersion":1,
       "status":"ORIGINAL_GLOBAL_7_1_METADATA_USAGE_PAIRS_AND_FACTORY_CLASS_SLOT_HOLDERS__TYPE_IDENTITY_UNRESOLVED",
       "originalExeSha256":PROFILE_71.exe_sha256,
       "originalMetadataSha256":PROFILE_71.metadata_sha256,
       "sourceOriginalFactory":FACTORY_REPORT,
       "sourceNativeClassSlotPrior":SLOT_XREF_REPORT,
       "metadataUsage":decoded,
       "nativeFactoryClassSlotFileHolderCensus":holders,
       "sourceConcreteCase1ClassTypeDefIndexResolved":False,
       "sourceConcreteCase14ClassTypeDefIndexResolved":False,
       "sourceVirtualReadSlotF8TargetResolved":False,
       "sourceScenePointAssetParserLoaderBindingResolved":False,
       "sourceChestInstanceLocationsOrLevelResolved":False,
       "limitations":[
          "Decoded obfuscated native metadata usage kinds are original raw numeric bits without semantic type labels assigned.",
          "Class-slot qword VA holders and raw dword RVA matches are reported separately; no metadata usage destination index-to-class pointer slot join follows from byte matches alone.",
          "Original class slots may be runtime-initialized in unbacked .data, so absent file-backed direct holders is a bounded static negative result.",
          "Exact original source executable and metadata hashes and original native decoder constants are required before any usage-pair claim.",
          "No original Scene Point loader, entity/chest position, Gadget level or reward server ownership is inferred."
       ]
    }


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ("exe","metadata","factory","prior","output"):
        p.add_argument("--"+name,type=Path,required=True)
    a=p.parse_args()
    r=inspect(a.exe,a.metadata,a.factory,a.prior)
    a.output.parent.mkdir(parents=True,exist_ok=True)
    a.output.write_text(json.dumps(r,ensure_ascii=False,indent=2)+"\n",encoding="utf-8")
    print("ORIGINAL_METADATA_SLOT_USAGE_BEGIN")
    print(json.dumps(r,ensure_ascii=False,indent=2))
    print("ORIGINAL_METADATA_SLOT_USAGE_END")


if __name__=="__main__":main()
