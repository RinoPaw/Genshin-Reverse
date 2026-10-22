#!/usr/bin/env python3
"""Source-pinned original 7.1 Scene Point first element byte-gate evidence.

Cross 13 source-verified original client Scene/Point 32-byte prefixes with
the original exact native NLLGJBBHHAN 31-case element discriminator and
its NLDEPJEOJGC call path. No asset-loader relation is inferred.
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

ORIGINAL_SAMPLES="versions/7.1.0-global/analyses/progression/world/7.1-original-scene-point-source-payload-census.json"
ORIGINAL_FACTORY="versions/7.1.0-global/analyses/progression/world/7.1-original-scene-point-array-element-factory-native-evidence.json"
RVA=0xAD23000
SIZE=0x620
RVA_SHA="6319613278adf382bf7ce513d1d875ef98b318d5f5f3bc9c423b72caebd7c0ad"
EXE_SHA="08a3086d5f3fe695f01dab61efa42e442006b18e5e475b2520df356f6a073b7d"
METHODS_BLOB="a9c106a7fdd5fe97ad204d6f4641c1e2c8d5433a"
PREFIX_SIZE=32
MIN_ID=0
MAX_ID=30
SOURCE_COUNT_U32_OFFSET=3
SOURCE_ELEMENT_FIRST_DIRECT_OFFSET=7
CANDIDATE_ELEMENT_OFFSET=10


def git_blob(path:Path)->str:
    h=hashlib.sha1()
    h.update(f"blob {path.stat().st_size}\0".encode("ascii"))
    with path.open("rb") as f:
        for b in iter(lambda:f.read(1<<20),b""):h.update(b)
    return h.hexdigest()


def evidence_samples(assets:Path,factory:Path)->tuple[list[dict],dict]:
    j=json.loads(assets.read_text(encoding="utf-8"))
    n=json.loads(factory.read_text(encoding="utf-8"))
    if (j["exactOriginalExeSha256"]!=EXE_SHA or j["scenesChecked"]!=13
            or j["statusCounts"]!={"SOURCE_RAW_AND_FRAMING_VERIFIED":13}
            or n["originalExeSha256"]!=EXE_SHA
            or n["originalArrayNativeReader"]["nativeSourceWindowSha256"]!=RVA_SHA
            or n["originalFactory"]["exactAlignedNativeJumpCaseCount"]!=31
            or n["originalArrayNativeReader"]["elementDiscriminatorNativeByteXor"]!="0xF5"
            or n["originalArrayNativeReader"]["elementDiscriminatorNativeByteAdd"]!="0x34"
            or j["source"]["exactBranchCommit"]!="63980a635f7202ab7dd4b964047c0788108db893"):
        raise ValueError("source-original Global 7.1 Scene Point/factory evidence drift")
    rows=j["assetRows"]
    if [x["sceneId"] for x in rows]!=[3,4,5,6,7,9,10,11,100,101,102,103,51195]:
        raise ValueError("original scene point identities changed")
    for row in rows:
        if len(bytes.fromhex(row["unwrappedPayloadFirst32Hex"]))!=PREFIX_SIZE:
            raise ValueError("source original Scene Point prefix length changed")
    return rows,n


def decode_native_kind(byte:int)->int:
    return ((byte^0xF5)+0x34)&0xFF


def prefix_candidates(rows:list[dict])->dict:
    values=[bytes.fromhex(r["unwrappedPayloadFirst32Hex"]) for r in rows]
    masks=[int.from_bytes(x[:2],"little") for x in values]
    if not all(((x+0xF077)&0xC000)==0xC000 for x in masks):
        raise ValueError("original source mask compatibility changed")
    if not all(x[2]==0xCB for x in values):
        raise ValueError("original source byte-2 helper input changed")
    count=[int.from_bytes(x[3:7],"little") ^ 0xC14B813C for x in values]
    if not all(v>=1 and v*2 <= int(r["payloadBytes"])
               for v,r in zip(count,rows,strict=True)):
        raise ValueError("original source candidate XOR count physical bounds failed")
    full=[]
    for offset in range(PREFIX_SIZE):
        kinds=[decode_native_kind(x[offset]) for x in values]
        full.append({
           "offset":offset,
           "originalUnmodifiedBytesHex":[f"0x{x[offset]:02X}" for x in values],
           "decodedOriginalNativeFactoryIdsIfUsedAtThisOffset":kinds,
           "sourceSamplesPassingRange0To30":sum(MIN_ID<=v<=MAX_ID for v in kinds),
           "all13OriginalSourceSamplesFitNativeFactory":all(MIN_ID<=v<=MAX_ID for v in kinds),
        })
    direct=full[SOURCE_ELEMENT_FIRST_DIRECT_OFFSET]
    candidate=full[CANDIDATE_ELEMENT_OFFSET]
    if direct["sourceSamplesPassingRange0To30"]!=0:
        raise ValueError("original direct-after-count candidate now plausible")
    if not candidate["all13OriginalSourceSamplesFitNativeFactory"]:
        raise ValueError("source sample byte+10 type-discriminator gate failed")
    matching=[row["offset"] for row in full if row["all13OriginalSourceSamplesFitNativeFactory"]]
    if matching!=[10]:
        raise ValueError(f"original all-scene aligned byte gate changed: {matching}")
    return {
      "sourceNativeFactoryByteExpression":"((originalByte XOR 0xF5) + 0x34) mod 256",
      "originalCandidateArrayCountOffset":SOURCE_COUNT_U32_OFFSET,
      "candidateArraysLengthsFromOriginal13SourcePrefixes":count,
      "candidateArrayCountSourceBindingProven":False,
      "immediateAfterLengthByteOffset":SOURCE_ELEMENT_FIRST_DIRECT_OFFSET,
      "offset7AllThirteenFailOriginalSubtypeFactory":True,
      "soleAll13SourcePassingByteOffset":CANDIDATE_ELEMENT_OFFSET,
      "sourceSubtypeAtOffset10Candidate":[
         {"sceneId":r["sceneId"],"rawNativeOriginalByte":candidate["originalUnmodifiedBytesHex"][i],
          "nativeTransformedNumericSubtypeCandidate":candidate["decodedOriginalNativeFactoryIdsIfUsedAtThisOffset"][i]}
         for i,r in enumerate(rows)
      ],
      "all32SourceOffsetsDiscriminatorCensus":full,
      "threeByteDisplacementAfterCountIsObserved":True,
      "nativeCursorConsumptionForExtraThreeBytesProven":False,
      "sourceAssetLoaderToOriginalNativeArrayReaderProven":False,
      "actualFirstElementDiscriminatorOffsetProven":False,
    }


def source_reader_trace(exe:Path,methods:Path)->dict:
    if git_blob(methods)!=METHODS_BLOB:
        raise ValueError("original 7.1 method-index Git blob mismatch")
    starts,m=_load_method_starts(methods)
    owners=m.get(RVA,[])
    if len(owners)!=1 or (owners[0]["type_name"],owners[0]["method_name"],
                          int(owners[0]["method_index"]))!=(
                          "NLDEPJEOJGC","GMENPOPMKAA",514423):
        raise ValueError("original native array reader owner drift")
    i=bisect_right(starts,RVA)
    if i>=len(starts) or starts[i]!=RVA+SIZE:
        raise ValueError("source original array reader method native window changed")
    require_sha256(exe,EXE_SHA,label="source original Global 7.1 native EXE")
    from capstone import Cs,CS_ARCH_X86,CS_MODE_64
    with PEImage(exe) as pe:
        buf=pe.read_rva(RVA,SIZE)
        if len(buf)!=SIZE or hashlib.sha256(buf).hexdigest()!=RVA_SHA:
            raise ValueError("source original array reader byte SHA mismatch")
        ins=[{"rva":f"0x{x.address-pe.image_base:X}",
              "mnemonic":x.mnemonic,
              "operands":x.op_str,
              "hex":bytes(x.bytes).hex()} for x in
             Cs(CS_ARCH_X86,CS_MODE_64).disasm(buf,pe.image_base+RVA)]
    by={x["rva"]:x for x in ins}
    required={
      "0xAD23066":("mov","ebx, 0xc14b813c"),
      "0xAD2306B":("xor","ebx, dword ptr [rax + rdx + 0x20]"),
      "0xAD23072":("mov","dword ptr [r15 + 0x28], ecx"),
      "0xAD23393":("movzx","eax, byte ptr [rax + rdx + 0x20]"),
      "0xAD23398":("inc","ecx"),
      "0xAD2339A":("mov","dword ptr [r15 + 0x28], ecx"),
      "0xAD2339E":("xor","al, 0xf5"),
      "0xAD233A0":("add","al, 0x34"),
      "0xAD233A5":("call","0x14c591c60"),
      "0xAD233BE":("call","qword ptr [rax + 0xf8]"),
    }
    for addr,(name,ops) in required.items():
        if addr not in by or (by[addr]["mnemonic"],by[addr]["operands"])!=(name,ops):
            raise ValueError("source original native array element discriminator instruction drift: "+addr)
    # Preserve all code that could explain a 3-byte difference between
    # source array length and first candidate subtype byte.
    prelude=[x for x in ins if 0xAD230D5<=int(x["rva"],16)<=0xAD233A5]
    reads=[x for x in prelude if x["mnemonic"].startswith(("mov","lea"))
           and any(t in x["operands"] for t in (
            "byte ptr [rax +","word ptr [rax +","dword ptr [rax +",
            "qword ptr [rax +","[r15 + 0x28]"))]
    calls=[x for x in prelude if x["mnemonic"] in ("call","jmp")]
    return {
       "nativeMethodRva":f"0x{RVA:X}","nativeMethodSha256":RVA_SHA,
       "decodedNativeInstructionCount":len(ins),
       "exactSourceInstructionAnchors":[by[x] for x in required],
       "firstElementPreludeBound":[f"0x{0xAD230D5:X}",f"0x{0xAD233A5:X}"],
       "firstElementPreludeInstructions":prelude,
       "firstElementPreludeMemoryReadAndCursorCandidates":reads,
       "firstElementPreludeCallOrJumpCandidates":calls,
       "sourceOriginalThreeByteCursorProven":False,
       "originalScenePointAssetConsumerProven":False,
    }


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for k in ("assets","factory","exe","methods","output"):
        p.add_argument("--"+k,required=True,type=Path)
    a=p.parse_args()
    rows,_=evidence_samples(a.assets,a.factory)
    result={
      "schemaVersion":1,
      "status":"ORIGINAL_GLOBAL_7_1_SCENE_POINT_FIRST_ELEMENT_TYPE_BYTE_GATE__LOADER_AND_CURSOR_UNVERIFIED",
      "originalExeSha256":EXE_SHA,
      "originalMethodsGitBlob":METHODS_BLOB,
      "sourceScenePointAssets":ORIGINAL_SAMPLES,
      "sourceFactoryEvidence":ORIGINAL_FACTORY,
      "sourcePrefixCrossSceneGate":prefix_candidates(rows),
      "sourceOriginalNativeArrayReader":source_reader_trace(a.exe,a.methods),
      "originalChestInstancePositionsOrLevelProven":False,
      "limits":[
        "The word at +3 and the one-byte transform at +10 are *candidate* boundaries, not a proven original asset-loader cursor path.",
        "Offset +7 is incompatible with the 31-case factory in all 13 original source files, so a naive immediately-adjacent array subtype model is falsified.",
        "Offset +10 is the only offset in the first 32 bytes for which all 13 source bytes decode to valid native case IDs. This is a source-verified discriminator-pattern observation, not a certified field position.",
        "Native prelude must be analyzed by CFG and any nested call effects before assigning the additional three bytes to a particular original reader.",
        "No historical Lua, community JSON or AstaPS drop semantics are used."
      ]
    }
    a.output.parent.mkdir(parents=True,exist_ok=True)
    a.output.write_text(json.dumps(result,ensure_ascii=False,indent=2)+"\n",encoding="utf-8")
    print("ORIGINAL_POINT_ELEMENT_PREFIX_BEGIN")
    print(json.dumps({
      "crossScene":{"candidateLengths":result["sourcePrefixCrossSceneGate"]["candidateArraysLengthsFromOriginal13SourcePrefixes"],
      "directAfterCount":result["sourcePrefixCrossSceneGate"]["all32SourceOffsetsDiscriminatorCensus"][7],
      "firstSupported":result["sourcePrefixCrossSceneGate"]["sourceSubtypeAtOffset10Candidate"],
      "allPassingOffsets":[r["offset"] for r in result["sourcePrefixCrossSceneGate"]["all32SourceOffsetsDiscriminatorCensus"] if r["all13OriginalSourceSamplesFitNativeFactory"]]},
      "nativeSourceTrace":result["sourceOriginalNativeArrayReader"],
    },ensure_ascii=False,indent=2))
    print("ORIGINAL_POINT_ELEMENT_PREFIX_END")

if __name__=="__main__":
    main()
