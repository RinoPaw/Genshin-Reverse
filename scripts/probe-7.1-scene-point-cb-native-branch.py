#!/usr/bin/env python3
"""Global 7.1 exact original native CCPCOHEPGHC reader branch for input 0xCB.

Original source SHA guards are mandatory. Branch evidence alone cannot prove
total consumed bytes, Scene/Point loader binding, chest coordinates or levels.
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

RVA=0x12498FE0
OWNER="CCPCOHEPGHC"
METHOD="GMENPOPMKAA"
INDEX=173227
PREFIX_SIZE=0x220
PREFIX_SHA="4dc0d197c153cb88a8f54e65cc7300c8fa9cefa96b1054bd3c9277feaa4cf0c2"
METHODS_SHA="a9c106a7fdd5fe97ad204d6f4641c1e2c8d5433a"
SCENES="versions/7.1.0-global/analyses/progression/world/7.1-original-scene-point-source-payload-census.json"
PRIOR="versions/7.1.0-global/analyses/progression/world/7.1-original-scene-point-parent-mask-native-callchain.json"


def blob_sha(path:Path)->str:
    h=hashlib.sha1()
    h.update(f"blob {path.stat().st_size}\0".encode("ascii"))
    with path.open("rb") as file:
        for chunk in iter(lambda:file.read(1<<20),b""):
            h.update(chunk)
    return h.hexdigest()


def source_guards(methods:Path,prior:Path,scenes:Path):
    if blob_sha(methods)!=METHODS_SHA:raise ValueError("original method-index blob drift")
    p=json.loads(prior.read_text(encoding="utf-8"))
    s=json.loads(scenes.read_text(encoding="utf-8"))
    n=p["nativeIntermediateReader"]
    if (p["originalExeSha256"]!=PROFILE_71.exe_sha256
        or n["nativeRva"]!=f"0x{RVA:X}" or n["methodIndex"]!=INDEX
        or n["nativeWindowSha256"]!=PREFIX_SHA
        or s["exactOriginalExeSha256"]!=PROFILE_71.exe_sha256
        or s["scenesChecked"]!=13 or len(s["assetRows"])!=13
        or any(bytes.fromhex(x["unwrappedPayloadFirst32Hex"])[2]!=0xCB
               for x in s["assetRows"])):
        raise ValueError("original client Scene Point parent/samples drift")
    starts,by_start=_load_method_starts(methods)
    rows=by_start.get(RVA,[])
    if len(rows)!=1 or (rows[0]["type_name"],rows[0]["method_name"],
                          int(rows[0]["method_index"]))!=(OWNER,METHOD,INDEX):
        raise ValueError("original CCPCOHEPGHC metadata owner drift")
    return starts



CB_BASIC_BLOCKS=(
  (0x12499031,0x1249904B,0x12499144),
  (0x12499144,0x1249915F,0x12499278),
  (0x12499278,0x12499286,0x124993A7),
  (0x124993A7,0x124993B6,0x124994D1),
  (0x124994D1,0x124994E0,0x124995E4),
  (0x124995E4,0x124995FF,None),
)
CB_SOURCE_BRANCHES={
  0x1249904B:("je",0x12499144),
  0x1249915F:("je",0x12499278),
  0x12499286:("js",0x124993A7),
  0x124993B6:("je",0x124994D1),
  0x124994E0:("je",0x124995E4),
}
CB_SOURCE_INSTRUCTIONS={
  0x12499031:"movzx r15d, byte ptr [rax + rcx + 0x20]",
  0x12499037:"inc ecx",
  0x12499039:"mov dword ptr [r12], ecx",
  0x1249903D:"test r15b, 0x10",
  0x1249914B:"mov r13d, r15d",
  0x1249914E:"xor r13b, 0xcb",
  0x12499156:"test r13b, 8",
  0x12499283:"test r15b, r15b",
  0x124993B2:"test r15b, 0x20",
  0x124994DC:"test r13b, 1",
  0x124995FF:"ret",
}


def prove_single_byte_cb_route(instructions:list[dict],image_base:int)->dict:
    """Verify source basic-block path for 0xCB through one read and native RET."""
    by={int(x["rva"],16):x for x in instructions}
    indices={int(x["rva"],16):i for i,x in enumerate(instructions)}
    for addr,op in CB_SOURCE_INSTRUCTIONS.items():
        if by.get(addr,{}).get("op")!=op:
            raise ValueError(f"original 0xCB source native witness mismatch at {addr:X}")
    for addr,(branch,target) in CB_SOURCE_BRANCHES.items():
        if by.get(addr,{}).get("op")!=f"{branch} 0x{image_base+target:x}":
            raise ValueError(f"original 0xCB source branch target mismatch at {addr:X}")
    if (0xCB&0x10) or ((0xCB^0xCB)&8) or not(0xCB&0x80) or (0xCB&0x20):
        raise ValueError("original 0xCB conditional predicate drift")
    executed=[]
    evidence=[]
    for first,last,target in CB_BASIC_BLOCKS:
        if first not in indices or last not in indices or indices[first]>indices[last]:
            raise ValueError("invalid 0xCB source native basic-block boundaries")
        block=instructions[indices[first]:indices[last]+1]
        if target is None and block[-1]["op"]!="ret":
            raise ValueError("0xCB path has no native return")
        evidence.append({"firstRva":f"0x{first:X}","lastRva":f"0x{last:X}",
                         "nextRva":None if target is None else f"0x{target:X}",
                         "sourceNativeInstructions":block})
        executed.extend(block)
    source_reads=[x for x in executed if
        "byte ptr [rax + rcx + 0x20]" in x["op"] or
        "word ptr [rax + rcx + 0x20]" in x["op"] or
        "dword ptr [rax + rcx + 0x20]" in x["op"]]
    cursor_writes=[x for x in executed if x["op"].startswith((
        "mov dword ptr [r12]","add dword ptr [r12]","inc dword ptr [r12]"))]
    hidden_calls=[x for x in executed if x["op"].startswith(("call ","jmp "))]
    if ([x["rva"] for x in source_reads]!=["0x12499031"]
        or [x["rva"] for x in cursor_writes]!=["0x12499039"] or hidden_calls):
        raise ValueError("source original 0xCB path has unexpected input effect")
    return {
        "candidateInputByte":"0xCB",
        "xoredFlagByte":"0x00",
        "sourceBlocks":evidence,
        "nativeConditionalBranchesVerified":len(CB_SOURCE_BRANCHES),
        "nativeStreamByteReadsAlongPath":1,
        "nativeStreamCursorWritesAlongPath":1,
        "nativeHelperCallsAlongPath":0,
        "sourceReturnRva":"0x124995FF",
        "sourceNativeHelperConsumesExactlyOneByteFor0xCB":True,
        "originalScenePointAssetLoaderAndStartingCursorVerified":False,
    }


def inspect(exe:Path,methods:Path,prior:Path,scenes:Path):
    starts=source_guards(methods,prior,scenes)
    require_sha256(exe,PROFILE_71.exe_sha256,label="original Global 7.1 executable")
    i=bisect_right(starts,RVA)
    if i>=len(starts):raise ValueError("no original next method boundary")
    size=starts[i]-RVA
    if not PREFIX_SIZE<=size<=0x10000:raise ValueError("native body size out of bound")
    from capstone import Cs,CS_ARCH_X86,CS_MODE_64
    with PEImage(exe) as pe:
        data=pe.read_rva(RVA,size)
        if len(data)!=size or hashlib.sha256(data[:PREFIX_SIZE]).hexdigest()!=PREFIX_SHA:
            raise ValueError("source original CCPCO native bytes mismatch")
        md=Cs(CS_ARCH_X86,CS_MODE_64)
        ins=[{"rva":f"0x{x.address-pe.image_base:X}",
              "op":f"{x.mnemonic} {x.op_str}".strip(),
              "bytes":bytes(x.bytes).hex()} for x in md.disasm(data,pe.image_base+RVA)]
        byaddr={x["rva"]:x for x in ins}
        exact={
           "0x12499031":"movzx r15d, byte ptr [rax + rcx + 0x20]",
           "0x12499037":"inc ecx",
           "0x12499039":"mov dword ptr [r12], ecx",
           "0x1249903D":"test r15b, 0x10",
           "0x1249904B":f"je 0x{pe.image_base+0x12499144:x}"
        }
        for addr,op in exact.items():
            if addr not in byaddr or byaddr[addr]["op"]!=op:
                raise ValueError(f"original 0xCB conditional native evidence drift {addr}")
    if 0xCB&0x10:raise ValueError("0xCB bit branch condition unexpected")
    tail_checks={
       "0x1249914B":"mov r13d, r15d",
       "0x1249914E":"xor r13b, 0xcb",
       "0x12499156":"test r13b, 8",
       "0x1249915F":f"je 0x{pe.image_base+0x12499278:x}",
       "0x12499283":"test r15b, r15b",
       "0x12499286":f"js 0x{pe.image_base+0x124993A7:x}",
    }
    for addr,op in tail_checks.items():
        if addr not in byaddr or byaddr[addr]["op"]!=op:
            raise ValueError(f"native 0xCB follow-on branch mismatch at {addr}")
    at=next(i for i,x in enumerate(ins) if x["rva"]=="0x12499144")
    cb_path=prove_single_byte_cb_route(ins,pe.image_base)
    context=ins[max(0,at-8):at+155]
    accesses=[x for x in ins if
              "dword ptr [r12]" in x["op"] or
              "byte ptr [rax + rcx + 0x20]" in x["op"] or
              "word ptr [rax + rcx + 0x20]" in x["op"] or
              "dword ptr [rax + rcx + 0x20]" in x["op"]]
    flags=[x for x in ins if x["op"].startswith(("test r15","test r12","and r15","cmp r15","test bl","test ebx"))]
    return {
       "schemaVersion":1,"status":"EXACT_ORIGINAL_7_1_CB_SINGLE_BYTE_HELPER_RETURN_CONFIRMED__SCENE_LOADER_UNVERIFIED",
       "originalExeSha256":PROFILE_71.exe_sha256,"methodsGitBlob":METHODS_SHA,
       "originalOwner":OWNER,"originalMethod":METHOD,"methodIndex":INDEX,
       "nativeRva":f"0x{RVA:X}","nextOriginalMethodRva":f"0x{starts[i]:X}",
       "nativeBodyBytes":size,"nativeBodySha256":hashlib.sha256(data).hexdigest(),
       "decodedInstructionCount":len(ins),
       "sourceFirstByteInstructions":[byaddr[x] for x in exact],
       "candidateByte0xCBMask0x10Result":0,
       "sourceNativeTakenJumpDestinationRva":"0x12499144",
       "nativeTargetContext":context,
       "sourceCursorReadWriteOperations":accesses[:160],
       "sourceFlagOperations":flags[:160],
       "sourceXoredCBValue":0,
       "sourceNativeCBSecondJumpTarget":"0x12499278",
       "sourceNativeCBSignedThirdJumpTarget":"0x124993A7",
       "sourceCBFollowUpConditionalInstructions":[byaddr[x] for x in tail_checks],
       "completeOriginalNativeInstructions":ins,
       "directCalls":[x for x in ins if x["op"].startswith("call ")][:200],
       "all13OriginalScenePointThirdBytesMatchCB":True,
       "clientPointAssetLoaderLinkedToThisMethod":False,
       "sourceSubreaderConsumesExactlyOneByteForCB":True,
       "exactOneByteCBSourcePath":cb_path,
       "originalScenePointArrayOffsetThreeConfirmed":False,
       "originalArrayOffsetThreeConditionalOnSourcePayloadAtCursorZero":True,
       "chestInstanceOrLevelProven":False,
       "limits":[
        "The 0xCB first-byte and its one conditional branch are verified against original EXE, with 13 source-authenticated sample prefixes.",
        "Method branch includes further operations not modeled; true cursor position and row parsing require complete CFG and relevant nested call effects.",
        "No semantic names, native client scene asset loader or chest placement are inferred."
       ]
    }


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ("exe","methods","prior","scenes","output"):
        parser.add_argument("--"+name,type=Path,required=True)
    a=parser.parse_args()
    out=inspect(a.exe,a.methods,a.prior,a.scenes)
    a.output.parent.mkdir(parents=True,exist_ok=True)
    a.output.write_text(json.dumps(out,ensure_ascii=False,indent=2)+"\n",encoding="utf-8")
    print("ORIGINAL_CB_PATH_BEGIN")
    print(json.dumps(out,ensure_ascii=False,indent=2))
    print("ORIGINAL_CB_PATH_END")


if __name__=="__main__":
    main()
