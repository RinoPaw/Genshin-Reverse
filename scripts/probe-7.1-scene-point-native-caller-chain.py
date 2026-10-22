#!/usr/bin/env python3
"""Follow SHA-pinned original Global 7.1 native array reader callers.

The only proven callee is NLDEPJEOJGC.GMENPOPMKAA @ RVA 0xAD23000.
Direct E8 call bytes, independently disassembled instruction boundaries,
original methods.csv owners and potential file-backed qword pointer holders
are separate evidence. No link to Scene/Point is assumed from byte
compatibility of the array length alone.
"""
from __future__ import annotations

import argparse
from bisect import bisect_right
import csv
import hashlib
import json
from pathlib import Path

from genshinre.callxref import scan_direct_call_xrefs, _load_method_starts
from genshinre.pointerxref import scan_pointer_xrefs
from genshinre.nativeprofile import PROFILE_71
from genshinre.pe import PEImage
from genshinre.sampleidentity import require_sha256

TARGET = 0xAD23000
METHOD_INDEX = 514423
OWNER = "NLDEPJEOJGC"
METHOD = "GMENPOPMKAA"
SOURCE_WINDOW_SHA = "6319613278adf382bf7ce513d1d875ef98b318d5f5f3bc9c423b72caebd7c0ad"
METHODS_GIT_BLOB = "a9c106a7fdd5fe97ad204d6f4641c1e2c8d5433a"
PRIOR_SCENE_POINT = "versions/7.1.0-global/analyses/progression/world/7.1-original-scene-point-native-xor-reader-evidence.json"
MAX_CALLER_WINDOW = 0x4000
MAX_MATCHES = 200
MAX_HOLDERS = 200
PARENT_RVA = 0xEE66B20
PARENT_TYPE = "IJNOFJEOMBD"
PARENT_METHOD_INDEX = 171707
PARENT_CALL_RVA = 0xEE66BF1
PARENT_CALL_PREFIX_SHA = "f13a9f477ddb05c65f5bf70e81e3fdde6fbb59ff70299cc3be479a839ab1a31f"
FIELDS_GIT_BLOB = "ae01d117f4d884e891a95d529a15302a68715b04"


def git_blob(path: Path) -> str:
    h = hashlib.sha1()
    h.update(f"blob {path.stat().st_size}\0".encode("ascii"))
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def validate_source(methods: Path, prior: Path) -> tuple[list[int], dict]:
    if git_blob(methods) != METHODS_GIT_BLOB:
        raise ValueError("exact original Global 7.1 methods.csv Git-blob mismatch")
    j = json.loads(prior.read_text(encoding="utf-8"))
    native = j["sourceNativeArrayCountReader"]
    if (j["originalExeSha256"] != PROFILE_71.exe_sha256
            or j["originalMethodsGitBlob"] != METHODS_GIT_BLOB
            or (native["originalMethodRva"], native["originalMethodIndex"],
                native["originalMethodWindowSha256"], native["originalTypeName"]) !=
               (f"0x{TARGET:X}", METHOD_INDEX, SOURCE_WINDOW_SHA, OWNER)
            or not native["genericNativeU32XorCountReaderProven"]):
        raise ValueError("original 7.1 native count reader evidence drift")
    starts, metadata = _load_method_starts(methods)
    rows = metadata.get(TARGET, [])
    if len(rows) != 1 or (rows[0]["type_name"], rows[0]["method_name"],
                           int(rows[0]["method_index"])) != (OWNER, METHOD, METHOD_INDEX):
        raise ValueError("exact original count reader callee identity mismatch")
    p = metadata.get(PARENT_RVA, [])
    if len(p) != 1 or (p[0]["type_name"], p[0]["method_name"],
                       int(p[0]["method_index"])) != (PARENT_TYPE, METHOD, PARENT_METHOD_INDEX):
        raise ValueError("original 7.1 outer array owner metadata changed")
    return starts, metadata


def verify_direct_call_alignment(pe: PEImage, starts: list[int],
                                 metadata: dict, call: dict) -> dict:
    """Decode from authenticated metadata method start, no guessed call alignment."""
    from bisect import bisect_right
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64

    site = int(call["instruction_rva"], 16)
    index = bisect_right(starts, site) - 1
    if index < 0:
        return {"callRva":call["instruction_rva"], "alignedNativeCall":False,
                "status":"NO_ORIGINAL_METHOD_START"}
    method_start = starts[index]
    next_start = starts[index + 1] if index + 1 < len(starts) else None
    span = site + 5 - method_start
    if (span < 5 or span > MAX_CALLER_WINDOW or
            (next_start is not None and site >= next_start)):
        return {"callRva":call["instruction_rva"], "alignedNativeCall":False,
                "status":"SOURCE_METHOD_BOUNDARY_UNAVAILABLE",
                "candidateMethodRva":f"0x{method_start:X}"}
    source = pe.read_rva(method_start, span)
    if len(source) != span:
        raise ValueError("original caller source method not file-backed")
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    ins = list(md.disasm(source, pe.image_base + method_start))
    matching = [x for x in ins if x.address - pe.image_base == site and
                x.mnemonic == "call" and len(x.bytes) == 5 and
                bytes(x.bytes).hex() == call["instruction_hex"] and
                x.op_str.lower() == f"0x{pe.image_base + TARGET:x}"]
    if not matching:
        return {"callRva":call["instruction_rva"], "alignedNativeCall":False,
                "status":"NO_ALIGNED_E8_IN_ORIGINAL_METHOD",
                "candidateMethodRva":f"0x{method_start:X}"}
    x = matching[0]
    site_ix = next(i for i, y in enumerate(ins) if y.address == x.address)
    context = [
        {"rva":f"0x{y.address - pe.image_base:X}",
         "instruction":f"{y.mnemonic} {y.op_str}".strip(),
         "bytes":bytes(y.bytes).hex()}
        for y in ins[max(0, site_ix-10):site_ix+5]
    ]
    return {
        "callRva":f"0x{site:X}",
        "alignedNativeCall":True,
        "status":"EXACT_NATIVE_ALIGNED_DIRECT_CALL",
        "originalCallerMethodRva":f"0x{method_start:X}",
        "originalCallerMethodOwners":[{
            "typeName":r["type_name"],
            "typeDefinitionIndex":int(r["type_definition_index"]),
            "methodName":r["method_name"],
            "methodIndex":int(r["method_index"]),
            "parameterTypes":r.get("parameter_types", ""),
        } for r in metadata[method_start]],
        "nativeOriginalCallOpcode":bytes(x.bytes).hex(),
        "sourcePrefixSha256":hashlib.sha256(source).hexdigest(),
        "sourcePrefixBytes":len(source),
        "instructionContext":context,
        "scenePointAssetPathConsumerProven":False,
    }



def inspect_parent_native_method(pe: PEImage, starts: list[int],
                                 metadata: dict) -> dict:
    """Record exact 7.1 parent reader and its *local* source instruction chain."""
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64

    ix = bisect_right(starts, PARENT_RVA)
    if ix >= len(starts):
        raise ValueError("no source method successor for original parent parser")
    next_start = starts[ix]
    size = next_start - PARENT_RVA
    if not 0 < size <= MAX_CALLER_WINDOW:
        raise ValueError("source parent method native window exceeds bound")
    code = pe.read_rva(PARENT_RVA, size)
    if len(code) != size:
        raise ValueError("truncated original outer parser")
    if hashlib.sha256(code[:PARENT_CALL_RVA + 5 - PARENT_RVA]).hexdigest() != PARENT_CALL_PREFIX_SHA:
        raise ValueError("outer source native prefix differs from original first verified caller run")
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    original = list(md.disasm(code, pe.image_base + PARENT_RVA))
    instructions = [{
       "rva": f"0x{x.address - pe.image_base:X}",
       "mnemonic": x.mnemonic, "operands": x.op_str,
       "opcode": bytes(x.bytes).hex(),
    } for x in original]
    known = {x["rva"]:x for x in instructions}
    required = {
        "0xEE66BDB":("lea","rax, [r14 + 0x30]"),
        "0xEE66BDF":("test","ebx, 0x4000"),
        "0xEE66BE5":("je",None),
        "0xEE66BEB":("mov","rcx, rdi"),
        "0xEE66BEE":("mov","rdx, rax"),
        "0xEE66BF1":("call",f"0x{pe.image_base + TARGET:X}".lower()),
    }
    for rva,(mnemonic,operands) in required.items():
        obj = known.get(rva)
        if obj is None or obj["mnemonic"] != mnemonic or (
            operands is not None and obj["operands"].lower() != operands.lower()
        ):
            raise ValueError(f"exact original parent pointer/flag/call witness drift: {rva}")
    first = instructions[:60]
    ix_call = next(i for i,x in enumerate(instructions) if x["rva"]=="0xEE66BF1")
    local=instructions[max(0,ix_call-24):ix_call+14]
    transfer=[]
    for row in instructions:
        if row["mnemonic"]!="call":continue
        if not row["operands"].startswith("0x"):continue
        dest=int(row["operands"],16)
        if dest>=pe.image_base:
            transfer.append({"siteRva":row["rva"],
                             "targetRva":f"0x{dest-pe.image_base:X}"})
    return {
       "originalOwner":PARENT_TYPE,
       "originalMethod":METHOD,
       "originalMethodIndex":PARENT_METHOD_INDEX,
       "readerRva":f"0x{PARENT_RVA:X}",
       "nativeSourceBytes":size,
       "nativeSourceSha256":hashlib.sha256(code).hexdigest(),
       "entireMetadataWindowDisassembled":True,
       "nativeInstructions":len(instructions),
       "firstNativeInstructions":first,
       "sourceVerifiedSubobjectAddressCalculation":known["0xEE66BDB"],
       "sourceVerifiedFlagCheck":known["0xEE66BDF"],
       "sourceVerifiedCall":known["0xEE66BF1"],
       "nativeCallContext":local,
       "directCalleeTargets":transfer,
       "linkedNestedBinaryReaderRva":f"0x{TARGET:X}",
       "subobjectOwnerFieldTokenProven":False,
       "sourceScenePointResourcePathProven":False
    }


def original_parent_fields(path: Path) -> list[dict]:
    if git_blob(path)!=FIELDS_GIT_BLOB:
        raise ValueError("exact original Global 7.1 fields.csv Git-blob mismatch")
    rows=[]
    with path.open("r",encoding="utf-8-sig",newline="") as stream:
        for row in csv.DictReader(stream):
            if int(row["type_definition_index"])!=22426:continue
            if row["type_name"]!=PARENT_TYPE:
                raise ValueError("original outer binary class field owner changed")
            rows.append({
                "originalFieldIndex":int(row["field_index"]),
                "originalObfuscatedToken":row["field_name"],
                "originalType":row["field_type"],
                "originalRuntimeTypeIndex":int(row["field_type_index"]),
                "originalMetadataOffset":row.get("offset") or None,
            })
    if not rows:
        raise ValueError("original outer binary class fields missing")
    return rows



SCENE_POINT_SOURCE_REPORT = "versions/7.1.0-global/analyses/progression/world/7.1-original-scene-point-source-payload-census.json"
NATIVE_CHILD_PRECURSOR_RVA=0x12498FE0
NATIVE_CHILD_PRECURSOR_CALL_RVA=0xEE66BD6


def scene_point_mask_prefix_census(source: Path)->dict:
    """Source-observed prefixes aligned against verified native outer mask arithmetic."""
    import struct
    j=json.loads(source.read_text(encoding="utf-8"))
    if (j["exactOriginalExeSha256"] != PROFILE_71.exe_sha256
        or j["exactOriginalDesignIndexRawSha256"] !=
          "fe1e1ce970e3aa72e764b0894d94a684b7a49edc9f3ae6a32c4d7f38d8a64712"
        or j["source"]["exactBranchCommit"] !=
          "63980a635f7202ab7dd4b964047c0788108db893"
        or j["scenesChecked"]!=13
        or j["statusCounts"]!={"SOURCE_RAW_AND_FRAMING_VERIFIED":13}):
        raise ValueError("original 7.1 Scene Point source-prefix census identity drift")
    out=[]
    for row in j["assetRows"]:
        b=bytes.fromhex(row["unwrappedPayloadFirst32Hex"])
        word=struct.unpack_from("<H",b)[0]
        mask=(word+0xF077)&0xFFFF
        out.append({
            "sceneId":row["sceneId"],
            "originalFirstThreeBytesHex":b[:3].hex(),
            "originalSourceU16":f"0x{word:04X}",
            "candidateOuterNativeMask":f"0x{mask:04X}",
            "sourceFlag8000IfReaderStartsAtZero":bool(mask&0x8000),
            "sourceFlag4000IfReaderStartsAtZero":bool(mask&0x4000),
            "candidateByteAtOffset2":f"0x{b[2]:02X}",
            "originalRootParserUsesTheseFirstBytesProven":False,
        })
    if len(out)!=13:
        raise ValueError("source scene point asset row count drift")
    return {
        "rows":out,
        "all13HaveNativeOuterFlag8000":all(x["sourceFlag8000IfReaderStartsAtZero"] for x in out),
        "all13HaveNativeOuterFlag4000":all(x["sourceFlag4000IfReaderStartsAtZero"] for x in out),
        "all13HaveSameByteAtOffset2":len({x["candidateByteAtOffset2"] for x in out})==1,
        "originalRootParserActuallyConsumedTheseBytes":False,
        "nativeSingleBytePrecursorConsumerVerified":False,
    }


def inspect_precursor_native(pe:PEImage,starts:list[int],metadata:dict)->dict:
    """Inspect only the source file-backed helper called before nested array reader."""
    from capstone import Cs,CS_ARCH_X86,CS_MODE_64
    idx=bisect_right(starts,NATIVE_CHILD_PRECURSOR_RVA)
    next_start=starts[idx] if idx<len(starts) else None
    window=min((next_start-NATIVE_CHILD_PRECURSOR_RVA) if next_start is not None else 0x220, 0x220)
    if window<16:
        raise ValueError("original preceding native helper cannot be inspected")
    buf=pe.read_rva(NATIVE_CHILD_PRECURSOR_RVA,window)
    if len(buf)!=window:
        raise ValueError("original preceding native helper bytes not file backed")
    md=Cs(CS_ARCH_X86,CS_MODE_64)
    ops=[{"rva":f"0x{ins.address-pe.image_base:X}",
           "op":f"{ins.mnemonic} {ins.op_str}".strip(),
           "bytes":bytes(ins.bytes).hex()} for ins in md.disasm(buf,pe.image_base+NATIVE_CHILD_PRECURSOR_RVA)]
    return {
       "nativeHelperRva":f"0x{NATIVE_CHILD_PRECURSOR_RVA:X}",
       "nativeHelperWindowBytes":window,
       "nativeHelperSha256":hashlib.sha256(buf).hexdigest(),
       "sourceExactMethodStartOwners":[{
          "typeName":x["type_name"],"methodName":x["method_name"],
          "methodIndex":int(x["method_index"])
       } for x in metadata.get(NATIVE_CHILD_PRECURSOR_RVA,[])],
       "firstNativeInstructions":ops[:75],
       "sourceCallSiteRva":f"0x{NATIVE_CHILD_PRECURSOR_CALL_RVA:X}",
       "sourceHelperConsumesExactOneByteProven":False,
       "sourceScenePointInputProven":False,
    }


def investigate(exe: Path, methods: Path, prior: Path, fields: Path, scene_assets:Path) -> dict:
    starts, metadata = validate_source(methods, prior)
    require_sha256(exe, PROFILE_71.exe_sha256, label="original Global 7.1 executable")
    with PEImage(exe) as pe:
        raw = pe.read_rva(TARGET, 0x620)
        if len(raw) != 0x620 or hashlib.sha256(raw).hexdigest() != SOURCE_WINDOW_SHA:
            raise ValueError("original 7.1 reader native method byte hash mismatch")
        matches = scan_direct_call_xrefs(exe, [TARGET,PARENT_RVA], methods_csv=None, window=12)["matches"]
        raw_calls = matches[f"0x{TARGET:X}"]
        parents = matches[f"0x{PARENT_RVA:X}"]
        if len(raw_calls)>MAX_MATCHES or len(parents)>MAX_MATCHES:
            raise ValueError("too many original native direct-call candidates")
        witnesses = [verify_direct_call_alignment(pe, starts, metadata, r) for r in raw_calls]
        parent_callers = [verify_direct_call_alignment(pe, starts, metadata, r) for r in parents]
        outer = inspect_parent_native_method(pe, starts, metadata)
        precursor = inspect_precursor_native(pe, starts, metadata)

    ptrs = scan_pointer_xrefs(exe, TARGET, TARGET + 1, window=16)
    if ptrs["holder_count"] > MAX_HOLDERS:
        raise ValueError("original native method holder count outside bound")

    # A method pointer is evidence of registration/storage, not necessarily
    # a runtime call or a consumer of a Scene Point asset.
    return {
        "schemaVersion": 1,
        "status":"EXACT_ORIGINAL_7_1_XOR_ARRAY_READER_CALLER_AND_METHOD_POINTER_CENSUS__SCENE_POINT_LINK_UNVERIFIED",
        "originalExeSha256":PROFILE_71.exe_sha256,
        "originalMethodsGitBlob":METHODS_GIT_BLOB,
        "sourcePrior":PRIOR_SCENE_POINT,
        "nativeTargetRva":f"0x{TARGET:X}",
        "nativeTargetOwner":OWNER,
        "nativeTargetMethod":METHOD,
        "nativeTargetMethodIndex":METHOD_INDEX,
        "nativeTargetMethodSha256":SOURCE_WINDOW_SHA,
        "originalDirectCallByteMatches":len(raw_calls),
        "alignedOriginalDirectCallCount":sum(x["alignedNativeCall"] for x in witnesses),
        "directCallCandidates":witnesses,
        "nativeParentReader":outer,
        "nativeParentPrecursorReader":precursor,
        "originalScenePointHeaderMaskCrossSample":scene_point_mask_prefix_census(scene_assets),
        "nativeParentOriginalFieldDeclarations":original_parent_fields(fields),
        "originalParentDirectCallByteMatches":len(parents),
        "alignedOriginalParentDirectCallCount":sum(x["alignedNativeCall"] for x in parent_callers),
        "originalParentCallerCandidates":parent_callers,
        "nativeMethodPointerHolderCount":ptrs["holder_count"],
        "nativeMethodPointerHoldersWithCodeXrefs":ptrs["holders_with_code_xrefs"],
        "nativeMethodPointerHolders":ptrs["holders"],
        "directOrIndirectScenePointAssetReaderLinkProven":False,
        "originalScenePointPrefixCursorOffset3Proven":False,
        "originalScenePointRowsDecoded":False,
        "originalChestGadgetPlacementSourceProven":False,
        "limits":[
           "A verified E8 direct call to a native method is not a link to a specific file path unless the original loader input is proven.",
           "A file-backed qword reference to the method is method registration/pointer data, not a proof of runtime invocation.",
           "An aligned method owner or a string name cannot establish the client Scene Point content schema.",
           "The count XOR method remains a source-verified general parser. No original chest position, Gadget instance or server ownership follows.",
        ],
    }


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ("exe","methods","prior","fields","scene-assets","output"):
        p.add_argument("--"+name,type=Path,required=True)
    a=p.parse_args()
    report=investigate(a.exe,a.methods,a.prior,a.fields,a.scene_assets)
    a.output.parent.mkdir(parents=True,exist_ok=True)
    a.output.write_text(json.dumps(report,indent=2,ensure_ascii=False)+"\n",encoding="utf-8")
    print("ORIGINAL_POINT_READER_CALLERS_BEGIN")
    print(json.dumps({
       "status":report["status"],
       "nativeDirectCallByteMatches":report["originalDirectCallByteMatches"],
       "alignedOriginalDirectCallCount":report["alignedOriginalDirectCallCount"],
       "directCallCandidates":report["directCallCandidates"],
       "nativeParentReader":report["nativeParentReader"],
       "nativeParentPrecursorReader":report["nativeParentPrecursorReader"],
       "originalScenePointHeaderMaskCrossSample":report["originalScenePointHeaderMaskCrossSample"],
       "originalParentDirectCallByteMatches":report["originalParentDirectCallByteMatches"],
       "originalParentCallerCandidates":report["originalParentCallerCandidates"],
       "nativeParentOriginalFieldDeclarations":report["nativeParentOriginalFieldDeclarations"],
       "nativeMethodPointerHolderCount":report["nativeMethodPointerHolderCount"],
       "nativeMethodPointerHoldersWithCodeXrefs":report["nativeMethodPointerHoldersWithCodeXrefs"],
       "nativeMethodPointerHolders":report["nativeMethodPointerHolders"][:50],
    },ensure_ascii=False,indent=2))
    print("ORIGINAL_POINT_READER_CALLERS_END")


if __name__=="__main__":
    main()
