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


def investigate(exe: Path, methods: Path, prior: Path) -> dict:
    starts, metadata = validate_source(methods, prior)
    require_sha256(exe, PROFILE_71.exe_sha256, label="original Global 7.1 executable")
    with PEImage(exe) as pe:
        raw = pe.read_rva(TARGET, 0x620)
        if len(raw) != 0x620 or hashlib.sha256(raw).hexdigest() != SOURCE_WINDOW_SHA:
            raise ValueError("original 7.1 reader native method byte hash mismatch")
        raw_calls = scan_direct_call_xrefs(exe, [TARGET], methods_csv=None, window=12)["matches"][f"0x{TARGET:X}"]
        if len(raw_calls) > MAX_MATCHES:
            raise ValueError("too many original native direct-call candidates")
        witnesses = [verify_direct_call_alignment(pe, starts, metadata, r)
                     for r in raw_calls]

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
    for name in ("exe","methods","prior","output"):
        p.add_argument("--"+name,type=Path,required=True)
    a=p.parse_args()
    report=investigate(a.exe,a.methods,a.prior)
    a.output.parent.mkdir(parents=True,exist_ok=True)
    a.output.write_text(json.dumps(report,indent=2,ensure_ascii=False)+"\n",encoding="utf-8")
    print("ORIGINAL_POINT_READER_CALLERS_BEGIN")
    print(json.dumps({
       "status":report["status"],
       "nativeDirectCallByteMatches":report["originalDirectCallByteMatches"],
       "alignedOriginalDirectCallCount":report["alignedOriginalDirectCallCount"],
       "directCallCandidates":report["directCallCandidates"],
       "nativeMethodPointerHolderCount":report["nativeMethodPointerHolderCount"],
       "nativeMethodPointerHoldersWithCodeXrefs":report["nativeMethodPointerHoldersWithCodeXrefs"],
       "nativeMethodPointerHolders":report["nativeMethodPointerHolders"][:50],
    },ensure_ascii=False,indent=2))
    print("ORIGINAL_POINT_READER_CALLERS_END")


if __name__=="__main__":
    main()
