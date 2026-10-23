#!/usr/bin/env python3
"""Audit original Global 7.1 ctor-owning types using original EXE and metadata.

Original binary and metadata SHA-256 plus original generated methods/fields
Git blobs are mandatory. These are declarations and exact code RVA anchors,
not proof of vtable +0xF8, of static Il2CppClass identity or chest data.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
from pathlib import Path
from genshinre.nativeprofile import PROFILE_71
from genshinre.pe import PEImage
from genshinre.sampleidentity import require_sha256

CASE_REPORT = "versions/7.1.0-global/analyses/progression/world/7.1-original-point-factory-case-1-14-local-native-paths.json"
METHODS_BLOB = "a9c106a7fdd5fe97ad204d6f4641c1e2c8d5433a"
FIELDS_BLOB = "ae01d117f4d884e891a95d529a15302a68715b04"
TARGETS = {
    1: ("BHJILFMHGEE", 54542, 436907, 0x138BA180, "0x57C37B0"),
    14: ("NKJPPNFAEEF", 65289, 527282, 0x8613310, "0x57C1970"),
}
NATIVE_PREFIX_BYTES = 0x80


def git_blob(path: Path) -> str:
    h = hashlib.sha1()
    h.update(f"blob {path.stat().st_size}\0".encode())
    with path.open("rb") as fp:
        for buf in iter(lambda: fp.read(1<<20), b""):
            h.update(buf)
    return h.hexdigest()


def source_cases(path: Path) -> list[dict]:
    prior = json.loads(path.read_text(encoding="utf-8"))
    if (prior["originalExeSha256"] != PROFILE_71.exe_sha256
        or prior["originalMetadataSha256"] != PROFILE_71.metadata_sha256
        or prior["originalMethodsGitBlob"] != METHODS_BLOB):
        raise ValueError("original constructor case proof mismatch")
    rows = prior["caseSlices"]
    if [x["numericFactoryCase"] for x in rows] != list(TARGETS):
        raise ValueError("original cases missing")
    for row in rows:
        case = row["numericFactoryCase"]
        owner, typedef, index, rva, slot = TARGETS[case]
        calls = [x for x in row["sourceDirectJumpFollow"]["sourceSteps"]
                 if x["mnemonic"] == "call"]
        if (row["originalClassSlotRva"] != slot or len(calls) != 2 or
            calls[1]["directTargetRva"] != f"0x{rva:X}" or
            calls[1]["exactOriginalMethodStartOwners"] != [{
                "typeName":owner,"methodName":".ctor",
                "methodIndex":index,"typeDefinitionIndex":typedef}]):
            raise ValueError("original source ctor / class-slot case mismatch")
    return rows


def select_rows(path: Path, target: str, limit: int) -> list[dict]:
    rows = []
    with path.open(encoding="utf-8-sig", newline="") as source:
        for row in csv.DictReader(source):
            if row.get("type_name") != target:
                continue
            rows.append(row)
            if len(rows) > limit:
                raise ValueError("original target type contains excessive rows")
    return rows


def analyze(exe: Path, metadata: Path, methods: Path, fields: Path, prior: Path) -> dict:
    source_cases(prior)
    require_sha256(exe, PROFILE_71.exe_sha256, label="original 7.1 EXE")
    require_sha256(metadata, PROFILE_71.metadata_sha256, label="original 7.1 metadata")
    if git_blob(methods) != METHODS_BLOB or git_blob(fields) != FIELDS_BLOB:
        raise ValueError("generated original metadata CSV blob identity drift")
    all_methods = {}
    all_fields = {}
    for _, (name, _, _, _, _) in TARGETS.items():
        all_methods[name] = select_rows(methods, name, 500)
        all_fields[name] = select_rows(fields, name, 500)
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    result = []
    with PEImage(exe) as pe:
        for case, (name, typedef, ctor_index, ctor_rva, slot) in TARGETS.items():
            methods_for_type = all_methods[name]
            fields_for_type = all_fields[name]
            if not methods_for_type or any(int(x["type_definition_index"]) != typedef
                for x in methods_for_type + fields_for_type):
                raise ValueError("original constructor owner type-definition drift")
            ctor = [x for x in methods_for_type
                    if int(x["method_index"]) == ctor_index and x["method_name"] == ".ctor"]
            if len(ctor) != 1 or int(ctor[0]["rva"], 0) != ctor_rva:
                raise ValueError("original declared ctor and native entry mismatch")
            native = pe.read_rva(ctor_rva, NATIVE_PREFIX_BYTES)
            if len(native) != NATIVE_PREFIX_BYTES:
                raise ValueError("original native constructor is not file-backed")
            # Authenticate one original native reader method declaration, and
            # bound its window by the next distinct declared native method RVA.
            reader = [x for x in methods_for_type
                      if x["method_name"] == "GMENPOPMKAA"]
            if len(reader) != 1:
                raise ValueError("original case constructor owner has no unique reader declaration")
            reader_rva = int(reader[0]["rva"], 0)
            following = sorted(int(x["rva"], 0) for x in methods_for_type
                               if int(x["rva"], 0) > reader_rva)
            if not following or not 0 < following[0] - reader_rva <= 0x5000:
                raise ValueError("native reader's following source method boundary unavailable")
            reader_window = pe.read_rva(reader_rva, following[0] - reader_rva)
            if len(reader_window) != following[0] - reader_rva:
                raise ValueError("original native reader window not file backed")
            native_instructions = list(md.disasm(reader_window, pe.image_base+reader_rva))
            if not native_instructions:
                raise ValueError("source native reader method cannot be disassembled")
            def op(ins):
                return {"rva":f"0x{ins.address-pe.image_base:X}",
                        "mnemonic":ins.mnemonic,"operands":ins.op_str,
                        "bytes":bytes(ins.bytes).hex()}
            native_reader = {
                "sourceOriginalMethod": "GMENPOPMKAA",
                "sourceOriginalMethodIndex": int(reader[0]["method_index"]),
                "sourceOriginalMethodRva": f"0x{reader_rva:X}",
                "sourceNextDeclaredMethodRva": f"0x{following[0]:X}",
                "sourceWindowBytes": len(reader_window),
                "sourceWindowSha256": hashlib.sha256(reader_window).hexdigest(),
                "sourceDisassemblyDecodedLinearInstructions": len(native_instructions),
                "sourceFirstNativeInstructions": [op(x) for x in native_instructions[:75]],
                "sourceNativeMovssInstructions": [op(x) for x in native_instructions
                    if x.mnemonic in ("movss", "movsd")][:80],
                "sourceNativeCalls": [op(x) for x in native_instructions
                    if x.mnemonic == "call"][:100],
                "sourceReturnCandidates": [op(x) for x in native_instructions
                    if x.mnemonic == "ret"][:30],
                "sourceReaderVtableSlotF8MappingProven": False,
                "sourceNativeLinearDisassemblyIsRuntimeExecutedProven": False,
            }
            # This is a bounded prefix only; do not claim it is the entire method.
            result.append({
                "originalFactoryNumericCase": case,
                "sourceClassSlotRva": slot,
                "originalConstructorType": name,
                "originalConstructorTypeDefinitionIndex": typedef,
                "originalConstructorMethodIndex": ctor_index,
                "sourceNativeCtorRva": f"0x{ctor_rva:X}",
                "sourceNativeCtorPrefixHex": native[:32].hex(),
                "sourceNativeCtorPrefixSha256": hashlib.sha256(native).hexdigest(),
                "sourceCtorPrefixMayIncludeFollowingFunction": True,
                "originalDeclaredMethodCount": len(methods_for_type),
                "originalDeclaredFieldCount": len(fields_for_type),
                "sourceOriginalDeclaredMethods": methods_for_type,
                "sourceOriginalDeclaredFields": fields_for_type,
                "sourceGMENPOPMKAADeclarations": [
                    x for x in methods_for_type if x["method_name"] == "GMENPOPMKAA"
                ],
                "sourceOriginalGMENPOPMKAANativeMethod": native_reader,
                "nativeVtablePlusF8TargetConfirmed": False,
                "nativeClassSlotToConcreteTypeProven": False,
            })
    return {
        "schemaVersion":1,
        "status":"ORIGINAL_GLOBAL_7_1_FACTORY_1_14_CTOR_OWNER_METADATA_AND_NATIVE_PREFIX__VTABLE_UNVERIFIED",
        "sourceOriginalExeSha256":PROFILE_71.exe_sha256,
        "sourceOriginalMetadataSha256":PROFILE_71.metadata_sha256,
        "sourceOriginalMethodsBlob":METHODS_BLOB,
        "sourceOriginalFieldsBlob":FIELDS_BLOB,
        "sourcePreviousCaseEvidence":CASE_REPORT,
        "originalCaseOwnerDeclarations":result,
        "sourceFactoryClassSlotToExactRuntimeClassProven":False,
        "sourceFactoryVtableSlotF8MethodOwnerProven":False,
        "originalScenePointLoaderOrChestCoordinatesLevelProven":False,
        "limitations":[
            "CSV indexes come from the SHA-pinned original client metadata and original generated Git blobs.",
            "A method declared on a constructor-owner type is not automatically bound to vtable slot +0xF8.",
            "A call into a constructor does not by itself prove a static factory runtime class-slot mapping.",
            "No Scene/Point loader, original chest placement, coordinate or level can be inferred."
        ],
    }


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for arg in ("exe","metadata","methods","fields","prior","output"):
        p.add_argument("--"+arg,type=Path,required=True)
    args=p.parse_args()
    data=analyze(args.exe,args.metadata,args.methods,args.fields,args.prior)
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(json.dumps(data,ensure_ascii=False,indent=2)+"\n",encoding="utf-8")
    print("ORIGINAL_71_FACTORY_CTOR_TYPES_BEGIN")
    print(json.dumps(data,ensure_ascii=False,indent=2))
    print("ORIGINAL_71_FACTORY_CTOR_TYPES_END")


if __name__ == "__main__":
    main()
