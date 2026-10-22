#!/usr/bin/env python3
"""Inspect bounded original Global 7.1 Scene Point-compatible factory case code.

Source: exact SHA-256-pinned original EXE plus original generated methods.csv.
A per-case linear instruction slice is not a runtime path, a concrete
Il2CppClass identity, or proof that Scene/Point assets reach this factory.
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

FACTORY_REPORT = "versions/7.1.0-global/analyses/progression/world/7.1-original-scene-point-array-element-factory-native-evidence.json"
FACTORY_RVA = 0xC591C60
TABLE_RVA = 0xC592094
FACTORY_BYTES = 0x4B0
SOURCE_SHA256 = "78a9930eef271eae79f9b4fdcc60a49e86ae95a8cc01d87181691c88fd365f06"
METHODS_GIT_BLOB = "a9c106a7fdd5fe97ad204d6f4641c1e2c8d5433a"
TARGET_CASES = (1, 14)


def git_blob(path: Path) -> str:
    sha = hashlib.sha1()
    sha.update(f"blob {path.stat().st_size}\0".encode("ascii"))
    with path.open("rb") as stream:
        for part in iter(lambda: stream.read(1 << 20), b""):
            sha.update(part)
    return sha.hexdigest()


def source_cases(path: Path) -> list[dict]:
    report = json.loads(path.read_text(encoding="utf-8"))
    factory = report["originalFactory"]
    cases = factory["sourceCases"]
    if (report["originalExeSha256"] != PROFILE_71.exe_sha256
        or report["originalMetadataSha256"] != PROFILE_71.metadata_sha256
        or factory["originalSourceWindowSha256"] != SOURCE_SHA256
        or factory["nativeMethodRva"] != f"0x{FACTORY_RVA:X}"
        or factory["originalJumpTableRva"] != f"0x{TABLE_RVA:X}"
        or len(cases) != 31
        or [c["originalNumericCaseId"] for c in cases] != list(range(31))
        or (cases[1]["nativeRuntimeClassSlotRva"], cases[14]["nativeRuntimeClassSlotRva"]) !=
           ("0x57C37B0", "0x57C1970")):
        raise ValueError("original 7.1 factory source identity drift")
    return cases


def follow_source_unconditional_jumps(start: int, aligned: dict, image_base: int, owners: dict) -> dict:
    """Trace source straight-line instructions plus *direct* unconditional jumps only."""
    pc = start
    seen = set()
    steps = []
    stop = None
    for _ in range(48):
        if pc in seen:
            stop = "DIRECT_JUMP_CYCLE"
            break
        seen.add(pc)
        x = aligned.get(pc)
        if x is None:
            stop = "OUTSIDE_ALIGNED_SOURCE_CODE"
            break
        target = None
        if x.op_str.startswith("0x") and (
            x.mnemonic == "call" or x.mnemonic.startswith("j")):
            target = int(x.op_str, 16) - image_base
        row = {"rva": f"0x{pc:X}", "mnemonic": x.mnemonic,
               "operands": x.op_str, "bytes": bytes(x.bytes).hex()}
        if target is not None:
            row["directTargetRva"] = f"0x{target:X}"
            row["exactOriginalMethodStartOwners"] = [
                {"typeName": o["type_name"], "methodName": o["method_name"],
                 "methodIndex": int(o["method_index"]),
                 "typeDefinitionIndex": int(o["type_definition_index"])}
                for o in owners.get(target, [])]
        steps.append(row)
        if x.mnemonic == "jmp":
            if target is None:
                stop = "INDIRECT_JUMP_UNRESOLVED"
                break
            pc = target
        elif x.mnemonic.startswith("j"):
            stop = "CONDITIONAL_BRANCH_BOTH_OUTCOMES_UNRESOLVED"
            break
        elif x.mnemonic.startswith("ret"):
            stop = "SOURCE_RET"
            break
        else:
            pc += x.size
    else:
        stop = "STEP_BOUND"
    return {"sourceSteps": steps, "stopped": stop,
            "nativeIndirectCallTargetsFollowed": False,
            "sourceControlOnlyNotRuntimeProof": True}


def inspect(exe: Path, methods: Path, factory: Path) -> dict:
    cases = source_cases(factory)
    if git_blob(methods) != METHODS_GIT_BLOB:
        raise ValueError("original 7.1 metadata methods.csv drift")
    starts, owners = _load_method_starts(methods)
    if [(x["type_name"], x["method_name"], int(x["method_index"]))
        for x in owners.get(FACTORY_RVA, [])] != [
            ("NLLGJBBHHAN", "JIEAILFJKNA", 408945)]:
        raise ValueError("original factory method exact owner drift")
    require_sha256(exe, PROFILE_71.exe_sha256, label="original Global 7.1 EXE")
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64
    from capstone.x86 import X86_OP_MEM, X86_REG_RIP

    with PEImage(exe) as pe:
        buf = pe.read_rva(FACTORY_RVA, FACTORY_BYTES)
        if len(buf) != FACTORY_BYTES or hashlib.sha256(buf).hexdigest() != SOURCE_SHA256:
            raise ValueError("original 31-case factory window SHA drift")
        md = Cs(CS_ARCH_X86, CS_MODE_64)
        md.detail = True
        code = list(md.disasm(buf[:TABLE_RVA - FACTORY_RVA],
                              pe.image_base + FACTORY_RVA))
        aligned = {x.address - pe.image_base: x for x in code}
        starts_by_case = sorted(int(c["nativeBranchRva"], 16) for c in cases)
        if len(set(starts_by_case)) != 31:
            raise ValueError("original case branch RVA collision")
        outcomes = []
        for case_id in TARGET_CASES:
            case = cases[case_id]
            start = int(case["nativeBranchRva"], 16)
            next_case = next((s for s in starts_by_case if s > start), TABLE_RVA)
            if not FACTORY_RVA <= start < next_case <= TABLE_RVA:
                raise ValueError("case not within original native factory code")
            first = aligned.get(start)
            if first is None:
                raise ValueError("original native case starts between instructions")
            first_rip = [o for o in first.operands
                         if o.type == X86_OP_MEM and o.mem.base == X86_REG_RIP]
            slot = int(case["nativeRuntimeClassSlotRva"], 16)
            if (first.mnemonic != "mov" or len(first_rip) != 1
                or start + first.size + first_rip[0].mem.disp != slot
                or bytes(first.bytes).hex() !=
                   case["originalFirstNativeInstruction"]["bytes"]):
                raise ValueError("original native case first class-slot read drift")
            span = [x for x in code if start <= x.address - pe.image_base < next_case]
            if not span or span[0].address - pe.image_base != start:
                raise ValueError("missing native case span")
            native = []
            transfers = []
            for x in span:
                rva = x.address - pe.image_base
                record = {
                    "rva": f"0x{rva:X}",
                    "mnemonic": x.mnemonic,
                    "operands": x.op_str,
                    "bytes": bytes(x.bytes).hex()
                }
                native.append(record)
                if x.mnemonic.startswith("j") or x.mnemonic == "call":
                    target = None
                    if x.op_str.startswith("0x"):
                        target = int(x.op_str, 16) - pe.image_base
                    transfer = {"instruction": record, "directTargetRva":
                                f"0x{target:X}" if target is not None else None}
                    if target is not None:
                        transfer["exactOriginalMethodStartOwners"] = [
                            {"typeName": v["type_name"],
                             "methodName": v["method_name"],
                             "methodIndex": int(v["method_index"]),
                             "typeDefinitionIndex": int(v["type_definition_index"])}
                            for v in owners.get(target, [])
                        ]
                    transfers.append(transfer)
            outcomes.append({
                "numericFactoryCase": case_id,
                "originalCaseBranchRva": f"0x{start:X}",
                "originalClassSlotRva": f"0x{slot:X}",
                "linearScanEndExclusiveRva": f"0x{next_case:X}",
                "sourceCaseNativeInstructions": native,
                "sourceCaseTransfers": transfers,
                "sourceDirectJumpFollow": follow_source_unconditional_jumps(
                    start, aligned, pe.image_base, owners),
                "linearInstructionsAreRuntimeExecutedProven": False,
                "sourceCaseConcreteTypeDefinitionProven": False,
                "sourceVtablePlusF8MethodOwnerProven": False,
            })
    return {
        "schemaVersion": 1,
        "status": "SOURCE_ORIGINAL_7_1_FACTORY_CASE_1_14_LOCAL_NATIVE_CODE__CLASS_AND_LOADER_UNVERIFIED",
        "originalExeSha256": PROFILE_71.exe_sha256,
        "originalMetadataSha256": PROFILE_71.metadata_sha256,
        "originalMethodsGitBlob": METHODS_GIT_BLOB,
        "sourceFactoryReport": FACTORY_REPORT,
        "sourceNativeWindowSha256": SOURCE_SHA256,
        "sourceNativeFactoryRva": f"0x{FACTORY_RVA:X}",
        "sourceNativeFactoryJumpTableRva": f"0x{TABLE_RVA:X}",
        "caseSlices": outcomes,
        "unproven": ["Factory case to concrete TypeDefinitionIndex",
                     "Factory case to vtable +0xF8 method",
                     "Original Scene/Point file path to native parser call",
                     "Original chest instance position or level",
                     "Client/server placement authority"],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for label in ("exe", "methods", "factory", "output"):
        parser.add_argument("--" + label, type=Path, required=True)
    args = parser.parse_args()
    result = inspect(args.exe, args.methods, args.factory)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n",
                           encoding="utf-8")
    print("ORIGINAL_FACTORY_CASE_NATIVE_BEGIN")
    print(json.dumps(result, indent=2, ensure_ascii=False))
    print("ORIGINAL_FACTORY_CASE_NATIVE_END")


if __name__ == "__main__":
    main()
