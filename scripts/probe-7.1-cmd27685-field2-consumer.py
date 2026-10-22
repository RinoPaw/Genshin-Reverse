#!/usr/bin/env python3
"""Bounded original Global 7.1 call-target and method-ownership recovery.

Source: original typed CmdId 27685 OnAccept, RVA 0xFCDF5D0.
The exact original opcode at 0xFCDF6BE is a direct relative call with
field2 (+0x98) passed in EDX, r8d zeroed, and r9b set to one.

Only exact original EXE bytes and SHA-1-pinned original methods.csv are used.
A call parameter is not a verified native entity-id, level or reward label.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import struct
from pathlib import Path

from genshinre.nativeprofile import PROFILE_71
from genshinre.pe import PEImage
from genshinre.sampleidentity import require_sha256

CALLSITE_RVA = 0xFCDF6BE
ORIGINAL_OPCODE = bytes.fromhex("e89df28008")
TARGET_RVA = 0x184EE960
HANDLER_CALLSITE_RVA = 0xFCDF87D
HANDLER_ORIGINAL_OPCODE = bytes.fromhex("e8feed8008")
HANDLER_TARGET_RVA = 0x184EE680
HANDLER_PRE_CALL = [(0xFCDF863, "488b5e28"),
                    (0xFCDF870, "8b9798000000"),
                    (0xFCDF87A, "4889d9")]
PRE_CALL_INSTRUCTIONS = [
    (0xFCDF6B2, "8b9098000000"),
    (0xFCDF6B8, "4531c0"),
    (0xFCDF6BB, "41b101"),
]
METHODS_BLOB = "a9c106a7fdd5fe97ad204d6f4641c1e2c8d5433a"
DISASM_SIZE = 0x800
MAX_RETAINED_INSTRUCTIONS = 180


def git_blob(path: Path) -> str:
    h = hashlib.sha1()
    h.update(f"blob {path.stat().st_size}\0".encode("ascii"))
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1048576), b""):
            h.update(chunk)
    return h.hexdigest()


def decode_direct_call(call_rva: int, raw: bytes) -> int:
    if len(raw) != 5 or raw[0] != 0xE8:
        raise ValueError("expected five-byte x86-64 relative call")
    return call_rva + 5 + struct.unpack("<i", raw[1:])[0]


def original_methods(methods_path: Path, target_rva: int) -> dict:
    if git_blob(methods_path) != METHODS_BLOB:
        raise ValueError("original Global 7.1 method metadata Git blob mismatch")
    nearest = None
    exact = []
    index = -1
    with methods_path.open(encoding="utf-8-sig", newline="") as file:
        for row in csv.DictReader(file):
            if not row.get("rva"):
                continue
            m_rva = int(row["rva"], 16)
            if m_rva == target_rva:
                exact.append({
                    "methodIndex": row["method_index"],
                    "ownerTypeDefinitionIndex": row["type_definition_index"],
                    "ownerTypeName": row["type_name"],
                    "originalMethodName": row["method_name"],
                    "methodRva": row["rva"],
                    "originalParameterTypes": row.get("parameter_types",""),
                    "originalParameterCount": row.get("parameter_count",""),
                })
            if m_rva <= target_rva and m_rva > index:
                index = m_rva
                nearest = {
                    "methodIndex": row["method_index"],
                    "ownerTypeDefinitionIndex": row["type_definition_index"],
                    "ownerTypeName": row["type_name"],
                    "originalMethodName": row["method_name"],
                    "methodRva": row["rva"],
                    "distanceBytesToTarget": target_rva - m_rva,
                    "wholeMethodSpanProven": False,
                }
    if len(exact) > 20:
        raise ValueError("unexpected duplicate method RVA candidate population")
    return {"exactRvaMetadataMethods": exact, "nearestLowerRvaMetadataMethod": nearest,
            "nearestMethodActuallyContainsTargetProven": False}


def inspect(exe: Path, methods: Path) -> dict:
    require_sha256(exe, PROFILE_71.exe_sha256,
                   label="original Global 7.1 client")
    with PEImage(exe) as pe:
        for at, expected in PRE_CALL_INSTRUCTIONS:
            if pe.read_rva(at, len(bytes.fromhex(expected))).hex() != expected:
                raise ValueError(f"original OnAccept input instruction changed at 0x{at:X}")
        caller = pe.read_rva(CALLSITE_RVA, 5)
        if caller != ORIGINAL_OPCODE:
            raise ValueError("original OnAccept call opcode changed")
        target = decode_direct_call(CALLSITE_RVA, caller)
        if target != TARGET_RVA:
            raise ValueError("original OnAccept call target mismatch")
        target_data = pe.read_rva(target, DISASM_SIZE)
        if len(target_data) != DISASM_SIZE:
            raise ValueError(f"original native target 0x{target:X} is not fully file-backed")
        peer_original = pe.read_rva(HANDLER_CALLSITE_RVA, 5)
        if peer_original != HANDLER_ORIGINAL_OPCODE:
            raise ValueError("original Handle lookup call opcode changed")
        for peer_addr, hexbytes in HANDLER_PRE_CALL:
            expected = bytes.fromhex(hexbytes)
            if pe.read_rva(peer_addr, len(expected)) != expected:
                raise ValueError("original Handle input source operand changed")
        peer_target = decode_direct_call(HANDLER_CALLSITE_RVA, peer_original)
        if peer_target != HANDLER_TARGET_RVA:
            raise ValueError("original Handle lookup call target mismatch")
        peer_data = pe.read_rva(peer_target, 0x700)
        if len(peer_data) != 0x700:
            raise ValueError("original Handle lookup callee not source backed")
        image_base = pe.image_base
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    instructions = []
    branches = []
    for ins in md.disasm(target_data, image_base + TARGET_RVA):
        obj = {
            "rva": f"0x{ins.address - image_base:X}",
            "mnemonic": ins.mnemonic,
            "operands": ins.op_str,
            "hex": bytes(ins.bytes).hex(),
        }
        instructions.append(obj)
        if ins.mnemonic in ("call", "jmp") or ins.mnemonic.startswith("j"):
            if len(branches) < 100:
                branches.append(obj)
        if len(instructions) >= MAX_RETAINED_INSTRUCTIONS:
            break
        if ins.mnemonic == "ret":
            break
    if not instructions:
        raise ValueError("original target method native bytes could not disassemble")
    peer_instructions = []
    for ins in md.disasm(peer_data, image_base + peer_target):
        peer_instructions.append({
            "rva": f"0x{ins.address - image_base:X}",
            "mnemonic": ins.mnemonic,
            "operands": ins.op_str,
            "hex": bytes(ins.bytes).hex(),
        })
        if len(peer_instructions) >= MAX_RETAINED_INSTRUCTIONS or ins.mnemonic == "ret":
            break
    metadata = original_methods(methods, TARGET_RVA)
    peer_metadata = original_methods(methods, peer_target)
    return {
        "schemaVersion": 1,
        "status": "EXACT_71_CMD27685_FIELD2_NATIVE_CALLEE_RECOVERED__SEMANTICS_UNVERIFIED",
        "sample": PROFILE_71.identity,
        "originalExeSha256": PROFILE_71.exe_sha256,
        "originalMethodsGitBlob": METHODS_BLOB,
        "knownOriginalMessageType": "KIIKIELOHOG",
        "knownOriginalElementType": "KFOLLNPEMHH",
        "callsite": {
            "callerMethodName": "JLDCJCKHJEM.OnAccept",
            "callerMethodRva": "0xFCDF5D0",
            "instructionRva": f"0x{CALLSITE_RVA:X}",
            "originalBytes": caller.hex(),
            "nativeCallTargetRva": f"0x{target:X}",
            "nativeCallTargetVa": f"0x{image_base + target:X}",
            "inputFromElementOffset": "0x98",
            "fieldWireKeyPreviouslyVerified": "0x10",
            "secondArgumentRegister": "edx",
            "thirdArgumentR8d": "0",
            "fourthArgumentR9b": "1",
            "firstArgumentRcX": "qword ptr [rdi + 0x28]",
            "entityOrLevelSemanticsProven": False,
        },
        "callee": {
            "startRva": f"0x{TARGET_RVA:X}",
            "sourceBytesSha256": hashlib.sha256(target_data).hexdigest(),
            "sourceBytesExamined": len(target_data),
            "decodedInstructionCount": len(instructions),
            "firstRetSeen": instructions[-1]["mnemonic"] == "ret",
            "disassembledInstructions": instructions,
            "branchAndCallSamples": branches,
        },
        "methodMetadata": metadata,
        "peerCallsite": {
            "originalMethod": "JLDCJCKHJEM.Handle",
            "callerMethodRva": "0xFCDF7F0",
            "callRva": f"0x{HANDLER_CALLSITE_RVA:X}",
            "originalOpcode": peer_original.hex(),
            "nativeCalleeRva": f"0x{peer_target:X}",
            "firstArgFromObjectOffset": "0x28",
            "secondArgFromIndexedElementOffset": "0x98",
            "nativeIndexArgumentFromHandleMethod": True,
            "field2SemanticNameProven": False,
        },
        "peerCallee": {
            "startRva": f"0x{peer_target:X}",
            "sourceBytesSha256": hashlib.sha256(peer_data).hexdigest(),
            "decodedInstructions": peer_instructions,
            "boundedWindowBytes": len(peer_data),
            "fullMethodVerified": False,
        },
        "peerMethodMetadata": peer_metadata,
        "limits": [
            "Instruction operands prove the caller passes a scalar sourced from element +0x98; function identity and semantics require callee proof.",
            "Method metadata nearest-lower RVA is not automatically the enclosing method.",
            "Native disassembly is a bounded prefix, and a ret may belong to one control path; do not infer whole-function behavior.",
            "The original packet's semantic name/direction and any chest scene level or LootCSS category remain unproven.",
        ],
    }


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--exe", type=Path, required=True)
    p.add_argument("--methods", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    a = p.parse_args()
    report = inspect(a.exe, a.methods)
    a.output.parent.mkdir(parents=True, exist_ok=True)
    a.output.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n",
                        encoding="utf-8")
    print(json.dumps({
        "status": report["status"],
        "originalCallsite": report["callsite"],
        "methodMetadata": report["methodMetadata"],
        "calleeInstructions": report["callee"]["disassembledInstructions"][:130],
        "calleeSourceBytesSha256": report["callee"]["sourceBytesSha256"],
        "HandleCallsite": report["peerCallsite"],
        "HandleNativeCalleeInstructions": report["peerCallee"]["decodedInstructions"][:125],
        "HandleMethodMetadata": report["peerMethodMetadata"],
    }, indent=2))


if __name__ == "__main__":
    main()
