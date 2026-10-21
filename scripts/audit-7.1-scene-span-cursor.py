#!/usr/bin/env python3
"""Prove original 7.1 SceneTag candidate 696558 consumes its long byte span.

The instruction evidence is SHA-256 gated to the exact Global 7.1 client.
This is a negative direct-row-reader test, not runtime vtable identification.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path

from genshinre.assetindex import unwrap_mihoyo_bin_data
from genshinre.nativeprofile import PROFILE_71
from genshinre.scenebin71 import SOURCES, decode_source_header

ROOT = Path(__file__).resolve().parents[1]
REPORT = (ROOT / "versions/7.1.0-global/analyses/progression/economy"
          / "7.1-chest-scene-native-span-cursor-evidence.json")
BUDGET = ROOT / "scripts/audit-7.1-scene-string-reader-budget.py"
CALLER_SHA = "7ecd093986c70a8f6ea08362f1f670166a841f0066ab0b5eec7b3f4a6be903fc"
HELPER_SHA = "b36b6da826248d18f466776595bdd8e5e5cee475abef427691d4467167c6da30"
BASE_VA = 0x140000000
CALLER_RVA = 0x99C3380
HELPER_RVA = 0xFD53090
CALLER_ANCHORS = (
    ("0x99C3524", "movzx", "edi, si"),
    ("0x99C37D4", "mov", "rcx, r13"),
    ("0x99C37D7", "mov", "edx, edi"),
    ("0x99C37DD", "call", "0x14fd53090"),
)
HELPER_ANCHORS = (
    ("0xFD5309D", "mov", "ebp, edx"),
    ("0xFD5309F", "mov", "rdi, rcx"),
    ("0xFD53174", "test", "rdi, rdi"),
    ("0xFD53177", "je", "0x14fd53187"),
    ("0xFD53179", "add", "dword ptr [rdi + 0x28], ebp"),
    ("0xFD53186", "ret", ""),
)


def check_native(raw: bytes, digest: str, rva: int,
                 anchors: tuple[tuple[str, str, str], ...]) -> dict:
    if hashlib.sha256(raw).hexdigest() != digest:
        raise ValueError("original native disassembly SHA-256 mismatch")
    native = json.loads(raw)
    if (native.get("exe_sha256") != PROFILE_71.exe_sha256
            or int(native["image_base"], 16) != BASE_VA
            or int(native["start_rva"], 16) != rva):
        raise ValueError("original native EXE/VA/RVA identity mismatch")
    rows = native["instructions"]
    by_rva = {r["rva"]: r for r in rows}
    if len(by_rva) != len(rows):
        raise ValueError("duplicate original native instruction address")
    for at, mnemonic, operand in anchors:
        ins = by_rva.get(at)
        if ins is None or (ins["mnemonic"], ins["op_str"]) != (mnemonic, operand):
            raise ValueError(f"native instruction mismatch at {at}")
    return native


def verify(caller_raw: bytes, helper_raw: bytes) -> dict:
    caller = check_native(caller_raw, CALLER_SHA, CALLER_RVA, CALLER_ANCHORS)
    helper = check_native(helper_raw, HELPER_SHA, HELPER_RVA, HELPER_ANCHORS)
    site = next(i for i in caller["instructions"] if i["rva"] == "0x99C37DD")
    if int(site["op_str"], 16) - BASE_VA != HELPER_RVA:
        raise ValueError("native helper call VA did not resolve to required RVA")
    body = [i for i in helper["instructions"] if HELPER_RVA <= int(i["rva"], 16) <= 0xFD53186]
    if [i["rva"] for i in body if i["mnemonic"] == "ret"] != ["0xFD53186"]:
        raise ValueError("unexpected early return in cursor helper")
    return {
        "callerMethodIndex": 696558,
        "callerRva": "0x99C3380",
        "callSiteRva": "0x99C37DD",
        "calledAbsoluteVa": site["op_str"],
        "helperRva": "0xFD53090",
        "argumentPropagation": "rcx=r13 (stream); edx=edi (decoded length); helper rdi=rcx, ebp=edx",
        "normalReturnCursorAddRva": "0xFD53179",
        "normalReturnCursorAdd": "dword ptr [rdi + 0x28] += ebp",
        "normalReturnCursorAdvanceMatchesSpanLength": True,
    }


def audit(raw: bytes, caller_raw: bytes, helper_raw: bytes) -> dict:
    header = decode_source_header(raw, source="SceneTagConfigData")
    evidence = verify(caller_raw, helper_raw)
    spec = importlib.util.spec_from_file_location("scene_budget_71", BUDGET)
    budget = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(budget)
    result = budget.relaxed_max_rows(unwrap_mihoyo_bin_data(raw))
    rows = result["maxRowsStartingAtOffset"]
    length = result["firstRowMinimumBudget"]["spanLength"]
    if (rows != 300 or length != 35703 or header.row_count != 1147):
        raise ValueError("exact original SceneTag row-budget proof changed")
    return {
        "schemaVersion": 1,
        "status": "EXACT_71_SCENETAG_696558_NATIVE_CURSOR_ADVANCE_PROVEN__ROW_VTABLE_UNRESOLVED",
        "source": {
            "sample": PROFILE_71.identity,
            "exeSha256": PROFILE_71.exe_sha256,
            "sceneTagRawSha256": SOURCES["SceneTagConfigData"]["raw_sha"],
            "sceneTagPayloadSha256": SOURCES["SceneTagConfigData"]["payload_sha"],
            "callerDisassemblySha256": CALLER_SHA,
            "cursorDisassemblySha256": HELPER_SHA,
            "sourceRun": "https://github.com/RinoPaw/Genshin-Reverse/actions/runs/39565602303",
        },
        "native": evidence,
        "originalSceneTagRows": header.row_count,
        "firstRowDecodedByteSpanLength": length,
        "forwardOnlyMaxPossibleRows": rows,
        "limitations": [
            "The native helper advances the same stream cursor by the decoded byte length on successful normal return.",
            "The 300-row upper bound also requires all additional readers to proceed forward through the logical original stream; indirect refill/buffer behavior is not fully proved.",
            "Candidate 696558 is inconsistent with direct whole-row parsing under those conditions, but may be a helper of another class.",
            "The actual vtable +0xF0 row reader, scene/group/config, server drop_tag, reward roots and probabilities are still unverified.",
        ],
    }


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--scene-tag-raw", type=Path, required=True)
    p.add_argument("--caller-disasm", type=Path, required=True)
    p.add_argument("--cursor-disasm", type=Path, required=True)
    p.add_argument("--output", type=Path, default=REPORT)
    p.add_argument("--check", action="store_true")
    a = p.parse_args()
    report = audit(a.scene_tag_raw.read_bytes(), a.caller_disasm.read_bytes(),
                   a.cursor_disasm.read_bytes())
    if a.check:
        if json.loads(a.output.read_text(encoding="utf-8")) != report:
            raise SystemExit("source-pinned SceneTag span cursor evidence changed")
    else:
        a.output.parent.mkdir(parents=True, exist_ok=True)
        a.output.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n",
                            encoding="utf-8")
    print(json.dumps({"status": report["status"],
                      "cursorAdvance": report["native"]["normalReturnCursorAddRva"],
                      "maxRows": report["forwardOnlyMaxPossibleRows"]}))


if __name__ == "__main__":
    main()
