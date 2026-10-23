#!/usr/bin/env python3
"""Follow original Global 7.1 native 0x55A1F0 fallback using direct CFG edges.

Only exact original EXE bytes, native preceding callee 0x55A0B0 and its
committed original-source machine witnesses are accepted. This does not name
allocator semantics, concrete factory classes, Scene/Point instance fields,
or chest levels.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path

from genshinre.nativeprofile import PROFILE_71
from genshinre.pe import PEImage
from genshinre.sampleidentity import require_sha256

ROOT = Path(__file__).resolve().parents[1]
PRIOR = "versions/7.1.0-global/analyses/progression/world/7.1-original-point-factory-55a0b0-native-freelist.json"
CFG_SCRIPT = ROOT / "scripts/probe-7.1-kind1-post-init-cfg.py"
ENTRY_RVA = 0x55A1F0
WINDOW = 0x400
SOURCE_PRIOR_SHA = "5d9bca48ad84ed11588c7c14d80e81b92ea0c9424811ebc480caff4d0dd79f1b"
SOURCE_PRIOR_WINDOW = 0x800
SOURCE_PRIOR_START = 0x55A0B0
SOURCE_TAIL_JUMP = 0x55A1D5
OLD_METHOD_TERMINAL_RET = 0x55A19E

spec = importlib.util.spec_from_file_location("original_71_native_cfg", CFG_SCRIPT)
cfg = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cfg)


def verify_prior(path: Path) -> dict:
    d = json.loads(path.read_text(encoding="utf-8"))
    if (d["sourceOriginalExecutableSha256"] != PROFILE_71.exe_sha256
        or d["sourceOriginalMetadataSha256"] != PROFILE_71.metadata_sha256
        or d["sourceOriginalSampleSha256"] != SOURCE_PRIOR_SHA
        or d["originalHelperRva"] != f"0x{SOURCE_PRIOR_START:X}"
        or d["originalSampleWindowBytes"] != SOURCE_PRIOR_WINDOW
        or d["originalNativeReturnRva"] != f"0x{OLD_METHOD_TERMINAL_RET:X}"
        or d["originalFallbackNativeEntryRva"] != f"0x{ENTRY_RVA:X}"
        or not d["sourceVerifiedListHeadPopAndReturnedPointerFlow"]):
        raise ValueError("exact original preceding native helper source drift")
    outgoing = [x for x in d["sourceOriginalListPointerChain"]
                if x["rva"] == f"0x{SOURCE_TAIL_JUMP:X}"]
    if len(outgoing) != 1 or (outgoing[0]["mnemonic"], outgoing[0]["operands"],
                              outgoing[0]["bytes"]) != (
        "jmp", f"0x{0x140000000+ENTRY_RVA:x}", "e916000000"):
        raise ValueError("source 0x55A0B0 fallback tail-jump identity drift")
    return d


def inspect(exe: Path, prior: Path) -> dict:
    verify_prior(prior)
    require_sha256(exe, PROFILE_71.exe_sha256, label="original Global 7.1 EXE")
    with PEImage(exe) as pe:
        source = pe.read_rva(ENTRY_RVA, WINDOW)
        if len(source) != WINDOW:
            raise ValueError("original source fallback method window is not backed")
        if source[:4] != bytes.fromhex("41574156"):
            raise ValueError("original fallback entry register-save bytes drift")
        evidence = cfg.inspect_control_flow(source, pe.image_base, start_rva=ENTRY_RVA)
    # Every CFG instruction must originate in the pinned original executable.
    # We do not follow the bodies of native direct calls or unresolved indirect calls.
    decoded = evidence.pop("originalReachedNativeInstructions")
    source_returns = evidence["originalDecodedReturnSites"]
    if not source_returns:
        raise ValueError("bounded original fallback source has no terminal return")
    return {
        "schemaVersion": 1,
        "status": "EXACT_ORIGINAL_GLOBAL_7_1_FACTORY_55A1F0_FALLBACK_REACHABLE_SOURCE_CFG__CLASS_AND_SCENE_UNPROVEN",
        "originalExeSha256": PROFILE_71.exe_sha256,
        "originalMetadataSha256": PROFILE_71.metadata_sha256,
        "sourcePrior": PRIOR,
        "sourceOriginalNativeCallerJumpRva": f"0x{SOURCE_TAIL_JUMP:X}",
        "originalNativeFallbackRva": f"0x{ENTRY_RVA:X}",
        "sourceOriginalFallbackPrefixHex": source[:16].hex(),
        "sourceOriginalWindowSha256": hashlib.sha256(source).hexdigest(),
        "sourceNativeReachableCFG": evidence,
        "sourceNativeLastInstructions": decoded[-48:],
        "originalNativeAllocationSemanticProven": False,
        "originalRuntimeFactorySlotConcreteTypeProven": False,
        "originalFactoryVirtualReaderPlusF8Resolved": False,
        "originalScenePointFileLoaderOrChestCoordinatesLevelProven": False,
        "limitations": [
            "Reachable source-native CFG explores both conditional branches; not a runtime execution trace.",
            "Direct call target bodies and indirect call target identities are not visited.",
            "A direct tail-jump into this function proves the callee edge, not object-allocation semantics.",
            "Full unbounded function boundary or protected internal flows outside the window remain unknown.",
            "No Scene/Point loader, Gadget/chest instance coordinates, level or official server authority is implied."
        ]
    }


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    for arg in ("exe", "prior", "output"):
        p.add_argument("--"+arg, required=True, type=Path)
    args = p.parse_args()
    report = inspect(args.exe, args.prior)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, ensure_ascii=False)+"\n", encoding="utf-8")
    print("ORIGINAL_71_FALLBACK_55A1F0_BEGIN")
    print(json.dumps(report, indent=2, ensure_ascii=False))
    print("ORIGINAL_71_FALLBACK_55A1F0_END")


if __name__ == "__main__":
    main()
