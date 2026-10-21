#!/usr/bin/env python3
"""Exact Global 7.1 GadgetProp/GadgetInteract original row-reader candidate screen.

Original EXE/metadata and native key stores are required. Native code references
to a TypeInfo slot do not identify the concrete runtime class or vtable method.
"""
from __future__ import annotations

import argparse
from importlib import util
import json
from pathlib import Path

from genshinre.nativeprofile import PROFILE_71
from genshinre.xrefs import scan_rip_xrefs

ROOT = Path(__file__).resolve().parents[1]
spec = util.spec_from_file_location("original_scene_key_writer", ROOT / "scripts/probe-7.1-scene-reader-keywriters.py")
writer = util.module_from_spec(spec)
spec.loader.exec_module(writer)

SOURCES = {
    "GadgetPropExcelConfigData": {
        "managerIndex": 28984, "keyOffset": 0x1C,
        "typeInfoSlotRva": 0x57DAF50, "nativeClassLoadRva": 0x124F2D94,
    },
    "GadgetInteractExcelConfigData": {
        "managerIndex": 28382, "keyOffset": 0x28,
        "typeInfoSlotRva": 0x57FA548, "nativeClassLoadRva": 0x11073044,
    },
}


def summarize(writers: dict, refs: dict) -> dict:
    if writers["exeSha256"] != PROFILE_71.exe_sha256 or writers["methodsGitBlob"] != writer.METHODS_BLOB:
        raise ValueError("original 7.1 source identity mismatch")
    if writers["wrappedUint32WriterRva"] != f"0x{writer.WRITER:X}":
        raise ValueError("unexpected original wrapped-u32 writer")
    out = {}
    for name, source in SOURCES.items():
        rows = writers["keyOffsetCandidates"][name]
        if int(rows["memoryOffset"], 16) != source["keyOffset"] or len(rows["methods"]) != rows["methodCount"]:
            raise ValueError(f"{name}: original key candidate population mismatch")
        seen = set()
        for item in rows["methods"]:
            if item["methodIndex"] in seen:
                raise ValueError("duplicate candidate method index")
            seen.add(item["methodIndex"])
        candidates = sorted(rows["methods"], key=lambda item: (
            abs(item["typeDefinitionIndex"] - source["managerIndex"]),
            item["methodIndex"]))
        references = refs["matches"].get(f"0x{source['typeInfoSlotRva']:X}", [])
        if not any(int(ref["instruction_rva"], 16) == source["nativeClassLoadRva"]
                   for ref in references):
            raise ValueError(f"{name}: original class static positive control missing")
        out[name] = {
            "originalManagerTypeIndex": source["managerIndex"],
            "nativeKeyMemoryOffset": f"0x{source['keyOffset']:X}",
            "originalRowTypeInfoStaticSlotRva": f"0x{source['typeInfoSlotRva']:X}",
            "nativeTypeInfoStaticRefCount": len(references),
            "nativeTypeInfoReferences": [
                {"instructionRva": q["instruction_rva"],
                 "instructionHex": q["instruction_hex"],
                 "ownerMethods": [{
                     "index": o.get("method_index"),
                     "typeIndex": o.get("type_definition_index")}
                     for o in q.get("caller_methods", [])[:3]]}
                for q in references[:20]],
            "matchingNativeWrapperAndKeyStoreMethods": len(candidates),
            "typeIndexWithin50": sum(
                abs(c["typeDefinitionIndex"] - source["managerIndex"]) <= 50
                for c in candidates),
            "singleWrapperCallOnlyKeyStore": sum(
                len(c["nativeCallSites"]) == 1 and
                c["keyWriteOffsetsAfterWrapper"] == [source["keyOffset"]]
                for c in candidates),
            "nearest25Candidates": [{
                "methodIndex": c["methodIndex"],
                "typeDefinitionIndex": c["typeDefinitionIndex"],
                "typeName": c["typeName"], "methodRva": c["methodRva"],
                "relativeManagerIndex": c["typeDefinitionIndex"] - source["managerIndex"],
                "nativeWrapperCalls": len(c["nativeCallSites"]),
                "nativeStores": c["keyWriteOffsetsAfterWrapper"],
            } for c in candidates[:25]],
            "concreteVirtualRowReaderVerified": False,
        }
    return {
        "schemaVersion": 1,
        "status": "ORIGINAL_71_AUX_GADGET_KEYWRITERS_AND_STATIC_CLASS_XREFS__VIRTUAL_TARGET_UNRESOLVED",
        "originalExeSha256": PROFILE_71.exe_sha256,
        "methodsGitBlob": writer.METHODS_BLOB,
        "nativeWrapperRva": f"0x{writer.WRITER:X}",
        "nativeDirectWrapperCalls": writers["directNativeWriterCalls"],
        "nativeMatchingSignatureCalls": writers["sameReaderNameAndArgumentCalls"],
        "tables": out,
        "limitations": [
            "Post-call stores are alignment-checked native candidates, not authenticated row-class identities.",
            "Native TypeInfo slot xrefs do not establish runtime initialization or a concrete vtable at +0xF0.",
            "Metadata type-index proximity only orders candidates; it cannot identify the reader.",
            "Indirect/inlined and inherited row-key writers are not ruled out.",
            "No LootCSS grade, level, type, original scene placement or server payout is inferred.",
        ],
    }


def run(exe: Path, methods: Path) -> dict:
    offsets = {name: row["keyOffset"] for name,row in SOURCES.items()}
    writers = writer.run(exe, methods, key_offsets=offsets)
    targets = [row["typeInfoSlotRva"] for row in SOURCES.values()]
    refs = scan_rip_xrefs(exe, targets, methods_csv=methods, window=12)
    return summarize(writers, refs)


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--exe", required=True, type=Path)
    p.add_argument("--methods", required=True, type=Path)
    p.add_argument("--output", required=True, type=Path)
    a = p.parse_args()
    report = run(a.exe, a.methods)
    a.output.parent.mkdir(parents=True, exist_ok=True)
    a.output.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps({"status":report["status"],
        "tables":{name:{"candidates":t["matchingNativeWrapperAndKeyStoreMethods"],
                         "close":t["typeIndexWithin50"],
                         "singleStore":t["singleWrapperCallOnlyKeyStore"],
                         "typeInfoReferences":t["nativeTypeInfoStaticRefCount"],
                         "nearest":t["nearest25Candidates"][:8]}
                  for name,t in report["tables"].items()}},indent=2))


if __name__ == "__main__":
    main()
