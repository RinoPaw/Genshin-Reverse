#!/usr/bin/env python3
"""Trace original Scene/Point resource identities into original 7.1 EXE bytes.

Exact original client / source-index verified asset path hashes only. Search
image-backed sections for literal 40-bit path hashes, zero-extended qwords,
low 32-bit fragments, ASCII/UTF-16 scene path bytes and shared directory.
Hits are raw byte candidates, NOT original instruction or loader bindings.
No match does not exclude computed/obfuscated lookup strings.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path

from genshinre.assetindex import mihoyo_name_hash
from genshinre.nativeprofile import PROFILE_71
from genshinre.pe import PEImage
from genshinre.sampleidentity import require_sha256

ORIGINAL_SCENES = "versions/7.1.0-global/analyses/progression/world/7.1-original-scene-point-source-payload-census.json"
ORIGINAL_READER = "versions/7.1.0-global/analyses/progression/world/7.1-original-scene-point-parent-mask-native-callchain.json"
ORIGINAL_DESIGN_INDEX_SHA = "fe1e1ce970e3aa72e764b0894d94a684b7a49edc9f3ae6a32c4d7f38d8a64712"
ORIGINAL_SCENE_IDS = (3, 4, 5, 6, 7, 9, 10, 11, 100, 101, 102, 103, 51195)
ORIGINAL_READER_RVA = 0xEE66B20
ORIGINAL_READER_FIRST_BYTES_SHA = "e27dc0d3a924a74963b34e8d8ff64d17ab3fe472b77dcc42b4cbe3c704a6e61a"
ORIGINAL_READER_WINDOW = 864
ORIGINAL_FACTORY_CALL_RVA = 0xAD233A5
ORIGINAL_FACTORY_CALL_HEX = "e8b6e88601"
MAX_MATCHES = 32
EXECUTABLE_SECTION_FLAG = 0x20000000


def validate_source(scenes:Path,reader:Path)->list[dict]:
    a = json.loads(scenes.read_text(encoding="utf-8"))
    b = json.loads(reader.read_text(encoding="utf-8"))
    if (a["exactOriginalExeSha256"] != PROFILE_71.exe_sha256
        or a["exactOriginalDesignIndexRawSha256"] != ORIGINAL_DESIGN_INDEX_SHA
        or a["scenesChecked"] != 13
        or a["statusCounts"] != {"SOURCE_RAW_AND_FRAMING_VERIFIED":13}
        or b["originalExeSha256"] != PROFILE_71.exe_sha256
        or b["nativeParentReader"]["nativeRva"] != f"0x{ORIGINAL_READER_RVA:X}"
        or b["nativeParentReader"]["nativeSourceSha256"] != ORIGINAL_READER_FIRST_BYTES_SHA):
        raise ValueError("original resource/native reader provenance changed")
    assets = a["assetRows"]
    if tuple(x["sceneId"] for x in assets) != ORIGINAL_SCENE_IDS:
        raise ValueError("original scene identities changed")
    for x in assets:
        name = x["candidateOriginalPath"]
        actual = mihoyo_name_hash(name)
        if (name != f"Data/_BinOutput/Scene/Point/scene{x['sceneId']}_point"
            or x["indexStatus"] != "HASH_RESOLVED"
            or x["namePathHash"] != f"0x{actual:010X}"
            or not x["originalBlockVerifiedAsWorldAreaBlock"]
            or x["nativeScenePointRowSchemaDecoded"]):
            raise ValueError("original path/hash/block identity not authenticated")
    return assets


def find_hits(raw:bytes,needle:bytes,base_rva:int,section:str,*,executable:bool)->list[dict]:
    hits=[]
    pos=0
    while (idx:=raw.find(needle,pos))!=-1:
        pos=idx+1
        hits.append({
            "rva":f"0x{base_rva+idx:X}",
            "section":section,
            "executableSection":executable,
            "needleHex":needle.hex(),
            "surroundingHex":raw[max(0,idx-8):min(len(raw),idx+len(needle)+8)].hex()
        })
        if len(hits)>MAX_MATCHES:
            raise ValueError("source-original literal occurrence count unbounded")
    return hits


def patterns(x:dict)->dict[str,bytes]:
    path = x["candidateOriginalPath"]
    h = int(x["namePathHash"],16)
    return {
        "nameHash40LittleEndian5":h.to_bytes(5,"little"),
        "nameHashZeroExtendedQword8":h.to_bytes(8,"little"),
        "nameHashLow32LittleEndian4":(h & 0xffffffff).to_bytes(4,"little"),
        "exactPathAscii":path.encode("ascii"),
        "exactPathUTF16LE":path.encode("utf-16le"),
        "exactFilenameAscii":f"scene{x['sceneId']}_point".encode("ascii"),
        "exactFilenameUTF16LE":f"scene{x['sceneId']}_point".encode("utf-16le"),
    }


def analyze(exe:Path,scenes:Path,reader:Path)->dict:
    assets=validate_source(scenes,reader)
    require_sha256(exe,PROFILE_71.exe_sha256,label="exact original Global 7.1 executable")
    needles={x["sceneId"]:patterns(x) for x in assets}
    shared={
        "sharedPointPathPrefixAscii":b"Data/_BinOutput/Scene/Point/",
        "sharedPointPathPrefixUTF16LE":"Data/_BinOutput/Scene/Point/".encode("utf-16le")
    }
    hits={x["sceneId"]:{p:[] for p in needles[x["sceneId"]]} for x in assets}
    shared_hits={p:[] for p in shared}
    sizes=[]
    with PEImage(exe) as pe:
        original=pe.read_rva(ORIGINAL_READER_RVA,ORIGINAL_READER_WINDOW)
        if (len(original)!=ORIGINAL_READER_WINDOW or
            hashlib.sha256(original).hexdigest()!=ORIGINAL_READER_FIRST_BYTES_SHA):
            raise ValueError("source original native parent reader positive control drift")
        factory=pe.read_rva(ORIGINAL_FACTORY_CALL_RVA,5)
        if factory.hex()!=ORIGINAL_FACTORY_CALL_HEX:
            raise ValueError("original factory reader call positive control drift")
        for sec in pe.sections:
            if sec.raw_size<=0:continue
            buf=pe.read_rva(sec.virtual_address,sec.raw_size)
            if len(buf)!=sec.raw_size:
                raise ValueError("original executable image-backed section truncated")
            is_exec=bool(sec.characteristics & EXECUTABLE_SECTION_FLAG)
            sizes.append({"section":sec.name,"sourceRva":f"0x{sec.virtual_address:X}",
                          "sourceBytes":len(buf),"executableSection":is_exec})
            for scene_id,groups in needles.items():
                for label,pat in groups.items():
                    hits[scene_id][label].extend(find_hits(buf,pat,sec.virtual_address,sec.name,executable=is_exec))
                    if len(hits[scene_id][label])>MAX_MATCHES:
                        raise ValueError("source original PE has too many matching literal bytes")
            for label,pat in shared.items():
                shared_hits[label].extend(find_hits(buf,pat,sec.virtual_address,sec.name,executable=is_exec))
                if len(shared_hits[label])>MAX_MATCHES:
                    raise ValueError("source original PE has too many shared path fragments")
    rows=[]
    for asset in assets:
        sid=asset["sceneId"]
        values=hits[sid]
        rows.append({
            "sceneId":sid,
            "originalPath":asset["candidateOriginalPath"],
            "exactOriginalIndexNameHash":asset["namePathHash"],
            "sourceOriginalSampleBytes":asset["payloadBytes"],
            "literalHitCountByForm":{k:len(v) for k,v in values.items()},
            "sourceOriginalLiteralMatches":values,
            "originalScenePointAssetLoaderMethodResolved":False,
        })
    return {
      "schemaVersion":1,
      "status":"EXACT_ORIGINAL_GLOBAL_7_1_SCENE_POINT_NATIVE_LOOKUP_LITERAL_CENSUS__LOADER_UNVERIFIED",
      "originalExeSha256":PROFILE_71.exe_sha256,
      "sourceDesignIndexSha256":ORIGINAL_DESIGN_INDEX_SHA,
      "sourceOriginalScenes":ORIGINAL_SCENES,
      "sourceOriginalParentNativeReader":ORIGINAL_READER,
      "sourceOriginalReaderRva":f"0x{ORIGINAL_READER_RVA:X}",
      "sourceOriginalFactoryCallRva":f"0x{ORIGINAL_FACTORY_CALL_RVA:X}",
      "originalExecutableSectionsExamined":sizes,
      "sceneRows":rows,
      "sharedPathSubstringLiteralMatches":shared_hits,
      "originalResourcePathHashToRuntimeLookupLinkProven":False,
      "originalScenePointLoaderToNativeReaderLinkProven":False,
      "originalChestGadgetPositionsOrLevelProven":False,
      "limits":[
        "Exact PE byte-substring hits cannot establish instruction alignment, runtime hash use, or a file-to-parser call.",
        "The 4-byte low fragment is especially prone to accidental byte-pattern matches.",
        "Zero matches prove only absence of the exact listed literal encodings in the scanned image-backed sections.",
        "Client code may construct or hash strings at runtime, store them compressed, encrypt strings, or access assets via another layer.",
        "The source original Scene/Point payloads have no authenticated Gadget/chest position or level schema."
      ],
    }


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for n in ("exe","scenes","reader","output"):p.add_argument("--"+n,type=Path,required=True)
    a=p.parse_args()
    d=analyze(a.exe,a.scenes,a.reader)
    a.output.parent.mkdir(parents=True,exist_ok=True)
    a.output.write_text(json.dumps(d,indent=2,ensure_ascii=False)+"\n",encoding="utf-8")
    print("ORIGINAL_71_SCENE_POINT_LOOKUP_BEGIN")
    print(json.dumps({
        "status":d["status"],"sourceSectionCount":len(d["originalExecutableSectionsExamined"]),
        "sourceImageBytes":sum(x["sourceBytes"] for x in d["originalExecutableSectionsExamined"]),
        "rows":[{"sceneId":r["sceneId"],"counts":r["literalHitCountByForm"]}
                for r in d["sceneRows"]],
        "sharedHits":{k:len(v) for k,v in d["sharedPathSubstringLiteralMatches"].items()}
    },indent=2,ensure_ascii=False))
    print("ORIGINAL_71_SCENE_POINT_LOOKUP_END")


if __name__=="__main__":
    main()
