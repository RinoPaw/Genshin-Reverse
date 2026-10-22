#!/usr/bin/env python3
"""Audit original 7.1 direct Gadget ID raw-byte search against an original
known-positive native GadgetExcel decoder control.

WorldArea and original GadgetExcel input JSON are independently SHA-256-pinned
exact-client Action artifacts. Zero matches in both imply only that direct
little-endian ID byte search is INSUFFICIENT to establish native asset absence.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path

WORLD_JSON_SHA="9816985923f63a40e3679fdc897e07d2974b8e1fb011b40c2889ff6deec42c6b"
GADGET_JSON_SHA="bdfd8ca453460150740d42570abf33e0b24c97f52cde4b1bca2d90585bb3ef82"
REPORT=Path("versions/7.1.0-global/analyses/progression/economy/7.1-original-client-gadget-id-byte-search-boundary.json")
EXE_SHA="08a3086d5f3fe695f01dab61efa42e442006b18e5e475b2520df356f6a073b7d"


def verify(world_bytes:bytes,gadget_bytes:bytes)->dict:
    if hashlib.sha256(world_bytes).hexdigest()!=WORLD_JSON_SHA:
        raise ValueError("original WorldArea scan artifact changed")
    if hashlib.sha256(gadget_bytes).hexdigest()!=GADGET_JSON_SHA:
        raise ValueError("original GadgetExcel decoder control artifact changed")
    w=json.loads(world_bytes);g=json.loads(gadget_bytes)
    report=json.loads(REPORT.read_text(encoding="utf-8"))
    rows=report["originalDecodedPositiveControls"]["rows"]
    decoded={str(x["id"]):x["literal"] for x in rows}
    world={str(x["originalGadgetId"]):x["originalLiteral"] for x in w["nativeGadgetIdRows"]}
    if not (decoded==world==g["decoderRecoveredIdNames"] and len(decoded)==20):
        raise ValueError("original source native Gadget literal positive controls drift")
    if (w["originalClient"]!="7.1.0-global/windows-x64"
        or w["sourceBlockSha256"]!=report["source"]["worldAreaBlockSha256"]
        or g["sourceRawSha256"]!=report["source"]["gadgetExcelRawSha256"]
        or w["positiveWorldAreaRawSha256"]!=report["source"]["originalScene3WorldAreaRawSha256"]):
        raise ValueError("original source chain broken")
    if (g["nativeRowsDecoded"]!=30599
        or g["nativeGadgetDefinitionsValidated"]!=20
        or not g["sourceDefinitionContainsGadgetIdsProven"]
        or g["directLittleEndian32IdRawOccurrences"]!=0
        or any(g["directLittleEndian32PerId"].values())):
        raise ValueError("known-positive original GadgetExcel ID decode/byte mismatch")
    if (w["files"]["allNativeBinDataFiles"]!=167673
        or w["files"]["totalRawExportBytes"]!=415672040
        or w["directLittleEndian32Occurrences"]["native"]
        or w["directLittleEndian32Occurrences"]["diagnostic"]
        or w["sampleNativeMatchingObjects"]):
        raise ValueError("original WorldArea byte-scan scope changed")
    if (len(w["diagnosticBytePatterns"])!=8
        or len(report["originalDecodedPositiveControls"]["rows"])!=20):
        raise ValueError("bounded original scan controls changed")
    if (not report["evidenceConclusion"]["bytePatternAbsenceCannotExcludeOriginalAssetPresence"]
        or report["evidenceConclusion"]["originalSceneInstanceLevelProven"]):
        raise ValueError("unverified gameplay semantics were promoted")
    return report


def main()->None:
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--worldarea-artifact",required=True,type=Path)
    p.add_argument("--native-gadget-artifact",required=True,type=Path)
    args=p.parse_args()
    result=verify(args.worldarea_artifact.read_bytes(),args.native_gadget_artifact.read_bytes())
    print(json.dumps({"status":result["status"],
                      "originalDecoded":result["originalDecodedPositiveControls"]["totalGadgetExcelRowsDecoded"],
                      "positiveGadgets":result["originalDecodedPositiveControls"]["authenticatedNativeChestGadgetRows"],
                      "worldNativeRawMatchCount":result["worldAreaByteScan"]["nativeIdDirectLe32Matches"],
                      "gadgetKnownPositiveRawMatchCount":result["originalGadgetExcelPositiveDecodeByteScan"]["nativeIdDirectLe32Matches"]},indent=2))


if __name__=="__main__":
    main()
