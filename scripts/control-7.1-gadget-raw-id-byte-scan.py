#!/usr/bin/env python3
"""Positive source control for the WorldArea raw Gadget ID byte-occurrence test.

The original Global 7.1 GadgetExcel raw table is KNOWN to contain all 20
Gadget definitions. Decode every original record with the native verified
binary decoder and independently scan source raw bytes for the literal u32
little-endian Gadget IDs. This calibrates whether no direct ID hits in the
world-area block can plausibly imply absence of those native definitions.
"""
from __future__ import annotations
import argparse
from collections import Counter
import hashlib
import importlib.util
import json
from pathlib import Path

from genshinre.nativeprofile import PROFILE_71
from genshinre.gadgetbin import scan_gadget_raw_export

ROOT=Path(__file__).resolve().parents[1]
CONTACT_SCRIPT=ROOT/"scripts/probe-7.1-worldarea-native-gadget-id-contacts.py"
spec=importlib.util.spec_from_file_location("original_contact_scan",CONTACT_SCRIPT)
mod=importlib.util.module_from_spec(spec)
assert spec.loader
spec.loader.exec_module(mod)

RAW_SHA256="a35e3f3ed04f950cb6302099d12aa71e23ece21d8fe578950347d9318f769e35"
GADGET_EXPORT="d65ab32f.dat"
EXPECTED_ROWS=30599


def control(raw:bytes)->dict:
    if hashlib.sha256(raw).hexdigest()!=RAW_SHA256:
        raise ValueError("original GadgetExcel source Raw SHA mismatch")
    native=mod.native_gadget_ids()
    if len(native)!=20:
        raise ValueError("original native gadget ID source list incomplete")
    decoded=scan_gadget_raw_export(raw,expected_rows=EXPECTED_ROWS)
    found={row.gadget_id:row.fields.get(0x58) for row in decoded.rows if row.gadget_id in native}
    if len(decoded.rows)!=EXPECTED_ROWS or found!=native:
        raise ValueError("positive original native gadget decoder failed exact row controls")
    scan=mod.scan_bytes(raw[4:],native)
    raw_count=sum(scan["counts"]["native"].values())
    return {
      "schemaVersion":1,
      "status":"ORIGINAL_7_1_GADGET_EXCEL_SOURCE_BYTE_SCAN_POSITIVE_DECODER_CONTROL",
      "officialClient":PROFILE_71.identity,
      "sourceRawGadgetTable":GADGET_EXPORT,
      "sourceRawSha256":RAW_SHA256,
      "sourceRawBytes":len(raw),
      "nativeRowsDecoded":len(decoded.rows),
      "nativeGadgetDefinitionsValidated":len(native),
      "directLittleEndian32IdRawOccurrences":raw_count,
      "directLittleEndian32PerId":{str(k):scan["counts"]["native"][k] for k in sorted(native)},
      "diagnosticSyntheticRawMatches":sum(scan["counts"]["diagnostic"].values()),
      "firstDirectMatchOffsets":scan["samples"]["native"],
      "decoderRecoveredIdNames":{str(k):v for k,v in sorted(found.items())},
      "sourceDefinitionContainsGadgetIdsProven":True,
      "worldAreaDirectByteScanShowsNoMatches":True,
      "originalSceneInstanceLevelProven":False,
      "limits":[
        "Native-validated gadget IDs exist semantically in this original serialized table even if their little-endian byte sequences cannot be found verbatim.",
        "A positive decoded binary row does not require a literal four-byte little-endian representation; the native field wrapper/encoding can change bytes.",
        "Only the original GadgetExcel raw table is scanned here. WorldArea original block result is a separate source-validated artifact.",
        "Neither a positive nor a negative raw-byte match authenticates a chest placement, scene instance level or server reward."
      ]
    }


def main()->None:
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--gadget-raw",required=True,type=Path)
    ap.add_argument("--output",required=True,type=Path)
    args=ap.parse_args()
    result=control(args.gadget_raw.read_bytes())
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(json.dumps(result,indent=2,ensure_ascii=False)+"\n",encoding="utf-8")
    print(json.dumps(result,indent=2,ensure_ascii=False))


if __name__=="__main__":
    main()
