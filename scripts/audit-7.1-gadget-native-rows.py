#!/usr/bin/env python3
"""Audit the exact original Global 7.1 Gadget table without publishing asset bytes.

Input must be the exact pinned AnimeStudio Raw export d65ab32f.dat. All bytes are consumed by the recovered native base and inner readers.
Semantic field labels and server loot ownership remain separate investigations.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path

from genshinre.assetindex import unwrap_mihoyo_bin_data
from genshinre.gadgetbin import scan_gadget_payload

ROOT = Path(__file__).resolve().parents[1]
REPORT = (ROOT / "versions/7.1.0-global/analyses/progression/economy"
          / "7.1-chest-native-gadget-inner-row-audit.json")
RAW_SHA256 = "a35e3f3ed04f950cb6302099d12aa71e23ece21d8fe578950347d9318f769e35"
PAYLOAD_SHA256 = "b8f35d6f3fe1aec90398ccbbe205335fe0d9ae45245b206096be5e434746c354"
RAW_SIZE = 2854888
PAYLOAD_SIZE = 2854884
ROW_COUNT = 30599


def audit(raw: bytes) -> dict:
    if len(raw) != RAW_SIZE or hashlib.sha256(raw).hexdigest() != RAW_SHA256:
        raise ValueError("exact 7.1 Gadget raw export size or SHA-256 mismatch")
    payload = unwrap_mihoyo_bin_data(raw)
    if (len(payload) != PAYLOAD_SIZE
            or hashlib.sha256(payload).hexdigest() != PAYLOAD_SHA256):
        raise ValueError("exact 7.1 Gadget payload SHA-256/size mismatch")

    scan = scan_gadget_payload(payload, expected_rows=ROW_COUNT)
    summary = scan.summary()
    if (summary["rowCountObserved"] != ROW_COUNT
            or summary["uniqueIds"] != ROW_COUNT):
        raise ValueError("native Gadget row count/IDs do not match pinned sample")
    field_presence = summary["fieldPresentCounts"]
    if len(field_presence) != 22:
        raise ValueError("Gadget row field coverage changed")

    prefix_length = Counter((row.base_end - row.base_start) - 4 for row in scan.rows)
    inner_bytes = sum(row.inner_end - row.inner_start for row in scan.rows)
    id_bytes = ROW_COUNT * 4
    opaque_prefix_bytes = sum(prefix_length[length] * length for length in prefix_length)
    if 4 + id_bytes + opaque_prefix_bytes + inner_bytes != PAYLOAD_SIZE:
        raise ValueError("Gadget observed byte partition does not cover the sample")
    if summary["baseDecodedBytes"] != id_bytes + opaque_prefix_bytes:
        raise ValueError("Gadget scanner misreported opaque outer prefix bytes")

    enum26 = [row for row in scan.rows if row.fields.get(0x6C) == 26]
    if len(enum26) != 309 or any(0x58 not in row.fields for row in enum26):
        raise ValueError("candidate Chest subset does not match exact 7.1 asset")
    expected_ids = list(range(70210001, 70210007))
    controls = enum26[:6]
    if ([row.gadget_id for row in controls] != expected_ids
            or any(row.fields.get(0x58) != "SceneObj_Chest_NormalChest"
                   for row in controls)):
        raise ValueError("native Gadget candidate ID/name controls failed")

    boolean_tokens = {
        0x78: "NGDGAAEHPHB", 0x79: "MEAFFJCCKNE",
        0x7A: "AHACIELEHAG", 0x7B: "IDMKFDPKFEG",
        0x7C: "MECPCDBEFBG", 0x7D: "IJLLLELBGGI",
        0x7E: "CKIJBKMANHD", 0x7F: "OLOLLKJCHHI",
    }
    boolean_coverage = {}
    for offset, token in boolean_tokens.items():
        observed = [row.fields[offset] for row in enum26 if offset in row.fields]
        if any(type(value) is not bool for value in observed):
            raise ValueError(f"non-boolean Gadget wire field at 0x{offset:X}")
        boolean_coverage[f"0x{offset:X}"] = {
            "nativeToken": token,
            "presentTrue": sum(value is True for value in observed),
            "presentFalse": sum(value is False for value in observed),
            "absentOnWire": len(enum26) - len(observed),
        }

    return {
        "schemaVersion": 2,
        "status": "EXACT_7_1_GADGET_COMPLETE_NATIVE_TABLE_WIRE__SEMANTIC_REWARDS_UNRESOLVED",
        "source": {
            "sample": "7.1.0-global/windows-x64",
            "officialManifestBlock": "00/25539185.blk",
            "exportedAsset": "d65ab32f.dat",
            "nativeTablePathSuffix": "GadgetExcelConfigData",
            "rawExportBytes": RAW_SIZE,
            "rawExportSha256": RAW_SHA256,
            "payloadBytes": PAYLOAD_SIZE,
            "payloadSha256": PAYLOAD_SHA256,
            "nativeReaderOwner": "DCCHEHMHFGC",
            "nativeReaderMethod": "GMENPOPMKAA",
            "nativeReaderRva": "0x10278E50",
            "methodIndex": 483590,
            "baseReaderTypeDefinitionIndex": 49659,
            "baseReaderMethodIndex": 395933,
            "baseReaderRva": "0xBD56F60",
            "tableLoaderMethodIndex": 197827,
            "tableLoaderRva": "0x968F690",
        },
        "observedFraming": {
            "headerHex": scan.header_hex,
            "headerDecoded": True,
            "headerDecodedCount": scan.header_count,
            "headerCountNativeAdd": "0x23F5AB5E",
            "rowCount": ROW_COUNT,
            "uniqueNativeIds": summary["uniqueIds"],
            "firstNativeId": scan.rows[0].gadget_id,
            "lastNativeId": scan.rows[-1].gadget_id,
            "nativeIdMemoryOffset": "0x30",
            "nativeIdDecodeAdd": "0x4894CEA6",
            "baseMaskDecodeAdd": "0x5486",
            "nativeBaseDecodedBytes": scan.base_decoded_bytes,
            "nativeBaseOtherFieldBytes": opaque_prefix_bytes,
            "nativeIdFieldBytes": id_bytes,
            "innerDecodedBytes": inner_bytes,
            "headerBytes": 4,
            "unparsedBytes": 0,
            "baseOtherFieldLengthHistogram": {
                str(length): prefix_length[length] for length in sorted(prefix_length)
            },
            "lastDecodedRecordEndsAtEof": scan.rows[-1].inner_end == len(payload),
            "coveredBytes": PAYLOAD_SIZE,
        },
        "fieldPresenceCountByCandidateMemoryOffset": field_presence,
        "enum26CrossCheck": {
            "nativeTypeCandidateMemoryOffset": "0x6C",
            "nativeValueCandidate": 26,
            "rowCount": len(enum26),
            "nameCandidateMemoryOffset": "0x58",
            "distinctNameStrings": summary["enum26DistinctNames"],
            "allHaveNameField": True,
            "normalChestControls": [
                {
                    "gadgetId": row.gadget_id,
                    "nameString": row.fields[0x58],
                    "iconString": row.fields.get(0x50),
                }
                for row in controls
            ],
            "hasNonOrdinaryChestAndSpecialGadgetNames": True,
            "candidateBooleanWireCoverage": boolean_coverage,
        },
        "limits": [
            "SHA-256 validates the exact 7.1 Gadget Raw export; source block and extraction chain are pinned separately.",
            "All 30,599 table rows, the native header count, inherited fields and inner fields consume all payload bytes.",
            "Native enum-26 includes special/puzzle objects; no ordinary four-grade reward classification follows.",
            "Opaque in-memory wrapper fields lack authenticated gameplay semantic labels.",
            "A match with historical chest categories is a cross-check, never evidence for server rewards.",
            "No placed instance, native drop_tag, server payout root, item quantity or probability is established.",
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--raw-export", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=REPORT)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    report = audit(args.raw_export.read_bytes())
    if args.check:
        if json.loads(args.output.read_text(encoding="utf-8")) != report:
            raise SystemExit("exact 7.1 Gadget row audit diverged from committed report")
        print("PASS: 30599 original Gadget inner records and 309 enum-26 records")
    else:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n",
                               encoding="utf-8")
        print(json.dumps({
            "status": report["status"],
            "rows": report["observedFraming"]["rowCount"],
            "innerDecodedBytes": report["observedFraming"]["innerDecodedBytes"],
            "enum26Rows": report["enum26CrossCheck"]["rowCount"],
        }, indent=2))


if __name__ == "__main__":
    main()
