#!/usr/bin/env python3
"""Observe repeated raw-byte motifs in authenticated Global 7.1 scene tables.

This deliberately does not call any byte motif a field name, presence flag,
or row boundary. Native loader headers supply independent row counts; exact
motif occurrence counts are a reproducible structural observation only.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import statistics

from genshinre.assetindex import unwrap_mihoyo_bin_data
from genshinre.scenebin71 import decode_source_header

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = (ROOT / "versions/7.1.0-global/analyses/progression/economy"
          / "7.1-chest-scene-native-byte-motif-audit.json")
MOTIFS = {
    "SceneTagConfigData": (b"\x69\x0d\x4f", "b410089f.dat"),
    "SceneExcelConfigData": (b"\x00\x00\x00\x00", "fd805cfc.dat"),
}


def find_offsets(data: bytes, motif: bytes) -> list[int]:
    if not motif:
        raise ValueError("empty native byte motif is invalid")
    offsets = []
    at = 0
    while (pos := data.find(motif, at)) != -1:
        offsets.append(pos)
        at = pos + 1  # count overlapping matches too
    return offsets


def inspect(raw_by_name: dict[str, bytes]) -> dict:
    rows = {}
    for label, (motif, _filename) in MOTIFS.items():
        if label not in raw_by_name:
            raise ValueError(f"missing exact source export for {label}")
        raw = raw_by_name[label]
        header = decode_source_header(raw, source=label)  # exact hashes required
        payload = unwrap_mihoyo_bin_data(raw)
        offsets = find_offsets(payload, motif)
        distances = [b-a for a,b in zip(offsets, offsets[1:])]
        # No row-boundary claim: equality is observational only.
        if len(offsets) != header.row_count:
            raise ValueError(f"{label} expected native row count does not match motif hits")
        rows[label] = {
            "originalRawExportSha256": header.raw_export_sha256,
            "originalPayloadSha256": header.payload_sha256,
            "nativeLoaderRowCount": header.row_count,
            "motifBytesHex": motif.hex(),
            "motifOccurrences": len(offsets),
            "allOffsetsSha256": hashlib.sha256(
                b"".join(offset.to_bytes(4, "little") for offset in offsets)
            ).hexdigest(),
            "firstOffsets": offsets[:12],
            "lastOffsets": offsets[-12:],
            "neighborDistanceMin": min(distances) if distances else None,
            "neighborDistanceMedian": statistics.median(distances) if distances else None,
            "neighborDistanceMax": max(distances) if distances else None,
            "mostCommonNeighborDistances": [
                {"bytes": size, "pairs": n}
                for size,n in sorted(Counter(distances).items(),
                                     key=lambda kv: (-kv[1], kv[0]))[:10]
            ],
            "nativeFieldOwnerIdentified": False,
            "motifProvenRowDelimiter": False,
        }
    return {
        "schemaVersion": 1,
        "status": "EXACT_7_1_SCENE_BIN_NATIVE_COUNTS_MATCH_RAW_MOTIFS__ROW_DELIMITERS_UNVERIFIED",
        "source": "original 7.1 Global Sophon SceneTag and SceneExcel exports; source SHA-256 checked in scenebin71",
        "tables": rows,
        "limitations": [
            "Motif equality with native row count is an independent byte-layout observation; there is no proven per-record alignment or assigned native field at either sequence.",
            "A four-zero-byte motif may be a serialized default or padding; interpreting it as a marker/record delimiter requires the exact native row reader.",
            "The SceneTag 69 0D 4F motif may cross a serialized scalar boundary; field ownership is not established by frequency.",
            "Only the exact original binary and recovered native loader headers are authenticated; the virtual row reader at slot +0xF0 has not been recovered.",
            "Neither motif demonstrates scene placement, server drop_tag mapping, payout root, quantity or weight.",
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    for key, (motif, filename) in MOTIFS.items():
        parser.add_argument("--" + key.lower().replace("configdata", ""),
                            type=Path, required=True)
    parser.add_argument("--output", type=Path, default=OUTPUT)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    raw = {
        key: getattr(args, key.lower().replace("configdata", "")).read_bytes()
        for key in MOTIFS
    }
    report = inspect(raw)
    if args.check:
        if json.loads(args.output.read_text(encoding="utf-8")) != report:
            raise SystemExit("native scene motif evidence differs from original sources")
        print("PASS: exact 7.1 native scene motif observations")
    else:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2, ensure_ascii=False)+"\n",
                               encoding="utf-8")
    print(json.dumps({
        "status": report["status"],
        "observed": {name: {
            "rows": table["nativeLoaderRowCount"],
            "motif": table["motifBytesHex"],
            "occurrences": table["motifOccurrences"],
            "delimiterProven": table["motifProvenRowDelimiter"],
        } for name,table in report["tables"].items()},
    }, indent=2))


if __name__ == "__main__":
    main()
