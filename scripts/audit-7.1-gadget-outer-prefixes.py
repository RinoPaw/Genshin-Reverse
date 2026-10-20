#!/usr/bin/env python3
"""Source-gated observational audit of Global 7.1 Gadget outer row prefixes.

Only the exact pinned official GadgetExcel raw export is accepted. The parent
wire structure and the native map-reader consumer remain unresolved, so the
two-byte candidate control transform is descriptive, not a semantic decoder.
Original client bytes are never written into the output.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path

from genshinre.assetindex import unwrap_mihoyo_bin_data
from genshinre.gadgetbin import scan_gadget_payload

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = (ROOT / "versions/7.1.0-global/analyses/progression/economy"
          / "7.1-chest-native-gadget-outer-prefix-observations.json")
RAW_SHA256 = "a35e3f3ed04f950cb6302099d12aa71e23ece21d8fe578950347d9318f769e35"
PAYLOAD_SHA256 = "b8f35d6f3fe1aec90398ccbbe205335fe0d9ae45245b206096be5e434746c354"
RAW_BYTES = 2854888
PAYLOAD_BYTES = 2854884
ROW_COUNT = 30599
CANDIDATE_CONTROL_ADD = 0x5473


def observe(scan, payload: bytes) -> dict:
    """Summarize verified prefix boundaries, without parsing unknown fields."""
    by_mask = defaultdict(Counter)
    chest_by_mask = defaultdict(Counter)
    first_words: dict[int, int] = {}
    first_ids: dict[int, int] = {}
    total_prefix_bytes = 0
    header_length = 4
    if scan.opaque_header_hex != payload[:header_length].hex():
        raise ValueError("Gadget header no longer matches scan")
    for row in scan.rows:
        # Scanner associates row.prefix_start with the end of the previous
        # inner record, and id_wire_offset with the four bytes before its
        # inner-record marker.
        start, key_start, inner_start = row.prefix_start, row.id_wire_offset, row.inner_start
        if (key_start + 4 != inner_start or key_start - start < 2
                or inner_start > len(payload)):
            raise ValueError("invalid outer prefix/ID-candidate boundaries")
        prefix_length = inner_start - start
        raw_word = int.from_bytes(payload[start:start + 2], "little")
        candidate = (raw_word + CANDIDATE_CONTROL_ADD) & 0xFFFF
        by_mask[candidate][prefix_length] += 1
        existing = first_words.setdefault(candidate, raw_word)
        if existing != raw_word:
            raise ValueError("two raw control words map to the same candidate")
        first_ids.setdefault(candidate, row.id_candidate)
        if row.fields.get(0x6C) == 26:
            chest_by_mask[candidate][prefix_length] += 1
        total_prefix_bytes += prefix_length

    if total_prefix_bytes != scan.outer_prefix_bytes:
        raise ValueError("outer byte coverage disagrees with exact Gadget scan")
    if sum(sum(lengths.values()) for lengths in by_mask.values()) != len(scan.rows):
        raise ValueError("outer control histogram does not cover every row")

    def rows_with_lengths(group: dict[int, Counter]) -> dict:
        return {
            f"0x{candidate:04X}": {
                "rawFirstTwoBytesLe": f"0x{first_words[candidate]:04X}",
                "rows": sum(group[candidate].values()),
                "totalPrefixBytesIncludingCandidateId": sum(
                    n * count for n, count in group[candidate].items()),
                "prefixLengthHistogram": {
                    str(length): group[candidate][length]
                    for length in sorted(group[candidate])
                },
                "exampleGadgetIdCandidate": first_ids[candidate],
            } for candidate in sorted(group)
        }

    result = rows_with_lengths(by_mask)
    chest_rows = rows_with_lengths(chest_by_mask)
    return {
        "schemaVersion": 1,
        "status": "EXACT_7_1_OUTER_PREFIX_CONTROL_WORD_OBSERVED__NATIVE_LOADER_UNRESOLVED",
        "source": {
            "sample": "7.1.0-global/windows-x64",
            "officialClientBlock": "00/25539185.blk",
            "assetName": "GadgetExcelConfigData",
            "rawExportSha256": RAW_SHA256,
            "payloadSha256": PAYLOAD_SHA256,
            "nativeInnerReaderRva": "0x10278E50",
        },
        "observations": {
            "rowCount": len(scan.rows),
            "parentPrefixBytesIncludingIds": total_prefix_bytes,
            "candidateIdBytes": len(scan.rows) * 4,
            "uninterpretedPrefixBytes": total_prefix_bytes - len(scan.rows) * 4,
            "distinctFirstTwoByteValues": len(result),
            "distinctPrefixLengths": len({
                length for group in by_mask.values() for length in group
            }),
            "candidateControlWordTransform": "((little_endian_u16 + 0x5473) mod 2^16) - UNVERIFIED",
            "candidateControlWordHistogram": result,
            "chestSubsetCandidateTypeValue": 26,
            "chestSubsetRows": sum(sum(x.values()) for x in chest_by_mask.values()),
            "chestSubsetCandidateControlHistogram": chest_rows,
        },
        "limitations": [
            "A candidate two-byte control transform groups the exact observed bytes; its constant is not confirmed by the original loader.",
            "The 19 rows with candidate control 0xFFFE are a special observed encoding; do not interpret all set bits as present fields.",
            "Lengths of the remaining prefix fields, including optional/nested fields, have not been decoded from native instructions.",
            "A variable prefix length is not evidence of a reward tag, scene group, grade or payout rule.",
            "ID candidates still rely on an unverified four-byte key transform; their consistency is independently tested.",
            "The four-byte table header remains opaque, including the actual serialized row-count algorithm.",
            "This report must not be used to assign chest grades, drop tags or reward probabilities.",
        ],
    }


def audit(raw: bytes) -> dict:
    if len(raw) != RAW_BYTES or hashlib.sha256(raw).hexdigest() != RAW_SHA256:
        raise ValueError("exact 7.1 Gadget raw export size or SHA-256 mismatch")
    payload = unwrap_mihoyo_bin_data(raw)
    if (len(payload) != PAYLOAD_BYTES
            or hashlib.sha256(payload).hexdigest() != PAYLOAD_SHA256):
        raise ValueError("exact 7.1 Gadget payload SHA-256/size mismatch")
    scan = scan_gadget_payload(payload, expected_rows=ROW_COUNT)
    if len(scan.rows) != ROW_COUNT or scan.rows[-1].inner_end != len(payload):
        raise ValueError("incomplete original Gadget inner-row scan")
    report = observe(scan, payload)
    obs = report["observations"]
    if (obs["distinctFirstTwoByteValues"] != 12
            or obs["distinctPrefixLengths"] != 20
            or obs["chestSubsetRows"] != 309):
        raise ValueError("original Gadget outer-prefix evidence changed")
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--raw-export", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=OUTPUT)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    report = audit(args.raw_export.read_bytes())
    if args.check:
        if json.loads(args.output.read_text(encoding="utf-8")) != report:
            raise SystemExit("original 7.1 Gadget outer-prefix observations diverged")
        print("PASS: 30599 Gadget outer prefixes, 12 control candidates, 20 lengths")
    else:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n",
                               encoding="utf-8")
        print(json.dumps(report["observations"], indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
