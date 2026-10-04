from __future__ import annotations

import argparse
import bisect
import json
import struct
from collections import Counter
from pathlib import Path

from genshinre.callxref import scan_direct_call_xrefs
from genshinre.nativeprofile import PROFILE_71
from genshinre.pe import PEImage
from genshinre.sampleidentity import require_sha256

M32 = 0xFFFFFFFF

# Exact Global 7.1 constants recovered from the pinned executable's metadata-usage
# initializer around RVA 0x523400. Keep this research helper sample-guarded.
LIST_TABLE_HEADER_OFFSET = 0x15C
LIST_TABLE_HEADER_XOR = 0x7AFBCC1D
PAIR_TABLE_HEADER_OFFSET = 0x1E4
PAIR_TABLE_HEADER_ADD = 0x8DFB403D

LITERAL_TABLE_HEADER_OFFSET = 0x1C8
LITERAL_TABLE_HEADER_ADD = 0x9B13A93F
LITERAL_DATA_HEADER_OFFSET = 0x50
LITERAL_DATA_HEADER_ADD = 0xA32C143D

LIST_INDEX_MUL = 0xD987DF63
LIST_INDEX_SUB = 0x66D4F24B
LIST_INDEX_XOR = 0x6B05DBD6
LIST_INDEX_MUL2 = 0x7B92463D
LIST_VALUE_XOR = 0x684F73D6

PAIR_INDEX_MUL = 0x92DD
PAIR_INDEX_ADD = 0x4F440D42
PAIR_MASK_XOR1 = 0x3455F4E9
PAIR_MASK_MUL = 0x2AACE465
PAIR_MASK_XOR2 = 0x65D8218A
PAIR_MASK_ADD = 0x14032AEE
PAIR_A_ADD = 0x9D8F2FB5
PAIR_B_XOR = 0x5C14F482

LITERAL_USAGE_KIND = 5
DEFAULT_INITIALIZER_RVA = 0x523400


def u32(data: bytes, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def _header_candidates(exe: Path) -> list[tuple[int, bytes]]:
    out: list[tuple[int, bytes]] = []
    with PEImage(exe) as image:
        for section in image.sections:
            if section.raw_size <= 0:
                continue
            blob = image.read_rva(section.virtual_address, section.raw_size)
            start = 0
            while True:
                pos = blob.find(b"MHY\0", start)
                if pos < 0:
                    break
                rva = section.virtual_address + pos
                header = image.read_rva(rva, 0x240)
                if len(header) == 0x240:
                    out.append((rva, header))
                start = pos + 1
    return out


def find_metadata_layout(
    exe: Path,
    *,
    literal_table_file_offset: int,
    literal_data_file_offset: int,
) -> dict[str, int]:
    """Identify the MHY header and establish the runtime-metadata/file offset delta."""

    matches: list[dict[str, int]] = []
    for header_rva, header in _header_candidates(exe):
        literal_table_rel = (u32(header, LITERAL_TABLE_HEADER_OFFSET) + LITERAL_TABLE_HEADER_ADD) & M32
        literal_data_rel = (u32(header, LITERAL_DATA_HEADER_OFFSET) + LITERAL_DATA_HEADER_ADD) & M32
        delta_table = literal_table_file_offset - literal_table_rel
        delta_data = literal_data_file_offset - literal_data_rel
        if delta_table != delta_data or delta_table < 0:
            continue

        list_rel = u32(header, LIST_TABLE_HEADER_OFFSET) ^ LIST_TABLE_HEADER_XOR
        pair_rel = (u32(header, PAIR_TABLE_HEADER_OFFSET) + PAIR_TABLE_HEADER_ADD) & M32
        matches.append(
            {
                "header_rva": header_rva,
                "file_base_delta": delta_table,
                "literal_table_rel": literal_table_rel,
                "literal_data_rel": literal_data_rel,
                "usage_list_table_rel": list_rel,
                "usage_pair_table_rel": pair_rel,
                "usage_list_table_file_offset": delta_table + list_rel,
                "usage_pair_table_file_offset": delta_table + pair_rel,
            }
        )

    if len(matches) != 1:
        raise ValueError(f"expected exactly one matching MHY header, found {len(matches)}")
    return matches[0]


def decode_usage_list_start(metadata: bytes, table_offset: int, index: int) -> int:
    base = (index * LIST_INDEX_MUL) & M32
    mask = (base - LIST_INDEX_SUB) & M32
    mask ^= LIST_INDEX_XOR
    mask = (mask * LIST_INDEX_MUL2) & M32
    raw = u32(metadata, table_offset + index * 4)
    return (mask ^ raw ^ LIST_VALUE_XOR) & M32


def discover_usage_list_starts(
    metadata: bytes,
    list_table_offset: int,
    pair_table_offset: int,
    *,
    max_lists: int = 2_000_000,
) -> list[int]:
    pair_capacity = max(0, (len(metadata) - pair_table_offset) // 8)
    table_capacity = max(0, (len(metadata) - list_table_offset) // 4)
    limit = min(max_lists + 1, table_capacity)
    starts: list[int] = []

    for index in range(limit):
        value = decode_usage_list_start(metadata, list_table_offset, index)
        if value > pair_capacity:
            break
        if starts and value < starts[-1]:
            break
        starts.append(value)

    if len(starts) < 2:
        raise ValueError("failed to discover a plausible metadata usage-list prefix")
    if starts[0] != 0:
        raise ValueError(f"unexpected first metadata usage start: {starts[0]}")
    return starts


def pair_mask(index: int) -> int:
    value = (index * PAIR_INDEX_MUL + PAIR_INDEX_ADD) & M32
    value ^= PAIR_MASK_XOR1
    value = (value * PAIR_MASK_MUL) & M32
    value ^= PAIR_MASK_XOR2
    return (value + PAIR_MASK_ADD) & M32


def decode_usage_pair(metadata: bytes, table_offset: int, index: int) -> tuple[int, int, int, int]:
    raw_a, raw_b = struct.unpack_from("<II", metadata, table_offset + index * 8)
    mask = pair_mask(index)
    a = (((raw_a + PAIR_A_ADD) & M32) ^ mask) & M32
    b = (mask ^ raw_b ^ PAIR_B_XOR) & M32
    return a >> 29, a & 0x1FFFFFFF, b, a


def find_literal_usages(
    metadata: bytes,
    starts: list[int],
    pair_table_offset: int,
    literal_indices: set[int],
    *,
    literal_count: int,
) -> tuple[list[dict[str, int]], dict[str, object]]:
    pair_count = starts[-1]
    hits: list[dict[str, int]] = []
    kinds: Counter[int] = Counter()
    literal_total = 0
    literal_in_range = 0
    literal_max_source = -1

    for pair_index in range(pair_count):
        kind, source, dest, _ = decode_usage_pair(metadata, pair_table_offset, pair_index)
        kinds[kind] += 1
        if kind == LITERAL_USAGE_KIND:
            literal_total += 1
            literal_max_source = max(literal_max_source, source)
            if source < literal_count:
                literal_in_range += 1
            if source in literal_indices:
                list_index = bisect.bisect_right(starts, pair_index) - 1
                hits.append(
                    {
                        "literal_index": source,
                        "pair_index": pair_index,
                        "usage_list_index": list_index,
                        "destination_slot": dest,
                    }
                )

    validation = {
        "usage_list_count": len(starts) - 1,
        "usage_pair_count": pair_count,
        "kind_counts": {str(k): v for k, v in sorted(kinds.items())},
        "literal_usage_kind": LITERAL_USAGE_KIND,
        "literal_usage_count": literal_total,
        "literal_sources_in_range": literal_in_range,
        "literal_source_valid_ratio": 0.0 if literal_total == 0 else literal_in_range / literal_total,
        "literal_max_source": literal_max_source,
        "literal_count": literal_count,
    }
    return hits, validation


def _match_initializer_calls(
    exe: Path,
    methods_csv: Path,
    initializer_rva: int,
    target_lists: set[int],
) -> dict[str, object]:
    scan = scan_direct_call_xrefs(
        exe,
        [initializer_rva],
        methods_csv=methods_csv,
        window=64,
    )
    rows = scan["matches"].get(f"0x{initializer_rva:X}", [])
    matches: list[dict[str, object]] = []
    with PEImage(exe) as image:
        for row in rows:
            site = int(str(row["instruction_rva"]), 0)
            before = min(96, site)
            context = image.read_rva(site - before, before)
            matched_lists = []
            for list_index in sorted(target_lists):
                pattern = b"\xB9" + int(list_index).to_bytes(4, "little")
                if pattern in context:
                    matched_lists.append(list_index)
            if matched_lists:
                matches.append(
                    {
                        "call_rva": f"0x{site:X}",
                        "matched_usage_lists": matched_lists,
                        "caller_methods": row.get("caller_methods", []),
                        "context_rva": f"0x{site - before:X}",
                        "context_hex": context.hex(),
                    }
                )
    return {
        "initializer_rva": f"0x{initializer_rva:X}",
        "direct_call_count": len(rows),
        "matched_call_count": len(matches),
        "matches": matches,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("exe", type=Path)
    parser.add_argument("metadata", type=Path)
    parser.add_argument("--methods-csv", type=Path, required=True)
    parser.add_argument("--literal-index", type=int, action="append", required=True)
    parser.add_argument("--literal-count", type=int, required=True)
    parser.add_argument("--literal-table-file-offset", type=lambda s: int(s, 0), required=True)
    parser.add_argument("--literal-data-file-offset", type=lambda s: int(s, 0), required=True)
    parser.add_argument("--initializer-rva", type=lambda s: int(s, 0), default=DEFAULT_INITIALIZER_RVA)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    require_sha256(args.exe, PROFILE_71.exe_sha256, label="Global 7.1 executable")
    require_sha256(args.metadata, PROFILE_71.metadata_sha256, label="Global 7.1 metadata")
    metadata = args.metadata.read_bytes()

    layout = find_metadata_layout(
        args.exe,
        literal_table_file_offset=args.literal_table_file_offset,
        literal_data_file_offset=args.literal_data_file_offset,
    )
    list_offset = int(layout["usage_list_table_file_offset"])
    pair_offset = int(layout["usage_pair_table_file_offset"])
    starts = discover_usage_list_starts(metadata, list_offset, pair_offset)
    hits, validation = find_literal_usages(
        metadata,
        starts,
        pair_offset,
        set(args.literal_index),
        literal_count=args.literal_count,
    )
    target_lists = {row["usage_list_index"] for row in hits}
    callsites = _match_initializer_calls(
        args.exe,
        args.methods_csv,
        args.initializer_rva,
        target_lists,
    )

    result = {
        "sample": {
            "exe_sha256": PROFILE_71.exe_sha256,
            "metadata_sha256": PROFILE_71.metadata_sha256,
        },
        "layout": {key: (f"0x{value:X}" if "offset" in key or key.endswith("rva") or key.endswith("rel") or key == "file_base_delta" else value) for key, value in layout.items()},
        "targets": sorted(args.literal_index),
        "hits": hits,
        "validation": validation,
        "initializer_calls": callsites,
    }
    args.output.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
