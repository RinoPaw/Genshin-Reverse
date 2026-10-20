"""Exact Global 7.1 GadgetExcel *inner-record* wire scanner.

This uses the version-pinned 22-field reader reconstructed from
DCCHEHMHFGC.GMENPOPMKAA. The outer table header and per-record prefix are
not decoded: an exact-client marker permits read-only inner-record recovery,
and each skipped outer prefix is accounted for explicitly.

Field names here are candidate object displacements. Wrapper identities,
semantic enum labels, and server reward data are not inferred.
"""
from __future__ import annotations

from dataclasses import dataclass
from collections import Counter

from .assetindex import unwrap_mihoyo_bin_data
from .binconfig import BinaryConfigReader, decode_native_chunks

U16 = 0xFFFF
U32 = 0xFFFFFFFF
U64 = 0xFFFFFFFFFFFFFFFF
MASK_ADD = 0x466DB4EB
ID_ADD_CANDIDATE = 0x4894CEA6
MARKER = b"\xff\xff\xff\xff"

# Offset, presence bit, raw-wire kind, arguments; exact native read order.
# s: u16 length + constant, chunk-XOR UTF-8; a: u32 count + constant and s;
# d/q: unsigned width with integer transforms; b: encoded-byte != sentinel.
SCHEMA = (
    (0x7E, 17, "b", 0x62),
    (0x7D, 5, "b", 0x35),
    (0x98, 11, "q", ("xor", 0xAC9446F9)),
    (0x48, 22, "a", (0xC77C5B9A, 0xE9D9, 0x9714FF85FA17E9D9)),
    (0x79, 9, "b", 0x48),
    (0x80, 15, "d", ("xor", 0x3ABE8D00)),
    (0x88, 2, "q", ("add", 0xCBCBFA70)),
    (0x7A, 12, "b", 0x5B),
    (0x70, 3, "d", ("add", 0xA43303C2)),
    (0x78, 1, "b", 0x31),
    (0x74, 19, "d", ("xor", 0xFD1142B8)),
    (0x68, 18, "d", ("xor", 0x720DB4B4)),
    (0x50, 0, "s", (0x5E23, 0xBEEE8AD37BFE5E23)),
    (0x7C, 26, "b", 0x95),
    (0x84, 10, "d", ("add", 0xDA04D7C5)),
    (0x60, 24, "s", (0x7859, 0xFA1AE5AA1A987859)),
    (0x58, 25, "s", (0x6723, 0x897FDD2018EA6723)),
    (0x7B, 4, "b", 0x4D),
    (0x90, 16, "d", ("add", 0xCED888E1, "xor", 0x126916AF)),
    (0x94, 20, "d", ("add", 0x2EFB486E, "xor", 0xB5C6E8E2)),
    (0x6C, 7, "d", ("add", 0x9F6DBCA6, "xor", 0x0C064DBA)),
    (0x7F, 28, "b", 0x52),
)
ALLOWED_MASK = sum(1 << bit for _, bit, _, _ in SCHEMA)


class GadgetBinParseError(ValueError):
    pass


def _transform(value: int, arguments: tuple, *, width: int) -> int:
    limit = (1 << width) - 1
    for operation, constant in zip(arguments[::2], arguments[1::2]):
        if operation == "add":
            value = (value + constant) & limit
        elif operation == "xor":
            value = (value ^ constant) & limit
        else:
            raise GadgetBinParseError("unsupported Gadget wire operation")
    return value


def _string(reader: BinaryConfigReader, length_add: int, chunk_key: int) -> str:
    length = (reader.u16() + length_add) & U16
    raw = reader.take(length)
    try:
        return decode_native_chunks(raw, chunk_key, "xor").decode("utf-8")
    except UnicodeDecodeError as exc:
        raise GadgetBinParseError(f"invalid Gadget UTF-8 at 0x{reader.pos-length:X}") from exc


def _value(reader: BinaryConfigReader, kind: str, arg):
    if kind == "b":
        return reader.u8() != arg
    if kind == "d":
        return _transform(reader.u32(), arg, width=32)
    if kind == "q":
        return _transform(reader.u64(), arg, width=64)
    if kind == "s":
        return _string(reader, *arg)
    if kind == "a":
        count_add, length_add, chunk_key = arg
        count = (reader.u32() + count_add) & U32
        if count > (len(reader.data) - reader.pos) // 2:
            raise GadgetBinParseError(
                f"unbounded Gadget array count {count} at 0x{reader.pos:X}")
        return [_string(reader, length_add, chunk_key) for _ in range(count)]
    raise GadgetBinParseError(f"unknown Gadget inner-record field kind {kind}")


@dataclass(frozen=True)
class GadgetRow:
    id_candidate: int
    id_wire_offset: int
    inner_start: int
    inner_end: int
    prefix_start: int
    mask: int
    fields: dict[int, object]
    spans: dict[int, tuple[int, int]]

    @property
    def prefix_bytes(self) -> int:
        return self.inner_start - self.prefix_start


def read_inner_row(data: bytes, offset: int) -> tuple[int, dict, dict, int]:
    if offset < 0 or offset + 8 > len(data):
        raise GadgetBinParseError(f"invalid Gadget inner-record start 0x{offset:X}")
    reader = BinaryConfigReader(data, error_type=GadgetBinParseError, label="Gadget")
    reader.pos = offset
    mask = (reader.u64() + MASK_ADD) & U64
    if mask & ~ALLOWED_MASK:
        raise GadgetBinParseError(f"unrecognized Gadget row mask bits 0x{mask & ~ALLOWED_MASK:X}")
    fields: dict[int, object] = {}
    spans: dict[int, tuple[int, int]] = {}
    for displacement, bit, kind, arg in SCHEMA:
        if mask & (1 << bit):
            before = reader.pos
            fields[displacement] = _value(reader, kind, arg)
            spans[displacement] = (before, reader.pos)
    return mask, fields, spans, reader.pos


@dataclass(frozen=True)
class GadgetTableScan:
    opaque_header_hex: str
    rows: tuple[GadgetRow, ...]
    payload_bytes: int
    outer_prefix_bytes: int

    def summary(self) -> dict:
        present = Counter()
        for row in self.rows:
            present.update(row.fields)
        return {
            "status": "EXACT_7_1_GADGET_INNER_ROWS_DECODED__OUTER_PREFIX_UNRESOLVED",
            "opaqueHeaderHex": self.opaque_header_hex,
            "opaqueHeaderDecoded": False,
            "rowCountObserved": len(self.rows),
            "uniqueIdCandidates": len({row.id_candidate for row in self.rows}),
            "payloadBytes": self.payload_bytes,
            "outerPrefixBytesUnparsed": self.outer_prefix_bytes,
            "fieldPresentCounts": {f"0x{k:X}": present[k] for k in sorted(present)},
            "enum26CountCandidate": sum(row.fields.get(0x6C) == 26 for row in self.rows),
            "enum26DistinctNamesCandidate": len({
                row.fields.get(0x58)
                for row in self.rows if row.fields.get(0x6C) == 26
            }),
            "limitations": [
                "The marker scan is specific to the pinned Global 7.1 Gadget binary.",
                "Outer table header and variable per-row prefixes remain undecoded.",
                "The candidate ID additive transform and type-code meaning need independent native consumer validation.",
                "Full inner-record consumption does not mean all outer prefix bytes have been interpreted.",
                "No placed chest instance, four-grade assignment, reward root, item amount or rate is certified.",
            ],
        }


def scan_gadget_payload(data: bytes, *, expected_rows: int) -> GadgetTableScan:
    if len(data) < 12:
        raise GadgetBinParseError("Gadget payload too short")
    if expected_rows <= 0:
        raise GadgetBinParseError("expected Gadget row count must be positive")
    # This *exact observed version* has one 0xFFFFFFFF high-mask dword per
    # inner record. Never accept a mismatched marker count by guessing gaps.
    positions = []
    cursor = 0
    while True:
        found = data.find(MARKER, cursor)
        if found < 0:
            break
        positions.append(found - 4)
        cursor = found + 4
    if len(positions) != expected_rows:
        raise GadgetBinParseError(
            f"Gadget inner-record markers {len(positions)} != expected {expected_rows}")
    previous_end = 4
    rows: list[GadgetRow] = []
    ids: set[int] = set()
    outer_prefix_total = 0
    for index, inner_start in enumerate(positions):
        id_start = inner_start - 4
        if id_start < previous_end:
            raise GadgetBinParseError(f"overlapping Gadget prefix at row {index}")
        id_wire = int.from_bytes(data[id_start:inner_start], "little")
        candidate = (id_wire + ID_ADD_CANDIDATE) & U32
        if candidate in ids:
            raise GadgetBinParseError(f"duplicate Gadget ID candidate {candidate}")
        ids.add(candidate)
        mask, fields, spans, end = read_inner_row(data, inner_start)
        next_id_start = positions[index + 1] - 4 if index + 1 < len(positions) else len(data)
        if end > next_id_start:
            raise GadgetBinParseError(f"Gadget inner record overlaps next prefix at row {index}")
        if index == len(positions) - 1 and end != len(data):
            raise GadgetBinParseError("Gadget final inner record does not reach EOF")
        outer_prefix_total += inner_start - previous_end
        rows.append(GadgetRow(candidate, id_start, inner_start, end, previous_end,
                              mask, fields, spans))
        previous_end = end
    return GadgetTableScan(data[:4].hex(), tuple(rows), len(data), outer_prefix_total)


def scan_gadget_raw_export(raw: bytes, *, expected_rows: int) -> GadgetTableScan:
    return scan_gadget_payload(unwrap_mihoyo_bin_data(raw), expected_rows=expected_rows)
