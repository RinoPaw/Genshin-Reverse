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


# Recovered from the exact native inherited reader
# FGGKFGECPJJ.GMENPOPMKAA at RVA 0xBD56F60.
HEADER_COUNT_ADD = 0x23F5AB5E
BASE_MASK_ADD = 0x5486
BASE_STRING_KEY = 0xDE637C82E062FF2D
# presence flag, candidate memory displacement, wire kind and transforms.
BASE_SCHEMA = (
    (0x20, 0x40, "q", ("xor", 0xA269090E)),
    (0x04, 0x20, "q", ("xor", 0x67754856)),
    (0x01, 0x34, "d", ("add", 0xCFCCA56B)),
    (0x80, 0x10, "string", None),
    (0x02, 0x18, "d", ("add", 0xC6E69CA5)),
    (0x08, 0x38, "q", ("xor", 0xA3ED922C)),
    (0x40, 0x28, "q", ("add", 0xCD92A1B8, "xor", 0x87A58EB3)),
    (0x10, 0x30, "d", ("add", 0x4894CEA6)),
)


def read_inherited_row(reader: BinaryConfigReader) -> tuple[int, dict, dict]:
    """Read native inherited fields and ID, preserving true wire omission."""
    mask = (reader.u16() + BASE_MASK_ADD) & U16
    if mask & ~0xFF:
        raise GadgetBinParseError(f"unrecognized native Gadget base mask 0x{mask:X}")
    if not (mask & 0x10):
        raise GadgetBinParseError("native Gadget ID absent on wire")
    fields, spans = {}, {}
    for flag, offset, kind, operations in BASE_SCHEMA:
        if not (mask & flag):
            continue
        start = reader.pos
        if kind == "d":
            fields[offset] = _transform(reader.u32(), operations, width=32)
        elif kind == "q":
            fields[offset] = _transform(reader.u64(), operations, width=64)
        elif kind == "string":
            # Exactly the native u16 subtract/xor and chunk-XOR UTF-8 path.
            length = (((reader.u16() - 0xD3) & U16) ^ 0x7C82)
            raw = reader.take(length)
            try:
                fields[offset] = decode_native_chunks(
                    raw, BASE_STRING_KEY, "xor").decode("utf-8")
            except UnicodeDecodeError as exc:
                raise GadgetBinParseError(
                    f"invalid inherited Gadget UTF-8 at 0x{reader.pos-length:X}") from exc
        else:
            raise GadgetBinParseError(f"unrecognized base wire type {kind}")
        spans[offset] = (start, reader.pos)
    return mask, fields, spans


@dataclass(frozen=True)
class GadgetRow:
    gadget_id: int
    base_start: int
    base_end: int
    inner_start: int
    inner_end: int
    base_mask: int
    mask: int
    base_fields: dict[int, object]
    fields: dict[int, object]
    base_spans: dict[int, tuple[int, int]]
    spans: dict[int, tuple[int, int]]


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
    header_hex: str
    header_count: int
    rows: tuple[GadgetRow, ...]
    payload_bytes: int
    base_decoded_bytes: int

    def summary(self) -> dict:
        present = Counter()
        for row in self.rows:
            present.update(row.fields.keys())
        return {
            "status": "EXACT_7_1_GADGET_COMPLETE_NATIVE_TABLE_DECODE",
            "headerHex": self.header_hex,
            "headerCountDecoded": True,
            "decodedHeaderCount": self.header_count,
            "rowCountObserved": len(self.rows),
            "uniqueIds": len({row.gadget_id for row in self.rows}),
            "payloadBytes": self.payload_bytes,
            "baseDecodedBytes": self.base_decoded_bytes,
            "innerDecodedBytes": sum(row.inner_end - row.inner_start for row in self.rows),
            "unparsedBytes": 0,
            "fieldPresentCounts": {f"0x{k:X}": present[k] for k in sorted(present)},
            "enum26Count": sum(row.fields.get(0x6C) == 26 for row in self.rows),
            "enum26DistinctNames": len({
                row.fields.get(0x58)
                for row in self.rows if row.fields.get(0x6C) == 26
            }),
            "limitations": [
                "All 7.1 client Gadget serialized bytes and the native table count are decoded.",
                "The in-memory field-to-token mapping still relies on the pinned metadata layout candidate.",
                "Semantic meanings of inherited wrapper fields and type codes remain unverified.",
                "The client Gadget definition table has no authenticated scene drop_tag or server reward data.",
            ],
        }


def scan_gadget_payload(data: bytes, *, expected_rows: int) -> GadgetTableScan:
    """Parse header and all rows sequentially by the exact native reader path."""
    if len(data) < 4 or expected_rows <= 0:
        raise GadgetBinParseError("invalid Gadget data size or expected count")
    reader = BinaryConfigReader(data, error_type=GadgetBinParseError, label="Gadget")
    header_raw = reader.u32()
    count = (header_raw + HEADER_COUNT_ADD) & U32
    if count != expected_rows:
        raise GadgetBinParseError(f"native Gadget header count {count} != {expected_rows}")
    if count > (len(data) - 4) // 14:
        raise GadgetBinParseError("native Gadget count exceeds remaining input bounds")
    rows: list[GadgetRow] = []
    seen: set[int] = set()
    base_total = 0
    for i in range(count):
        base_start = reader.pos
        base_mask, base_fields, base_spans = read_inherited_row(reader)
        base_end = reader.pos
        gadget_id = base_fields[0x30]
        if gadget_id in seen:
            raise GadgetBinParseError(f"duplicate Gadget ID {gadget_id} at row {i}")
        seen.add(gadget_id)
        inner_start = reader.pos
        mask, fields, spans, inner_end = read_inner_row(data, inner_start)
        reader.pos = inner_end
        base_total += base_end - base_start
        rows.append(GadgetRow(gadget_id, base_start, base_end, inner_start, inner_end,
                              base_mask, mask, base_fields, fields, base_spans, spans))
    if reader.pos != len(data):
        raise GadgetBinParseError(
            f"Gadget table has {len(data) - reader.pos} trailing bytes at 0x{reader.pos:X}")
    return GadgetTableScan(data[:4].hex(), count, tuple(rows), len(data), base_total)


def scan_gadget_raw_export(raw: bytes, *, expected_rows: int) -> GadgetTableScan:
    return scan_gadget_payload(unwrap_mihoyo_bin_data(raw), expected_rows=expected_rows)
