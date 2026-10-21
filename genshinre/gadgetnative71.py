"""Exact Global 7.1 Gadget table framing and inherited-row wire reader.

Reconstructed from pinned Global 7.1 native methods:
  AACCGEFDDMD.GMENPOPMKAA  (0x968F690, table count / loop)
  FGGKFGECPJJ.GMENPOPMKAA  (0xBD56F60, inherited row)
  DCCHEHMHFGC.GMENPOPMKAA (0x10278E50, 22 Gadget fields)

The two base uint32 values (object displacements 0x18 and 0x30) pass through
an additional native value-type helper; the integers here are explicitly
*pre-wrapper* candidates pending consumer confirmation. No reward data is
recovered by this client configuration reader.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from typing import Any

from .binconfig import BinaryConfigReader, decode_native_chunks
from .gadgetbin import read_inner_row

U16 = 0xFFFF
U32 = 0xFFFFFFFF
U64 = 0xFFFFFFFFFFFFFFFF
TABLE_COUNT_ADD = 0x23F5AB5E
BASE_MASK_ADD = 0x5486
BASE_STRING_KEY = 0xDE637C82E062FF2D


class NativeGadgetTableError(ValueError):
    pass


@dataclass(frozen=True)
class NativeGadgetRow:
    index: int
    start: int
    inherited_end: int
    end: int
    inherited_mask: int
    inherited_fields: dict[int, Any]
    inherited_spans: dict[int, tuple[int, int]]
    gadget_mask: int
    gadget_fields: dict[int, Any]
    gadget_spans: dict[int, tuple[int, int]]

    @property
    def id_scalar_candidate(self) -> int:
        return self.inherited_fields[0x30]


@dataclass(frozen=True)
class NativeGadgetTable:
    header_raw_hex: str
    header_count: int
    rows: tuple[NativeGadgetRow, ...]
    consumed: int
    payload_bytes: int

    def summary(self) -> dict:
        base_presence = Counter()
        gadget_presence = Counter()
        masks = Counter()
        base_string_counts = Counter()
        for row in self.rows:
            base_presence.update(row.inherited_fields.keys())
            gadget_presence.update(row.gadget_fields.keys())
            masks[row.inherited_mask] += 1
            if 0x10 in row.inherited_fields:
                base_string_counts[row.inherited_fields[0x10]] += 1
        return {
            "status": "EXACT_7_1_NATIVE_GADGET_TABLE_AND_INHERITED_WIRE_DECODED",
            "headerRawHex": self.header_raw_hex,
            "headerCountDecoded": True,
            "nativeHeaderRowCount": self.header_count,
            "rowsDecoded": len(self.rows),
            "uniquePreWrapperIdScalars": len({row.id_scalar_candidate for row in self.rows}),
            "payloadBytes": self.payload_bytes,
            "consumedBytes": self.consumed,
            "inheritedWireBytes": sum(row.inherited_end-row.start for row in self.rows),
            "gadgetWireBytes": sum(row.end-row.inherited_end for row in self.rows),
            "inheritedMaskHistogram": {f"0x{k:02X}": masks[k] for k in sorted(masks)},
            "inheritedFieldPresenceByOffset": {f"0x{k:X}": base_presence[k] for k in sorted(base_presence)},
            "gadgetFieldPresenceByOffset": {f"0x{k:X}": gadget_presence[k] for k in sorted(gadget_presence)},
            "inheritedStringCounts": dict(sorted(base_string_counts.items())),
            "chestType26CountCandidate": sum(
                row.gadget_fields.get(0x6C) == 26 for row in self.rows),
            "limitations": [
                "The table header count, inherited field-mask addend and wire read order are pinned to exact 7.1 native instructions.",
                "The two inherited four-byte scalar fields pass through an additional native wrapper conversion; their memory layout remains to be traced.",
                "Obfuscated field names, enum meaning and Gadget definition ownership still need an independent consumer link.",
                "The table contains Gadget definitions, not scene placements or server reward probabilities.",
            ],
        }


def decode_header_count(payload: bytes) -> int:
    if len(payload) < 4:
        raise NativeGadgetTableError("truncated Gadget table header")
    count = (int.from_bytes(payload[:4], "little") + TABLE_COUNT_ADD) & U32
    if count == 0 or count > (len(payload)-4)//10:
        raise NativeGadgetTableError(f"impossible Gadget header count {count}")
    return count


def _native_base_string(reader: BinaryConfigReader) -> str:
    n = ((reader.u16() - 0xD3) ^ 0x7C82) & U16
    if n > len(reader.data)-reader.pos:
        raise NativeGadgetTableError("truncated inherited Gadget string")
    raw = reader.take(n)
    decoded = decode_native_chunks(raw, BASE_STRING_KEY, "xor")
    try:
        return decoded.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise NativeGadgetTableError(f"invalid inherited Gadget UTF-8 at 0x{reader.pos-n:X}") from exc


def read_inherited_row(reader: BinaryConfigReader) -> tuple[int, dict[int, Any], dict[int, tuple[int, int]]]:
    """Native field order. Keys are unverified managed object displacements."""
    raw_mask = reader.u16()
    mask = (raw_mask + BASE_MASK_ADD) & U16
    if mask & ~0xFF:
        raise NativeGadgetTableError(f"unrecognized inherited Gadget mask bits 0x{mask:X}")
    fields: dict[int, Any] = {}
    spans: dict[int, tuple[int, int]] = {}

    def read(offset: int, fn):
        start = reader.pos
        fields[offset] = fn()
        spans[offset] = (start, reader.pos)

    # These displacements are the parent-object's native direct stores.
    if mask & 0x20:  # rva 0xBD56FD5
        read(0x40, lambda: reader.u64() ^ 0xA269090E)
    if mask & 0x04:  # rva 0xBD5702C
        read(0x20, lambda: reader.u64() ^ 0x67754856)
    if mask & 0x01:  # rva 0xBD57039
        read(0x34, lambda: (reader.u32() + 0xCFCCA56B) & U32)
    if mask & 0x80:  # rva 0xBD57044
        read(0x10, lambda: _native_base_string(reader))
    if mask & 0x02:  # rva 0xBD571E9
        read(0x18, lambda: (reader.u32() + 0xC6E69CA5) & U32)
    if mask & 0x08:  # rva 0xBD57248
        read(0x38, lambda: reader.u64() ^ 0xA3ED922C)
    if mask & 0x40:  # rva 0xBD57257
        read(0x28, lambda: ((reader.u64() + 0xCD92A1B8) & U64) ^ 0x87A58EB3)
    if mask & 0x10:  # rva 0xBD57264
        read(0x30, lambda: (reader.u32() + 0x4894CEA6) & U32)
    return mask, fields, spans


def scan_native_gadget_table(payload: bytes, *, expected_rows: int | None = None) -> NativeGadgetTable:
    """Sequentially read header, base object and 22 Gadget fields until EOF.

    No marker hunting, assumed record length, fallback schema, or historical
    server table is involved. The identity of the exact binary must be checked
    by the source-hash gate *before* calling this generic in-memory function.
    """
    count = decode_header_count(payload)
    if expected_rows is not None and count != expected_rows:
        raise NativeGadgetTableError(
            f"native Gadget header count {count} != expected {expected_rows}")
    reader = BinaryConfigReader(payload, error_type=NativeGadgetTableError, label="native Gadget")
    reader.pos = 4
    rows: list[NativeGadgetRow] = []
    ids: set[int] = set()
    for index in range(count):
        start = reader.pos
        mask, base, base_spans = read_inherited_row(reader)
        inherited_end = reader.pos
        if 0x30 not in base:
            raise NativeGadgetTableError(f"Gadget row {index} lacks required native key scalar")
        candidate_id = base[0x30]
        if candidate_id in ids:
            raise NativeGadgetTableError(f"duplicate Gadget native ID scalar {candidate_id}")
        ids.add(candidate_id)
        gadget_mask, gadget, gadget_spans, end = read_inner_row(payload, inherited_end)
        if end <= inherited_end or end > len(payload):
            raise NativeGadgetTableError(f"Gadget row {index} inner reader out of bounds")
        rows.append(NativeGadgetRow(
            index, start, inherited_end, end, mask, base, base_spans,
            gadget_mask, gadget, gadget_spans))
        reader.pos = end
    if reader.pos != len(payload):
        raise NativeGadgetTableError(
            f"unexpected trailing Gadget bytes: {len(payload)-reader.pos}")
    return NativeGadgetTable(payload[:4].hex(), count, tuple(rows), reader.pos, len(payload))
