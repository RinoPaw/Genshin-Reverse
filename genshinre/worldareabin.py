"""Strict binary decoder for the original 7.1 Global WorldArea scene payloads.

Every transformation/conditional is from the exact pinned Windows x64
client native reader chain. Object layouts here are deliberately neutral:
decoded fields are recorded by offsets, without inheriting older obfuscated
community field names. Never assume absent members or shapes are zero.
"""
from __future__ import annotations

import math
import struct
from dataclasses import dataclass

from .binconfig import BinaryConfigReader

U32 = 0xFFFFFFFF


class WorldAreaBinError(ValueError):
    pass


@dataclass
class WorldAreaBinaryDecoder:
    reader: BinaryConfigReader

    @classmethod
    def from_bytes(cls, raw: bytes) -> "WorldAreaBinaryDecoder":
        return cls(BinaryConfigReader(raw, error_type=WorldAreaBinError, label="WorldArea 7.1"))

    def bounded_count(self, raw: int, transform: str, constant: int,
                      *, minimum_bytes: int = 1) -> int:
        if transform == "add":
            n = (raw + constant) & U32
        elif transform == "xor":
            n = raw ^ constant
        elif transform == "addxor":
            add, xor = constant
            n = ((raw + add) & U32) ^ xor
        else:
            raise WorldAreaBinError("unsupported count operation")
        if n > (len(self.reader.data) - self.reader.pos) // minimum_bytes:
            raise WorldAreaBinError(
                f"decoded array count {n} exceeds source length at 0x{self.reader.pos:X}"
            )
        return n

    def vector3(self) -> dict:
        r = self.reader
        start = r.pos
        marker = (r.u8() + 0xA7) & 0xFF
        coordinates: dict[str, float | None] = {"x": None, "y": None, "z": None}
        for bit, component, operation in (
            (0x02, "y", lambda v: ((v + 0x66D8B127) & U32) ^ 0x3E98C6BE),
            (0x40, "z", lambda v: (v + 0x25F781DF) & U32),
            (0x04, "x", lambda v: v ^ 0xDF729864),
        ):
            if marker & bit:
                native_word = operation(r.u32()) & U32
                value = struct.unpack("<f", struct.pack("<I", native_word))[0]
                if not math.isfinite(value):
                    raise WorldAreaBinError(f"nonfinite native vector {component} at 0x{start:X}")
                coordinates[component] = value
        return {"marker": marker, "coordinates": coordinates, "start": start, "end": r.pos}

    def vertices(self) -> dict:
        start = self.reader.pos
        n = self.bounded_count(
            self.reader.u32(), "addxor", (0x1E26A455, 0xC19205C3)
        )
        points = [self.vector3() for _ in range(n)]
        return {"count": n, "points": points, "start": start, "end": self.reader.pos}

    def spatial_shape(self) -> dict:
        r = self.reader
        start = r.pos
        mask = (r.u8() + 0x5F) & 0xFF
        active = (r.u8() != 0xF4) if mask & 0x02 else None
        scalar3c = (r.u32() ^ 0xC9C5C7DB) if mask & 0x10 else None
        vec24 = self.vector3() if mask & 0x80 else None
        vec30 = self.vector3() if mask & 0x01 else None
        points = self.vertices() if mask & 0x20 else None
        return {
            "marker": mask, "offset_0x20_bool": active,
            "offset_0x3C_u32": scalar3c,
            "offset_0x24_vector": vec24,
            "offset_0x30_vector": vec30,
            "offset_0x18_vertices": points,
            "start": start, "end": r.pos,
        }

    def area_record(self) -> dict:
        r = self.reader
        start = r.pos
        mask = (r.u8() + 0xFC) & 0xFF
        shape = self.spatial_shape() if mask & 0x80 else None
        scalar18 = ((r.u32() + 0x7B4A79A4) & U32) if mask & 0x04 else None
        scalar1c = (r.u32() ^ 0xB3B8156D) if mask & 0x20 else None
        return {
            "marker": mask, "offset_0x10_shape": shape,
            "offset_0x18_u32": scalar18, "offset_0x1C_u32": scalar1c,
            "start": start, "end": r.pos,
        }

    def child_array(self) -> dict:
        start = self.reader.pos
        n = self.bounded_count(self.reader.u32(), "xor", 0xFBD01BCE)
        values = [self.area_record() for _ in range(n)]
        return {"count": n, "values": values, "start": start, "end": self.reader.pos}

    def parent_element(self) -> dict:
        r = self.reader
        start = r.pos
        mask = ((r.u8() + 0x15) ^ 0x55) & 0xFF
        record = self.area_record() if mask & 0x40 else None
        children = self.child_array() if mask & 0x01 else None
        return {
            "marker": mask, "area_record": record, "child_array": children,
            "start": start, "end": r.pos,
        }


def decode_world_area(raw: bytes) -> dict:
    parser = WorldAreaBinaryDecoder.from_bytes(raw)
    r = parser.reader
    marker = r.u8()
    if marker != 0xCB:
        raise WorldAreaBinError(f"unexpected WorldArea root marker 0x{marker:02X}")
    count = parser.bounded_count(r.u32(), "add", 0x91B65B45)
    parents = [parser.parent_element() for _ in range(count)]
    if r.pos != len(raw):
        raise WorldAreaBinError(
            f"WorldArea unconsumed trailing bytes at 0x{r.pos:X}: {len(raw)-r.pos}"
        )
    return {
        "status": "EXACT_NATIVE_7_1_WIRE_DECODED",
        "sourceBytes": len(raw), "consumedBytes": r.pos,
        "rootMarker": marker, "parentCount": count, "parents": parents,
    }
