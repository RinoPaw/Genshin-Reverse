"""Decode original Global 7.1 Unity SECTR_StreamerRoot MonoBehaviour raw exports.

This is the serialized component body, not a reconstruction of terrain meshes.
"""
from __future__ import annotations

from dataclasses import dataclass
import struct


@dataclass(frozen=True)
class SectorRoot:
    game_object_path_id: int
    script_path_id: int
    enabled: bool
    config_name: str
    world_name: str
    manual_load: bool
    sectors: tuple[str, ...]
    blacklisted_sectors: tuple[str, ...]


class _Reader:
    def __init__(self, payload: bytes) -> None:
        self.data = payload
        self.pos = 0

    def take(self, count: int) -> bytes:
        if count < 0 or self.pos + count > len(self.data):
            raise ValueError("truncated original sector MonoBehaviour")
        result = self.data[self.pos:self.pos+count]
        self.pos += count
        return result

    def u8(self) -> int:
        return self.take(1)[0]

    def u32(self) -> int:
        return struct.unpack("<I", self.take(4))[0]

    def pptr(self) -> int:
        file_id = struct.unpack("<i", self.take(4))[0]
        path_id = struct.unpack("<q", self.take(8))[0]
        if file_id != 0:
            raise ValueError("unexpected external-sector PPtr")
        return path_id

    def align(self) -> None:
        self.take((-self.pos) % 4)

    def string(self) -> str:
        length = self.u32()
        # Limit is a structure-validation guard, not a game-world bound.
        if length > 1_000_000:
            raise ValueError("invalid original sector string length")
        text = self.take(length).decode("utf-8")
        self.align()
        return text

    def names(self) -> tuple[str, ...]:
        count = self.u32()
        if count > 100_000:
            raise ValueError("invalid original sector name count")
        return tuple(self.string() for _ in range(count))


def parse_sector_root(payload: bytes) -> SectorRoot:
    reader = _Reader(payload)
    game_object = reader.pptr()
    enabled = reader.u8() != 0
    reader.align()
    script = reader.pptr()
    name = reader.string()
    if name:
        raise ValueError("expected empty serialized SECTR_StreamerRoot m_Name")
    config = reader.string()
    world = reader.string()
    manual = reader.u8() != 0
    reader.align()
    sectors = reader.names()
    blacklist = reader.names()
    if reader.pos != len(payload):
        raise ValueError("unconsumed original SECTR_StreamerRoot bytes")
    return SectorRoot(
        game_object, script, enabled, config, world, manual, sectors, blacklist
    )
