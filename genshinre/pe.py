from __future__ import annotations

import mmap
import struct
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class PESection:
    name: str
    virtual_address: int
    virtual_size: int
    raw_offset: int
    raw_size: int
    characteristics: int


class PEImage:
    def __init__(self, path: Path):
        self.path = path
        self._file = path.open("rb")
        try:
            self._map = mmap.mmap(self._file.fileno(), 0, access=mmap.ACCESS_READ)
        except Exception:
            self._file.close()
            raise
        try:
            self.image_base, self.sections = self._parse_headers()
        except Exception:
            self._map.close()
            self._file.close()
            raise

    def _parse_headers(self) -> tuple[int, list[PESection]]:
        data = self._map
        if len(data) < 0x40 or data[:2] != b"MZ":
            raise ValueError(f"not a PE image: {self.path}")
        pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
        if pe_offset + 24 > len(data) or data[pe_offset : pe_offset + 4] != b"PE\0\0":
            raise ValueError(f"invalid PE signature: {self.path}")

        coff = pe_offset + 4
        section_count = struct.unpack_from("<H", data, coff + 2)[0]
        optional_size = struct.unpack_from("<H", data, coff + 16)[0]
        optional = coff + 20
        if optional + optional_size > len(data):
            raise ValueError("truncated PE optional header")
        magic = struct.unpack_from("<H", data, optional)[0]
        if magic == 0x20B:
            image_base = struct.unpack_from("<Q", data, optional + 24)[0]
        elif magic == 0x10B:
            image_base = struct.unpack_from("<I", data, optional + 28)[0]
        else:
            raise ValueError(f"unsupported PE optional-header magic: 0x{magic:X}")

        section_table = optional + optional_size
        sections: list[PESection] = []
        for index in range(section_count):
            offset = section_table + index * 40
            if offset + 40 > len(data):
                raise ValueError("truncated PE section table")
            raw_name = bytes(data[offset : offset + 8]).split(b"\0", 1)[0]
            name = raw_name.decode("ascii", errors="replace")
            virtual_size = struct.unpack_from("<I", data, offset + 8)[0]
            virtual_address = struct.unpack_from("<I", data, offset + 12)[0]
            raw_size = struct.unpack_from("<I", data, offset + 16)[0]
            raw_offset = struct.unpack_from("<I", data, offset + 20)[0]
            characteristics = struct.unpack_from("<I", data, offset + 36)[0]
            sections.append(
                PESection(
                    name=name,
                    virtual_address=virtual_address,
                    virtual_size=virtual_size,
                    raw_offset=raw_offset,
                    raw_size=raw_size,
                    characteristics=characteristics,
                )
            )
        return image_base, sections

    def rva_to_offset(self, rva: int) -> int | None:
        for section in self.sections:
            span = max(section.virtual_size, section.raw_size)
            if section.virtual_address <= rva < section.virtual_address + span:
                delta = rva - section.virtual_address
                if delta >= section.raw_size:
                    return None
                offset = section.raw_offset + delta
                if offset >= len(self._map):
                    return None
                return offset
        return None

    def read_rva(self, rva: int, size: int) -> bytes:
        offset = self.rva_to_offset(rva)
        if offset is None:
            return b""
        end = min(offset + size, len(self._map))
        return bytes(self._map[offset:end])

    def close(self) -> None:
        self._map.close()
        self._file.close()

    def __enter__(self) -> "PEImage":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()
