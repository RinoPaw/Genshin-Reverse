from __future__ import annotations

import hashlib
import struct
from pathlib import Path


def _hash_file(path: Path, algorithm: str) -> str:
    h = hashlib.new(algorithm)
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(8 * 1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _pe_info(path: Path) -> dict[str, object]:
    with path.open("rb") as f:
        header = f.read(0x40)
        if len(header) < 0x40 or header[:2] != b"MZ":
            return {}
        pe_offset = struct.unpack_from("<I", header, 0x3C)[0]
        f.seek(pe_offset)
        if f.read(4) != b"PE\0\0":
            return {}
        coff = f.read(20)
        if len(coff) != 20:
            return {}
        optional_size = struct.unpack_from("<H", coff, 16)[0]
        optional = f.read(optional_size)
        if len(optional) < 32:
            return {}
        magic = struct.unpack_from("<H", optional, 0)[0]
        if magic == 0x20B:
            image_base = struct.unpack_from("<Q", optional, 24)[0]
        elif magic == 0x10B:
            image_base = struct.unpack_from("<I", optional, 28)[0]
        else:
            return {"pe_optional_magic": hex(magic)}
        return {
            "pe_optional_magic": hex(magic),
            "pe_image_base": hex(image_base),
        }


def fingerprint(path: Path) -> dict[str, object]:
    stat = path.stat()
    with path.open("rb") as f:
        magic = f.read(16)
    result: dict[str, object] = {
        "path": path.name,
        "size_bytes": stat.st_size,
        "magic_hex": magic.hex(),
        "sha256": _hash_file(path, "sha256"),
        "sha1": _hash_file(path, "sha1"),
        "md5": _hash_file(path, "md5"),
    }
    result.update(_pe_info(path))
    return result
