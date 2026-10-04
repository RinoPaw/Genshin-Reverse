from __future__ import annotations

import hashlib
import struct
from pathlib import Path

_HASH_ALGORITHMS = ("sha256", "sha1", "md5")


def _hashes(path: Path) -> dict[str, str]:
    digests = {name: hashlib.new(name) for name in _HASH_ALGORITHMS}
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(8 * 1024 * 1024), b""):
            for digest in digests.values():
                digest.update(chunk)
    return {name: digest.hexdigest() for name, digest in digests.items()}


def _format_name(magic: bytes) -> str:
    if magic.startswith(b"MZ"):
        return "pe"
    if magic.startswith(b"MHY\x00"):
        return "mhy-obfuscated-metadata"
    if magic.startswith(bytes.fromhex("af1bb1fa")):
        return "standard-il2cpp-metadata"
    return "unknown"


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
        magic = f.read(32)
    hashes = _hashes(path)
    result: dict[str, object] = {
        "path": path.name,
        "size_bytes": stat.st_size,
        "magic_hex": magic[:16].hex(),
        "format": _format_name(magic),
        **hashes,
    }
    result.update(_pe_info(path))
    return result
