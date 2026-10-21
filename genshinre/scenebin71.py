"""Source-pinned original Global 7.1 SceneExcel and SceneTag *headers*.

The exact native table loaders are:
  HPNMCGDJOJL.GMENPOPMKAA, method 279989, RVA 0xA6C7000 (add)
  EJCNENCJADF.GMENPOPMKAA, method 696653, RVA 0x14015460 (xor).

Both loop over the verified decoded row count and invoke the row
reader indirectly through a virtual slot at +0xF0. No row field schema
or scene drop_tag meaning is asserted until that dynamic consumer is
recovered from the same pinned sample.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import struct

from .assetindex import unwrap_mihoyo_bin_data

U32 = 0xFFFFFFFF


class SceneBin71Error(ValueError):
    pass


@dataclass(frozen=True)
class OriginalSceneTableHeader:
    source: str
    raw_export_sha256: str
    payload_sha256: str
    raw_u32: int
    operation: str
    immediate: int
    row_count: int
    payload_bytes: int

    def summary(self) -> dict:
        return {
            "source": self.source,
            "rawExportSha256": self.raw_export_sha256,
            "payloadSha256": self.payload_sha256,
            "rawHeaderU32": f"0x{self.raw_u32:08X}",
            "nativeOperation": self.operation,
            "nativeImmediate": f"0x{self.immediate:08X}",
            "nativeRowCount": self.row_count,
            "payloadBytes": self.payload_bytes,
            "rowSchemaDecoded": False,
            "sceneGadgetOwnershipProven": False,
            "serverDropTagProven": False,
        }


SOURCES = {
    "SceneTagConfigData": {
        "raw_sha": "f0cada8ea11c59fb32b72f0dd19e3aaf69af31382ed012573b9de92954567075",
        "payload_sha": "9c043ecdbfba6a17c00243b37ae2bb3566ac9c09dcf800b648a76c3e113958ee",
        "op": "xor",
        "immediate": 0xF16A9D33,
        "count": 1147,
        "loader_rva": 0x14015460,
        "method_index": 696653,
        "key_offset": 0x28,
    },
    "SceneExcelConfigData": {
        "raw_sha": "970ffecdec5b1f9368b6db5c7c0129a9f0b9ba624f81d5289e3142572caebb8d",
        "payload_sha": "588563f62149d62038c7ee3b179e50191ecc9a3cfc003353e18a831918d27f6a",
        "op": "add",
        "immediate": 0xB8B21EBC,
        "count": 2377,
        "loader_rva": 0xA6C7000,
        "method_index": 279989,
        "key_offset": 0x50,
    },
}


def decode_source_header(raw: bytes, *, source: str) -> OriginalSceneTableHeader:
    """Verify both raw and payload hash before decoding a pinned native count.

    A generic/user-created stream with the same first four bytes must not be
    accepted as an independently verified original 7.1 resource.
    """
    if source not in SOURCES:
        raise SceneBin71Error(f"unknown pinned Global 7.1 Scene table: {source}")
    entry = SOURCES[source]
    raw_sha = hashlib.sha256(raw).hexdigest()
    if raw_sha != entry["raw_sha"]:
        raise SceneBin71Error(f"{source} raw export SHA-256 mismatch")
    try:
        payload = unwrap_mihoyo_bin_data(raw)
    except ValueError as exc:
        raise SceneBin71Error(f"{source} framing rejected: {exc}") from exc
    payload_sha = hashlib.sha256(payload).hexdigest()
    if payload_sha != entry["payload_sha"]:
        raise SceneBin71Error(f"{source} payload SHA-256 mismatch")
    if len(payload) < 4:
        raise SceneBin71Error("truncated native table header")
    word = struct.unpack_from("<I", payload, 0)[0]
    if entry["op"] == "xor":
        count = word ^ entry["immediate"]
    elif entry["op"] == "add":
        count = (word + entry["immediate"]) & U32
    else:
        raise SceneBin71Error("unrecognized pinned native count operation")
    if count != entry["count"]:
        raise SceneBin71Error(f"{source} unexpected native count {count}")
    return OriginalSceneTableHeader(
        source=source, raw_export_sha256=raw_sha, payload_sha256=payload_sha,
        raw_u32=word, operation=entry["op"], immediate=entry["immediate"],
        row_count=count, payload_bytes=len(payload),
    )
