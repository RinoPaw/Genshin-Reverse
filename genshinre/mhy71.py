from __future__ import annotations

import csv
import hashlib
import json
import mmap
import struct
from array import array
from collections.abc import Callable
from pathlib import Path

from .metadata import build_type_methods
from .param71 import PARAMETER_RECORD_SIZE, decode_parameter_record
from .pe import PEImage

MASK32 = 0xFFFFFFFF
MASK64 = 0xFFFFFFFFFFFFFFFF

EXPECTED_EXE_SHA256 = "08a3086d5f3fe695f01dab61efa42e442006b18e5e475b2520df356f6a073b7d"
EXPECTED_METADATA_SHA256 = "05ae04d7a91b91cc880217a56b0b01f3e67f845b06e894216654ec5d160e0da0"
EXPECTED_TYPE_COUNT = 88_904
EXPECTED_FIELD_COUNT = 440_172
EXPECTED_METHOD_COUNT = 733_442

BODY_SKIP = 0x210
EMBEDDED_HEADER_RVA = 0x027D4BD0
EMBEDDED_HEADER_SIZE = 0x210
TYPE_ARRAY_POINTER_RVA = 0x02870A88 + 0x48
METHOD_POINTER_TABLE_RVA = 0x02870B90

PRIMITIVE_KINDS = {
    0x01: "void",
    0x02: "bool",
    0x03: "char",
    0x04: "int8",
    0x05: "uint8",
    0x06: "int16",
    0x07: "uint16",
    0x08: "int32",
    0x09: "uint32",
    0x0A: "int64",
    0x0B: "uint64",
    0x0C: "float32",
    0x0D: "float64",
    0x0E: "string",
    0x18: "native_int",
    0x19: "native_uint",
    0x1C: "object",
}

TYPE_COLUMNS = (
    "type_definition_index",
    "namespace",
    "type_name",
    "parent_type",
    "field_start",
    "field_count",
    "method_start",
    "method_count",
    "type_cache_rva",
    "name_token",
    "namespace_token",
    "record_file_offset",
    "status",
    "evidence",
)
FIELD_COLUMNS = (
    "field_index",
    "type_definition_index",
    "type_name",
    "field_name",
    "field_type",
    "field_type_index",
    "name_token",
    "offset",
    "record_file_offset",
    "status",
    "evidence",
)
METHOD_COLUMNS = (
    "method_index",
    "type_definition_index",
    "type_name",
    "method_name",
    "rva",
    "return_type",
    "parameter_types",
    "parameter_type_indices",
    "parameter_start",
    "parameter_count",
    "name_token",
    "record_file_offset",
    "status",
    "evidence",
)
METHOD_POINTER_COLUMNS = (
    "method_index",
    "rva",
    "va",
    "status",
    "evidence",
)


def _u16(data: bytes | mmap.mmap, offset: int = 0) -> int:
    return struct.unpack_from("<H", data, offset)[0]


def _u32(data: bytes | mmap.mmap, offset: int = 0) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def _u64(data: bytes | mmap.mmap, offset: int = 0) -> int:
    return struct.unpack_from("<Q", data, offset)[0]


def _signed32(value: int) -> int:
    value &= MASK32
    return value if value < 0x80000000 else value - 0x100000000


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(8 * 1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def decode_type_record(record: bytes) -> dict[str, int]:
    if len(record) < 70:
        raise ValueError("truncated 7.1 type-definition record")
    return {
        "namespace_token": (_u32(record, 0x00) + 0xBBB4CF40) & MASK32,
        "method_start": _signed32(_u32(record, 0x0C) ^ 0x4D8127F2),
        "field_start": _signed32(_u32(record, 0x1C) ^ 0x29010897),
        "name_token": (_u32(record, 0x24) + 0xFBAD8E98) & MASK32,
        "method_count": (_u16(record, 0x30) + 0x12C6) & 0xFFFF,
        "field_count": _u16(record, 0x38) ^ 0x51A8,
    }


def _field_key(index: int) -> int:
    # Exact recovered Python arithmetic: mask the 64-bit product, then shift.
    product = ((((index * 0x87DE) ^ 0x59B1DB19) * 0x6CB83B74) & MASK64)
    return ((product >> 16) + 0x540C1A0D) & MASK32


def decode_field_record(record: bytes, index: int) -> dict[str, int]:
    if len(record) < 8:
        raise ValueError("truncated 7.1 field record")
    key = _field_key(index)
    return {
        "type_index": (_u32(record, 0x00) ^ key ^ 0x2D27D873) & MASK32,
        "name_token": (((_u32(record, 0x04) + 0xA810CEF4) & MASK32) ^ key ^ 0x2D027B84) & MASK32,
    }


def _method_key(index: int) -> int:
    return (((index * 0x3348BF73) ^ 0x73758947) + 0x5C439E5B) & MASK32


def decode_method_record(record: bytes, index: int) -> dict[str, int]:
    if len(record) < 26:
        raise ValueError("truncated 7.1 method record")
    key = _method_key(index)
    return {
        "name_token": (((_u32(record, 0x00) + 0xA52959D7) & MASK32) ^ key) & MASK32,
        "parameter_start": _signed32(((_u32(record, 0x04) + 0xF0A05526) & MASK32) ^ key),
        "declaring_type_index": (_u32(record, 0x0C) ^ key ^ 0x59244785) & MASK32,
        "parameter_count": ((record[0x18] + 0xE1) ^ key) & 0xFF,
    }


def decode_string_token(metadata: mmap.mmap | bytes, string_base: int, token: int) -> str:
    length = (token >> 24) & 0xFF
    index = token & 0xFFFFFF
    if length == 0:
        return ""
    key = (
        ((((index * 0x694418957C890198) & MASK64) ^ 0x55A357D81EF0E48B) * 0x5C2B4E660E2D0544)
        & MASK64
    )
    chunks = bytearray()
    chunk_count = (length + 7) // 8
    for chunk_index in range(chunk_count):
        offset = string_base + index + chunk_index * 8
        if offset + 8 > len(metadata):
            raise ValueError(f"string token 0x{token:08X} points outside metadata")
        encrypted = _u64(metadata, offset)
        stream = (key + chunk_index * 0x6B0B40C349AE61E5) & MASK64
        chunks.extend(struct.pack("<Q", encrypted ^ stream))
    return bytes(chunks[:length]).decode("utf-8", errors="replace")


def _header_layout(header: bytes) -> dict[str, int]:
    if len(header) != EMBEDDED_HEADER_SIZE:
        raise ValueError("invalid embedded 7.1 metadata header size")
    return {
        "type_offset": (_u32(header, 0xB4) + 0xEC48AB9F) & MASK32,
        "type_count": (((_u32(header, 0xE0) + 0xE2F9B07D) & MASK32) // 70),
        "parameter_offset": _u32(header, 0x114) ^ 0x3E5D33E6,
        "method_offset": (_u32(header, 0x16C) + 0xE33589AC) & MASK32,
        "string_offset": (_u32(header, 0x184) + 0xBF9D4735) & MASK32,
        "field_offset": (_u32(header, 0x18C) + 0xEBF0392C) & MASK32,
    }


def _write_csv(path: Path, columns: tuple[str, ...], rows) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=columns)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def _owner_array(count: int, types: list[dict[str, object]], start_key: str, count_key: str) -> array:
    owners = array("i", [-1]) * count
    for item in types:
        start = int(item[start_key])
        span = int(item[count_key])
        if start < 0 or span <= 0 or start >= count:
            continue
        end = min(start + span, count)
        owners[start:end] = array("i", [int(item["type_definition_index"])]) * (end - start)
    return owners


def _decode_parameter_span(
    metadata: mmap.mmap | bytes,
    parameter_base: int,
    parameter_start: int,
    parameter_count: int,
    resolve_type: Callable[[int], str],
) -> tuple[list[int], list[str]]:
    type_indices: list[int] = []
    type_names: list[str] = []
    if parameter_start < 0 or parameter_count <= 0:
        return type_indices, type_names

    for ordinal in range(parameter_count):
        index = parameter_start + ordinal
        offset = parameter_base + index * PARAMETER_RECORD_SIZE
        end = offset + PARAMETER_RECORD_SIZE
        if offset < 0 or end > len(metadata):
            raise ValueError(f"parameter record {index} exceeds metadata")
        decoded = decode_parameter_record(metadata[offset:end], index)
        type_index = int(decoded["type_index"])
        type_indices.append(type_index)
        type_names.append(resolve_type(type_index))
    return type_indices, type_names


def decode_metadata_71(
    exe: Path,
    metadata_path: Path,
    output_dir: Path,
    allow_unknown_sample: bool = False,
) -> dict[str, object]:
    exe_sha = _sha256(exe)
    metadata_sha = _sha256(metadata_path)
    if not allow_unknown_sample:
        if exe_sha != EXPECTED_EXE_SHA256:
            raise ValueError(f"unexpected GenshinImpact.exe SHA-256: {exe_sha}")
        if metadata_sha != EXPECTED_METADATA_SHA256:
            raise ValueError(f"unexpected global-metadata.dat SHA-256: {metadata_sha}")

    output_dir.mkdir(parents=True, exist_ok=True)
    warnings: list[str] = []

    with PEImage(exe) as image, metadata_path.open("rb") as metadata_file:
        metadata = mmap.mmap(metadata_file.fileno(), 0, access=mmap.ACCESS_READ)
        try:
            if metadata[:4] != b"MHY\0":
                raise ValueError("metadata does not start with MHY\\0")
            header = image.read_rva(EMBEDDED_HEADER_RVA, EMBEDDED_HEADER_SIZE)
            layout = _header_layout(header)
            if layout["type_count"] != EXPECTED_TYPE_COUNT:
                message = f"decoded type count {layout['type_count']} != preserved {EXPECTED_TYPE_COUNT}"
                if allow_unknown_sample:
                    warnings.append(message)
                else:
                    raise ValueError(message)

            type_base = BODY_SKIP + layout["type_offset"]
            field_base = BODY_SKIP + layout["field_offset"]
            method_base = BODY_SKIP + layout["method_offset"]
            parameter_base = BODY_SKIP + layout["parameter_offset"]
            string_base = BODY_SKIP + layout["string_offset"]

            types: list[dict[str, object]] = []
            type_names: dict[int, str] = {}
            for index in range(layout["type_count"]):
                record_offset = type_base + index * 70
                if record_offset + 70 > len(metadata):
                    raise ValueError(f"type record {index} exceeds metadata")
                decoded = decode_type_record(metadata[record_offset : record_offset + 70])
                name = decode_string_token(metadata, string_base, decoded["name_token"])
                namespace = decode_string_token(metadata, string_base, decoded["namespace_token"])
                item: dict[str, object] = {
                    "type_definition_index": index,
                    "namespace": namespace,
                    "type_name": name,
                    "parent_type": "",
                    "field_start": decoded["field_start"],
                    "field_count": decoded["field_count"],
                    "method_start": decoded["method_start"],
                    "method_count": decoded["method_count"],
                    "type_cache_rva": "",
                    "name_token": f"0x{decoded['name_token']:08X}",
                    "namespace_token": f"0x{decoded['namespace_token']:08X}",
                    "record_file_offset": f"0x{record_offset:X}",
                    "status": "static-decoded",
                    "evidence": "native 7.1 MHY metadata decoder",
                }
                types.append(item)
                type_names[index] = name

            field_count = max(
                (int(item["field_start"]) + int(item["field_count"]) for item in types if int(item["field_start"]) >= 0),
                default=0,
            )
            method_count = max(
                (int(item["method_start"]) + int(item["method_count"]) for item in types if int(item["method_start"]) >= 0),
                default=0,
            )
            for label, actual, expected in (
                ("field", field_count, EXPECTED_FIELD_COUNT),
                ("method", method_count, EXPECTED_METHOD_COUNT),
            ):
                if actual != expected:
                    message = f"decoded {label} count {actual} != preserved {expected}"
                    if allow_unknown_sample:
                        warnings.append(message)
                    else:
                        raise ValueError(message)

            field_owners = _owner_array(field_count, types, "field_start", "field_count")
            method_owners = _owner_array(method_count, types, "method_start", "method_count")

            type_array_pointer = image.read_rva(TYPE_ARRAY_POINTER_RVA, 8)
            if len(type_array_pointer) < 8:
                raise ValueError("cannot read IL2CPP type-array pointer")
            type_array_va = _u64(type_array_pointer)
            type_array_rva = type_array_va - image.image_base
            if type_array_rva <= 0:
                raise ValueError("invalid IL2CPP type-array pointer")
            type_cache: dict[int, str] = {}

            def resolve_il2cpp_type(type_index: int) -> str:
                cached = type_cache.get(type_index)
                if cached is not None:
                    return cached
                entry = image.read_rva(type_array_rva + type_index * 16, 16)
                if len(entry) < 16:
                    value = f"type_index:{type_index}"
                else:
                    kind = entry[0x0A]
                    if kind in (0x11, 0x12):
                        definition = _u32(entry, 0)
                        value = type_names.get(definition, f"typeDefinition:{definition}")
                    else:
                        value = PRIMITIVE_KINDS.get(kind, f"kind_0x{kind:02X}")
                type_cache[type_index] = value
                return value

            _write_csv(output_dir / "types.csv", TYPE_COLUMNS, types)

            def field_rows():
                for index in range(field_count):
                    record_offset = field_base + index * 8
                    if record_offset + 8 > len(metadata):
                        raise ValueError(f"field record {index} exceeds metadata")
                    decoded = decode_field_record(metadata[record_offset : record_offset + 8], index)
                    owner = field_owners[index]
                    yield {
                        "field_index": index,
                        "type_definition_index": "" if owner < 0 else owner,
                        "type_name": "" if owner < 0 else type_names.get(owner, ""),
                        "field_name": decode_string_token(metadata, string_base, decoded["name_token"]),
                        "field_type": resolve_il2cpp_type(decoded["type_index"]),
                        "field_type_index": decoded["type_index"],
                        "name_token": f"0x{decoded['name_token']:08X}",
                        "offset": "",
                        "record_file_offset": f"0x{record_offset:X}",
                        "status": "static-decoded",
                        "evidence": "native 7.1 MHY metadata decoder",
                    }

            _write_csv(output_dir / "fields.csv", FIELD_COLUMNS, field_rows())

            pointer_blob = image.read_rva(METHOD_POINTER_TABLE_RVA, method_count * 8)
            if len(pointer_blob) < method_count * 8:
                raise ValueError("method-pointer table is truncated")
            owner_mismatches = 0
            decoded_parameter_count = 0

            def method_rows():
                nonlocal owner_mismatches, decoded_parameter_count
                for index in range(method_count):
                    record_offset = method_base + index * 26
                    if record_offset + 26 > len(metadata):
                        raise ValueError(f"method record {index} exceeds metadata")
                    decoded = decode_method_record(metadata[record_offset : record_offset + 26], index)
                    range_owner = method_owners[index]
                    declared_owner = decoded["declaring_type_index"]
                    if range_owner >= 0 and declared_owner != range_owner:
                        owner_mismatches += 1
                    pointer_va = _u64(pointer_blob, index * 8)
                    rva = pointer_va - image.image_base if pointer_va else 0
                    parameter_type_indices, parameter_types = _decode_parameter_span(
                        metadata,
                        parameter_base,
                        decoded["parameter_start"],
                        decoded["parameter_count"],
                        resolve_il2cpp_type,
                    )
                    decoded_parameter_count += len(parameter_type_indices)
                    yield {
                        "method_index": index,
                        "type_definition_index": declared_owner,
                        "type_name": type_names.get(declared_owner, ""),
                        "method_name": decode_string_token(metadata, string_base, decoded["name_token"]),
                        "rva": "" if rva <= 0 else f"0x{rva:X}",
                        "return_type": "",
                        "parameter_types": json.dumps(parameter_types, ensure_ascii=False, separators=(",", ":")),
                        "parameter_type_indices": json.dumps(parameter_type_indices, separators=(",", ":")),
                        "parameter_start": decoded["parameter_start"],
                        "parameter_count": decoded["parameter_count"],
                        "name_token": f"0x{decoded['name_token']:08X}",
                        "record_file_offset": f"0x{record_offset:X}",
                        "status": "static-decoded",
                        "evidence": "native 7.1 MHY metadata decoder; parameter records decoded",
                    }

            _write_csv(output_dir / "methods.csv", METHOD_COLUMNS, method_rows())

            def pointer_rows():
                for index in range(method_count):
                    va = _u64(pointer_blob, index * 8)
                    rva = va - image.image_base if va else 0
                    yield {
                        "method_index": index,
                        "rva": "" if rva <= 0 else f"0x{rva:X}",
                        "va": "" if va == 0 else f"0x{va:X}",
                        "status": "static-decoded",
                        "evidence": "7.1 IL2CPP method-pointer table",
                    }

            _write_csv(output_dir / "method-pointers.csv", METHOD_POINTER_COLUMNS, pointer_rows())
        finally:
            metadata.close()

    build_type_methods(output_dir / "methods.csv", output_dir / "type-methods.json")
    summary: dict[str, object] = {
        "decoder": "native-mhy71",
        "sample": {
            "exe_sha256": exe_sha,
            "metadata_sha256": metadata_sha,
        },
        "layout": {key: f"0x{value:X}" if key.endswith("_offset") else value for key, value in layout.items()},
        "counts": {
            "types": len(types),
            "fields": field_count,
            "methods": method_count,
            "parameters": decoded_parameter_count,
        },
        "type_array_rva": f"0x{type_array_rva:X}",
        "method_pointer_table_rva": f"0x{METHOD_POINTER_TABLE_RVA:X}",
        "parameter_base_file_offset": f"0x{parameter_base:X}",
        "parameter_record_size": PARAMETER_RECORD_SIZE,
        "method_owner_range_mismatches": owner_mismatches,
        "parameter_records_decoded": True,
        "warnings": warnings,
        "provenance": {
            "embedded_header_rva": f"0x{EMBEDDED_HEADER_RVA:X}",
            "metadata_body_skip": f"0x{BODY_SKIP:X}",
            "formula_source": (
                "preserved 7.1 static-analysis formulas plus native parameter decoder "
                "basic block at RVA 0x52881C..0x528867"
            ),
        },
    }
    (output_dir / "native-decoder-summary.json").write_text(
        json.dumps(summary, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    return summary