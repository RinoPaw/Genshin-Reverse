from __future__ import annotations

from dataclasses import dataclass
import struct


class QuestContent71ParseError(ValueError):
    pass


MASK_ADD = 0x8F
KNOWN_MASK = (1 << 1) | (1 << 0) | (1 << 7) | (1 << 4)

STRING_LENGTH_ADD = 0x8555
STRING_BLOCK_XOR = 0xA4D839D96CBB8555
TYPE_XOR = 0xE9FA3068
TYPE_ADD = 0x31C7C23E
PARAM_COUNT_ADD = 0xC867B940
PARAM_ELEMENT_ADD = 0x78B6DDFA
UNKNOWN_SCALAR_XOR = 0x06723F87

ARRAY_COUNT_ADD = 0x9278C6C1
ARRAY_COUNT_XOR = 0x415C14AA


@dataclass(frozen=True)
class QuestContent71:
    start: int
    end: int
    mask_raw: int
    mask: int
    string_value: str | None
    content_type: int | None
    params: tuple[int, ...] | None
    unknown_scalar: int | None

    @property
    def size(self) -> int:
        return self.end - self.start


def _u16(data: bytes, pos: int, end: int, label: str) -> int:
    if pos < 0 or pos + 2 > end:
        raise QuestContent71ParseError(f"truncated {label} at 0x{pos:X}")
    return struct.unpack_from("<H", data, pos)[0]


def _u32(data: bytes, pos: int, end: int, label: str) -> int:
    if pos < 0 or pos + 4 > end:
        raise QuestContent71ParseError(f"truncated {label} at 0x{pos:X}")
    return struct.unpack_from("<I", data, pos)[0]


def _decode_xor_blocks(raw: bytes, key: int) -> bytes:
    out = bytearray()
    for pos in range(0, len(raw), 8):
        block = raw[pos:pos + 8]
        width = len(block)
        mask = (1 << (width * 8)) - 1
        value = int.from_bytes(block, "little") ^ (key & mask)
        out += value.to_bytes(width, "little")
    return bytes(out)


def _read_string(data: bytes, pos: int, end: int) -> tuple[str, int]:
    raw_length = _u16(data, pos, end, "QuestContent string length")
    length = (raw_length + STRING_LENGTH_ADD) & 0xFFFF
    pos += 2
    if length > end - pos:
        raise QuestContent71ParseError(
            f"QuestContent string length {length} exceeds remaining {end - pos} bytes"
        )
    decoded = _decode_xor_blocks(data[pos:pos + length], STRING_BLOCK_XOR)
    try:
        value = decoded.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise QuestContent71ParseError("QuestContent string is not valid UTF-8") from exc
    return value, pos + length


def parse_questcontent71(
    data: bytes,
    start: int,
    end: int,
) -> QuestContent71:
    if start < 0 or end > len(data) or start >= end:
        raise QuestContent71ParseError(
            f"invalid QuestContent71 range 0x{start:X}..0x{end:X}"
        )

    mask_raw = data[start]
    mask = (mask_raw + MASK_ADD) & 0xFF
    if mask & ~KNOWN_MASK:
        raise QuestContent71ParseError(
            f"QuestContent mask 0x{mask_raw:02X} decodes to unsupported 0x{mask:02X}"
        )
    p = start + 1

    string_value = None
    if (mask >> 1) & 1:
        string_value, p = _read_string(data, p, end)

    content_type = None
    if mask & 1:
        raw = _u32(data, p, end, "QuestContent type")
        content_type = ((raw ^ TYPE_XOR) + TYPE_ADD) & 0xFFFFFFFF
        p += 4

    params = None
    if (mask >> 7) & 1:
        raw_count = _u32(data, p, end, "QuestContent params count")
        count = (raw_count + PARAM_COUNT_ADD) & 0xFFFFFFFF
        p += 4
        if count > 64:
            raise QuestContent71ParseError(
                f"implausible QuestContent params count {count}"
            )
        if p + count * 4 > end:
            raise QuestContent71ParseError("truncated QuestContent params")
        values = []
        for _ in range(count):
            raw = _u32(data, p, end, "QuestContent param")
            values.append((raw + PARAM_ELEMENT_ADD) & 0xFFFFFFFF)
            p += 4
        params = tuple(values)

    unknown_scalar = None
    if (mask >> 4) & 1:
        unknown_scalar = _u32(data, p, end, "QuestContent scalar") ^ UNKNOWN_SCALAR_XOR
        p += 4

    return QuestContent71(
        start=start,
        end=p,
        mask_raw=mask_raw,
        mask=mask,
        string_value=string_value,
        content_type=content_type,
        params=params,
        unknown_scalar=unknown_scalar,
    )


def parse_questcontent71_array(
    data: bytes,
    start: int,
    end: int,
) -> tuple[tuple[QuestContent71, ...], int]:
    raw_count = _u32(data, start, end, "QuestContent array count")
    count = ((raw_count + ARRAY_COUNT_ADD) & 0xFFFFFFFF) ^ ARRAY_COUNT_XOR
    if count > 4096:
        raise QuestContent71ParseError(
            f"implausible QuestContent array count {count}"
        )
    p = start + 4
    values = []
    for _ in range(count):
        item = parse_questcontent71(data, p, end)
        values.append(item)
        p = item.end
    return tuple(values), p
