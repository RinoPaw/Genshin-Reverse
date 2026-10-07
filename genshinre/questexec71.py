from __future__ import annotations

from dataclasses import dataclass
import struct


class QuestExec71ParseError(ValueError):
    pass


MASK_ADD = 0x44
KNOWN_MASK = (1 << 5) | (1 << 2)

PARAM_COUNT_ADD = 0x8DAF6E6F
PARAM_COUNT_XOR = 0x745258F8
PARAM_LENGTH_XOR = 0xDEA7
PARAM_BLOCK_ADD = 0x0B61F31AFE80DEA7
TYPE_ADD = 0x203BCD7F

ARRAY_COUNT_ADD = 0xB0F7C9F4


@dataclass(frozen=True)
class QuestExec71:
    start: int
    end: int
    mask_raw: int
    mask: int
    params: tuple[str, ...] | None
    exec_type: int | None

    @property
    def size(self) -> int:
        return self.end - self.start


def _u16(data: bytes, pos: int, end: int, label: str) -> int:
    if pos < 0 or pos + 2 > end:
        raise QuestExec71ParseError(f"truncated {label} at 0x{pos:X}")
    return struct.unpack_from("<H", data, pos)[0]


def _u32(data: bytes, pos: int, end: int, label: str) -> int:
    if pos < 0 or pos + 4 > end:
        raise QuestExec71ParseError(f"truncated {label} at 0x{pos:X}")
    return struct.unpack_from("<I", data, pos)[0]


def _decode_additive_blocks(raw: bytes, key: int) -> bytes:
    out = bytearray()
    for pos in range(0, len(raw), 8):
        block = raw[pos:pos + 8]
        width = len(block)
        mask = (1 << (width * 8)) - 1
        value = (
            int.from_bytes(block, "little")
            + (key & mask)
        ) & mask
        out += value.to_bytes(width, "little")
    return bytes(out)


def _read_param(data: bytes, pos: int, end: int) -> tuple[str, int]:
    raw_length = _u16(data, pos, end, "QuestExec param length")
    length = raw_length ^ PARAM_LENGTH_XOR
    pos += 2
    if length > end - pos:
        raise QuestExec71ParseError(
            f"QuestExec param length {length} exceeds remaining {end - pos} bytes"
        )
    decoded = _decode_additive_blocks(data[pos:pos + length], PARAM_BLOCK_ADD)
    try:
        value = decoded.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise QuestExec71ParseError("QuestExec param is not valid UTF-8") from exc
    return value, pos + length


def parse_questexec71(
    data: bytes,
    start: int,
    end: int,
) -> QuestExec71:
    if start < 0 or end > len(data) or start >= end:
        raise QuestExec71ParseError(
            f"invalid QuestExec71 range 0x{start:X}..0x{end:X}"
        )

    mask_raw = data[start]
    mask = (mask_raw + MASK_ADD) & 0xFF
    if mask & ~KNOWN_MASK:
        raise QuestExec71ParseError(
            f"QuestExec mask 0x{mask_raw:02X} decodes to unsupported 0x{mask:02X}"
        )
    p = start + 1

    params = None
    if (mask >> 5) & 1:
        raw_count = _u32(data, p, end, "QuestExec params count")
        count = (
            ((raw_count + PARAM_COUNT_ADD) & 0xFFFFFFFF)
            ^ PARAM_COUNT_XOR
        )
        p += 4
        if count > 64:
            raise QuestExec71ParseError(
                f"implausible QuestExec params count {count}"
            )
        values = []
        for _ in range(count):
            value, p = _read_param(data, p, end)
            values.append(value)
        params = tuple(values)

    exec_type = None
    if (mask >> 2) & 1:
        raw = _u32(data, p, end, "QuestExec type")
        exec_type = (raw + TYPE_ADD) & 0xFFFFFFFF
        p += 4

    return QuestExec71(
        start=start,
        end=p,
        mask_raw=mask_raw,
        mask=mask,
        params=params,
        exec_type=exec_type,
    )


def parse_questexec71_array(
    data: bytes,
    start: int,
    end: int,
) -> tuple[tuple[QuestExec71, ...], int]:
    raw_count = _u32(data, start, end, "QuestExec array count")
    count = (raw_count + ARRAY_COUNT_ADD) & 0xFFFFFFFF
    if count > 4096:
        raise QuestExec71ParseError(
            f"implausible QuestExec array count {count}"
        )
    p = start + 4
    values = []
    for _ in range(count):
        item = parse_questexec71(data, p, end)
        values.append(item)
        p = item.end
    return tuple(values), p
