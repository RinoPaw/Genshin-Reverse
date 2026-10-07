from __future__ import annotations

from dataclasses import dataclass
import struct


class QuestCond71ParseError(ValueError):
    pass


MASK_SUB = 0x4B4B
MASK_XOR = 0xA59E
KNOWN_MASK = (1 << 3) | (1 << 0)

PARAM_COUNT_XOR = 0x353F27DA
PARAM_COUNT_ADD = 0x001A3D64
PARAM_ELEMENT_ADD = 0xD1D38FBA
PARAM_ELEMENT_XOR = 0x97EB1C88
TYPE_ADD = 0x9BD9087A

ARRAY_COUNT_XOR = 0x9D096542
ARRAY_COUNT_ADD = 0x73F5D5DA


@dataclass(frozen=True)
class QuestCond71:
    start: int
    end: int
    mask_raw: int
    mask: int
    params: tuple[int, ...] | None
    cond_type: int | None

    @property
    def size(self) -> int:
        return self.end - self.start


def _u16(data: bytes, pos: int, end: int, label: str) -> int:
    if pos < 0 or pos + 2 > end:
        raise QuestCond71ParseError(f"truncated {label} at 0x{pos:X}")
    return struct.unpack_from("<H", data, pos)[0]


def _u32(data: bytes, pos: int, end: int, label: str) -> int:
    if pos < 0 or pos + 4 > end:
        raise QuestCond71ParseError(f"truncated {label} at 0x{pos:X}")
    return struct.unpack_from("<I", data, pos)[0]


def parse_questcond71(
    data: bytes,
    start: int,
    end: int,
) -> QuestCond71:
    if start < 0 or end > len(data) or start + 2 > end:
        raise QuestCond71ParseError(
            f"invalid QuestCond71 range 0x{start:X}..0x{end:X}"
        )

    mask_raw = _u16(data, start, end, "QuestCond mask")
    mask = (((mask_raw - MASK_SUB) & 0xFFFF) ^ MASK_XOR) & 0xFFFF
    if mask & ~KNOWN_MASK:
        raise QuestCond71ParseError(
            f"QuestCond mask 0x{mask_raw:04X} decodes to unsupported 0x{mask:04X}"
        )
    p = start + 2

    params = None
    if (mask >> 3) & 1:
        raw_count = _u32(data, p, end, "QuestCond params count")
        count = (
            (raw_count ^ PARAM_COUNT_XOR) + PARAM_COUNT_ADD
        ) & 0xFFFFFFFF
        p += 4
        if count > 64:
            raise QuestCond71ParseError(
                f"implausible QuestCond params count {count}"
            )
        if p + count * 4 > end:
            raise QuestCond71ParseError("truncated QuestCond params")
        values = []
        for _ in range(count):
            raw = _u32(data, p, end, "QuestCond param")
            value = (
                ((raw + PARAM_ELEMENT_ADD) & 0xFFFFFFFF)
                ^ PARAM_ELEMENT_XOR
            )
            values.append(value)
            p += 4
        params = tuple(values)

    cond_type = None
    if mask & 1:
        raw = _u32(data, p, end, "QuestCond type")
        cond_type = (raw + TYPE_ADD) & 0xFFFFFFFF
        p += 4

    return QuestCond71(
        start=start,
        end=p,
        mask_raw=mask_raw,
        mask=mask,
        params=params,
        cond_type=cond_type,
    )


def parse_questcond71_array(
    data: bytes,
    start: int,
    end: int,
) -> tuple[tuple[QuestCond71, ...], int]:
    raw_count = _u32(data, start, end, "QuestCond array count")
    count = (
        (raw_count ^ ARRAY_COUNT_XOR) + ARRAY_COUNT_ADD
    ) & 0xFFFFFFFF
    if count > 4096:
        raise QuestCond71ParseError(
            f"implausible QuestCond array count {count}"
        )
    p = start + 4
    values = []
    for _ in range(count):
        item = parse_questcond71(data, p, end)
        values.append(item)
        p = item.end
    return tuple(values), p
