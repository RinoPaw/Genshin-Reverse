from __future__ import annotations

from dataclasses import dataclass
import struct


class QuestGuideHint71ParseError(ValueError):
    pass


MASK_XOR = 0x8398
MASK_ADD = 0xEF60
KNOWN_FIELD_MASK = 0x002A

BIT_PARAM2 = 5
BIT_TYPE = 3
BIT_PARAM1 = 1

PARAM2_LENGTH_ADD = 0xA9C8
PARAM2_BLOCK_XOR = 0xEBDAE9F0CF05A9C8
TYPE_XOR = 0x4B04493B
TYPE_ADD = 0x2ED35D71
PARAM1_LENGTH_XOR = 0x65D5
PARAM1_BLOCK_ADD = 0x1F52804CD4D865D5


@dataclass(frozen=True)
class QuestGuideHint71:
    start: int
    end: int
    mask_raw: int
    mask: int
    param2: str | None
    guide_type: int | None
    param1: str | None

    @property
    def size(self) -> int:
        return self.end - self.start


def _u16(data: bytes, pos: int, end: int, label: str) -> int:
    if pos < 0 or pos + 2 > end:
        raise QuestGuideHint71ParseError(f"truncated {label} at 0x{pos:X}")
    return struct.unpack_from("<H", data, pos)[0]


def _u32(data: bytes, pos: int, end: int, label: str) -> int:
    if pos < 0 or pos + 4 > end:
        raise QuestGuideHint71ParseError(f"truncated {label} at 0x{pos:X}")
    return struct.unpack_from("<I", data, pos)[0]


def _decode_blocks(raw: bytes, key: int, *, xor: bool) -> bytes:
    out = bytearray()
    for pos in range(0, len(raw), 8):
        block = raw[pos:pos + 8]
        width = len(block)
        mask = (1 << (width * 8)) - 1
        encoded = int.from_bytes(block, "little")
        if xor:
            decoded = encoded ^ (key & mask)
        else:
            decoded = (encoded + (key & mask)) & mask
        out += decoded.to_bytes(width, "little")
    return bytes(out)


def _read_string(
    data: bytes,
    pos: int,
    end: int,
    *,
    length_decode,
    block_key: int,
    block_xor: bool,
    label: str,
) -> tuple[str, int]:
    raw_length = _u16(data, pos, end, f"{label} length")
    length = length_decode(raw_length) & 0xFFFF
    pos += 2
    if length > end - pos:
        raise QuestGuideHint71ParseError(
            f"{label} length {length} exceeds remaining {end - pos} bytes"
        )
    decoded = _decode_blocks(
        data[pos:pos + length],
        block_key,
        xor=block_xor,
    )
    try:
        value = decoded.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise QuestGuideHint71ParseError(f"{label} is not valid UTF-8") from exc
    return value, pos + length


def parse_questguidehint71(
    data: bytes,
    start: int,
    end: int,
) -> QuestGuideHint71:
    if start < 0 or end > len(data) or start + 2 > end:
        raise QuestGuideHint71ParseError(
            f"invalid QuestGuideHint71 range 0x{start:X}..0x{end:X}"
        )

    mask_raw = _u16(data, start, end, "guideHint mask")
    mask = ((mask_raw ^ MASK_XOR) + MASK_ADD) & 0xFFFF
    if mask & ~KNOWN_FIELD_MASK:
        raise QuestGuideHint71ParseError(
            f"guideHint mask 0x{mask_raw:04X} decodes to unsupported 0x{mask:04X}"
        )
    p = start + 2

    param2 = None
    if (mask >> BIT_PARAM2) & 1:
        param2, p = _read_string(
            data,
            p,
            end,
            length_decode=lambda raw: raw + PARAM2_LENGTH_ADD,
            block_key=PARAM2_BLOCK_XOR,
            block_xor=True,
            label="guideHint param2",
        )

    guide_type = None
    if (mask >> BIT_TYPE) & 1:
        raw_type = _u32(data, p, end, "guideHint type")
        guide_type = ((raw_type ^ TYPE_XOR) + TYPE_ADD) & 0xFFFFFFFF
        p += 4

    param1 = None
    if (mask >> BIT_PARAM1) & 1:
        param1, p = _read_string(
            data,
            p,
            end,
            length_decode=lambda raw: raw ^ PARAM1_LENGTH_XOR,
            block_key=PARAM1_BLOCK_ADD,
            block_xor=False,
            label="guideHint param1",
        )

    return QuestGuideHint71(
        start=start,
        end=p,
        mask_raw=mask_raw,
        mask=mask,
        param2=param2,
        guide_type=guide_type,
        param1=param1,
    )
