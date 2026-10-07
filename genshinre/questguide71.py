from __future__ import annotations

from dataclasses import dataclass
import struct


class QuestGuide71ParseError(ValueError):
    pass


MASK_XOR = 0x4DB0C843
VARIABLE_MASK = 0xF3CCA45E
FIXED_MASK = 0x0C335BA1
FIXED_VALUE = 0x0C304801

STRING0_LENGTH_XOR = 0x0188
STRING0_BLOCK_ADD = 0x05339EDBCEF50188
STRING1_LENGTH_XOR = 0xA344
STRING1_BLOCK_ADD = 0xDB3418F273A3A344
PARAM_COUNT_ADD = 0x6E3734D8
PARAM_LENGTH_XOR = 0x3E11
PARAM_BLOCK_ADD = 0xFE73512F02263E11


@dataclass(frozen=True)
class QuestGuide71:
    start: int
    end: int
    mask_raw: int
    unknown_string_10: str | None
    params: tuple[str, ...] | None
    unknown_string_20: str | None
    in_scene_style: int | None
    unknown_scalar_2c: int | None
    auto_guide: int | None
    guide_scene: int | None
    indicator_style: int | None
    resident_guide_type: int | None
    unknown_scalar_40: int | None
    unknown_scalar_44: int | None
    guide_layer: int | None
    poi_point_id: int | None
    guide_style: int | None
    area_style: int | None
    poi_region_id: int | None
    unknown_scalar_5c: int | None
    guide_type: int | None

    @property
    def size(self) -> int:
        return self.end - self.start


def _u16(data: bytes, pos: int, end: int, label: str) -> int:
    if pos < 0 or pos + 2 > end:
        raise QuestGuide71ParseError(f"truncated {label} at 0x{pos:X}")
    return struct.unpack_from("<H", data, pos)[0]


def _u32(data: bytes, pos: int, end: int, label: str) -> int:
    if pos < 0 or pos + 4 > end:
        raise QuestGuide71ParseError(f"truncated {label} at 0x{pos:X}")
    return struct.unpack_from("<I", data, pos)[0]


def _present(mask_raw: int, bit: int, *, decoded_mask: bool = False) -> bool:
    mask = mask_raw ^ MASK_XOR if decoded_mask else mask_raw
    return bool((mask >> bit) & 1)


def _decode_additive_blocks(raw: bytes, add_key: int) -> bytes:
    out = bytearray()
    for pos in range(0, len(raw), 8):
        block = raw[pos:pos + 8]
        width = len(block)
        bits = width * 8
        mask = (1 << bits) - 1
        encoded = int.from_bytes(block, "little")
        decoded = (encoded + (add_key & mask)) & mask
        out += decoded.to_bytes(width, "little")
    return bytes(out)


def _read_string(
    data: bytes,
    pos: int,
    end: int,
    *,
    length_xor: int,
    block_add: int,
    label: str,
) -> tuple[str, int]:
    length = _u16(data, pos, end, f"{label} length") ^ length_xor
    pos += 2
    if length > end - pos:
        raise QuestGuide71ParseError(
            f"{label} length {length} exceeds remaining {end - pos} bytes"
        )
    raw = data[pos:pos + length]
    decoded = _decode_additive_blocks(raw, block_add)
    try:
        value = decoded.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise QuestGuide71ParseError(f"{label} is not valid UTF-8") from exc
    return value, pos + length


def _read_params(data: bytes, pos: int, end: int) -> tuple[tuple[str, ...], int]:
    raw_count = _u32(data, pos, end, "guide params count")
    count = (raw_count + PARAM_COUNT_ADD) & 0xFFFFFFFF
    pos += 4
    if count > 64:
        raise QuestGuide71ParseError(f"implausible guide params count {count}")

    values = []
    for index in range(count):
        value, pos = _read_string(
            data,
            pos,
            end,
            length_xor=PARAM_LENGTH_XOR,
            block_add=PARAM_BLOCK_ADD,
            label=f"guide params[{index}]",
        )
        values.append(value)
    return tuple(values), pos


def parse_questguide71(data: bytes, start: int, end: int) -> QuestGuide71:
    if start < 0 or end > len(data) or start + 4 > end:
        raise QuestGuide71ParseError(
            f"invalid QuestGuide71 range 0x{start:X}..0x{end:X}"
        )

    mask_raw = _u32(data, start, end, "guide mask")
    if mask_raw & FIXED_MASK != FIXED_VALUE:
        raise QuestGuide71ParseError(
            f"guide mask 0x{mask_raw:08X} violates fixed-bit invariant"
        )

    p = start + 4

    unknown_string_10 = None
    if _present(mask_raw, 6, decoded_mask=True):
        unknown_string_10, p = _read_string(
            data,
            p,
            end,
            length_xor=STRING0_LENGTH_XOR,
            block_add=STRING0_BLOCK_ADD,
            label="guide string +0x10",
        )

    in_scene_style = None
    if _present(mask_raw, 1, decoded_mask=True):
        raw = _u32(data, p, end, "guide in-scene style")
        in_scene_style = ((raw + 0xE9F48C83) & 0xFFFFFFFF) ^ 0xAB75C25D
        p += 4

    area_style = None
    if _present(mask_raw, 2):
        raw = _u32(data, p, end, "guide area style")
        area_style = ((raw + 0xA3111AD6) & 0xFFFFFFFF) ^ 0xD02AF3CF
        p += 4

    unknown_scalar_44 = None
    if _present(mask_raw, 29):
        raw = _u32(data, p, end, "guide scalar +0x44")
        unknown_scalar_44 = (raw + 0x9A458AD0) & 0xFFFFFFFF
        p += 4

    unknown_string_20 = None
    if _present(mask_raw, 31):
        unknown_string_20, p = _read_string(
            data,
            p,
            end,
            length_xor=STRING1_LENGTH_XOR,
            block_add=STRING1_BLOCK_ADD,
            label="guide string +0x20",
        )

    poi_point_id = None
    if _present(mask_raw, 30, decoded_mask=True):
        poi_point_id = _u32(data, p, end, "guide poiPointId") ^ 0xAC4C2643
        p += 4

    resident_guide_type = None
    if _present(mask_raw, 10):
        raw = _u32(data, p, end, "guide resident type")
        resident_guide_type = ((raw + 0x8469CA8A) & 0xFFFFFFFF) ^ 0x2EF674A7
        p += 4

    guide_layer = None
    if _present(mask_raw, 15, decoded_mask=True):
        raw = _u32(data, p, end, "guide layer")
        guide_layer = ((raw + 0xF7EC8352) & 0xFFFFFFFF) ^ 0x14E4E67E
        p += 4

    guide_scene = None
    if _present(mask_raw, 3):
        guide_scene = _u32(data, p, end, "guide scene") ^ 0x33876F87
        p += 4

    poi_region_id = None
    if _present(mask_raw, 28):
        poi_region_id = _u32(data, p, end, "guide poiRegionId") ^ 0x8A316049
        p += 4

    params = None
    if _present(mask_raw, 4):
        params, p = _read_params(data, p, end)

    auto_guide = None
    if _present(mask_raw, 22):
        raw = _u32(data, p, end, "guide autoGuide")
        auto_guide = ((raw + 0x3558F5E6) & 0xFFFFFFFF) ^ 0x16544D4B
        p += 4

    unknown_scalar_40 = None
    if _present(mask_raw, 25):
        unknown_scalar_40 = _u32(data, p, end, "guide scalar +0x40") ^ 0x50426272
        p += 4

    unknown_scalar_5c = None
    if _present(mask_raw, 19):
        unknown_scalar_5c = _u32(data, p, end, "guide scalar +0x5C") ^ 0x46B407FE
        p += 4

    guide_type = None
    if _present(mask_raw, 23, decoded_mask=True):
        raw = _u32(data, p, end, "guide type")
        guide_type = (raw + 0x6FE88290) & 0xFFFFFFFF
        p += 4

    unknown_scalar_2c = None
    if _present(mask_raw, 18):
        unknown_scalar_2c = _u32(data, p, end, "guide scalar +0x2C") ^ 0x135FBF6F
        p += 4

    indicator_style = None
    if _present(mask_raw, 13):
        indicator_style = _u32(data, p, end, "guide indicator style") ^ 0xEDA2E8CA
        p += 4

    guide_style = None
    if _present(mask_raw, 24, decoded_mask=True):
        guide_style = _u32(data, p, end, "guide style") ^ 0x4E6C4BAE
        p += 4

    if p != end:
        raise QuestGuide71ParseError(
            f"QuestGuide71 consumes through 0x{p:X}, expected 0x{end:X}"
        )

    return QuestGuide71(
        start=start,
        end=p,
        mask_raw=mask_raw,
        unknown_string_10=unknown_string_10,
        params=params,
        unknown_string_20=unknown_string_20,
        in_scene_style=in_scene_style,
        unknown_scalar_2c=unknown_scalar_2c,
        auto_guide=auto_guide,
        guide_scene=guide_scene,
        indicator_style=indicator_style,
        resident_guide_type=resident_guide_type,
        unknown_scalar_40=unknown_scalar_40,
        unknown_scalar_44=unknown_scalar_44,
        guide_layer=guide_layer,
        poi_point_id=poi_point_id,
        guide_style=guide_style,
        area_style=area_style,
        poi_region_id=poi_region_id,
        unknown_scalar_5c=unknown_scalar_5c,
        guide_type=guide_type,
    )


def find_questguide71(
    data: bytes,
    search_start: int,
    expected_end: int,
) -> QuestGuide71:
    if search_start < 0 or expected_end > len(data) or search_start + 4 > expected_end:
        raise QuestGuide71ParseError(
            f"invalid guide search range 0x{search_start:X}..0x{expected_end:X}"
        )

    matches = []
    for start in range(search_start, expected_end - 3):
        mask_raw = struct.unpack_from("<I", data, start)[0]
        if mask_raw & FIXED_MASK != FIXED_VALUE:
            continue
        try:
            guide = parse_questguide71(data, start, expected_end)
        except QuestGuide71ParseError:
            continue
        matches.append(guide)

    if len(matches) != 1:
        raise QuestGuide71ParseError(
            f"expected one QuestGuide71 in 0x{search_start:X}..0x{expected_end:X}, "
            f"found {len(matches)}"
        )
    return matches[0]
