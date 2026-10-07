from __future__ import annotations

import struct
import unittest

from genshinre.questexcel71 import (
    BAN_TYPE_BY_RAW,
    BIT_BAN_TYPE,
    BIT_DMCMNPLMCKL,
    BIT_EXCLUSIVE_PLACE_LIST,
    BIT_IS_MP_BLOCK,
    BIT_ORDER,
    BIT_PREFER_AREA2_GUIDE_SCENE,
    BIT_SHOW_TYPE,
    BIT_UNKNOWN_34,
    BIT_UNKNOWN_40,
    EXCLUSIVE_PLACE_COUNT_XOR,
    DMCMNPLMCKL_HIDDEN_RAW,
    EXCLUSIVE_PLACE_ELEMENT_SUB,
    GUIDE_TIPS_TEXT_MAP_HASH_XOR,
    IS_MP_BLOCK_TRUE_RAW,
    LOW_ROW_MASKS,
    ORDER_RAW_SUB,
    PREFER_AREA2_GUIDE_SCENE_RAW,
    QuestExcel71ParseError,
    SHOW_TYPE_HIDDEN_RAW,
    STEP_DESC_TEXT_MAP_HASH_XOR,
    SUB_ID_XOR,
    UNKNOWN_BIT34_RAW,
    UNKNOWN_BIT40_RAW,
    parse_questexcel71_raw_export,
)

from genshinre.questguide71 import (
    PARAM_BLOCK_ADD,
    PARAM_COUNT_ADD,
    PARAM_LENGTH_XOR,
)


LOW_MASK = 0x087EFDD5


def u32(value: int) -> bytes:
    return struct.pack("<I", value & 0xFFFFFFFF)


def _encode_additive_blocks(decoded: bytes, add_key: int) -> bytes:
    out = bytearray()
    for pos in range(0, len(decoded), 8):
        block = decoded[pos:pos + 8]
        width = len(block)
        mask = (1 << (width * 8)) - 1
        value = int.from_bytes(block, "little")
        encoded = (value - (add_key & mask)) & mask
        out += encoded.to_bytes(width, "little")
    return bytes(out)


def _encode_param(value: str) -> bytes:
    raw = value.encode("utf-8")
    return (
        struct.pack("<H", len(raw) ^ PARAM_LENGTH_XOR)
        + _encode_additive_blocks(raw, PARAM_BLOCK_ADD)
    )


def make_guide(
    *,
    params: tuple[str, ...] = ("", "", "", "", ""),
    guide_scene: int | None = None,
    guide_type: int | None = None,
) -> bytes:
    # All decoded-mask-gated fields absent; raw bit4 keeps the params array.
    mask_raw = 0x4DB0C853
    if guide_scene is not None:
        mask_raw |= 1 << 3
    if guide_type is not None:
        # Guide type uses decoded bit23; MASK_XOR bit23 is one.
        mask_raw &= ~(1 << 23)

    out = bytearray(u32(mask_raw))
    if guide_scene is not None:
        out += u32(guide_scene ^ 0x33876F87)
    out += u32(len(params) - PARAM_COUNT_ADD)
    for value in params:
        out += _encode_param(value)
    if guide_type is not None:
        out += u32(guide_type - 0x6FE88290)
    return bytes(out)


def make_row(
    sub_id: int,
    *,
    unknown_prefix_u32: int,
    places: tuple[int, ...] | None = None,
    prefer: bool = False,
    order: int | None = None,
    is_mp_block: bool = False,
    bit34: bool = False,
    step_desc_text_map_hash: int = 0,
    dmcmnplmckl_hidden: bool = False,
    ban_type: str | None = None,
    bit40: bool = False,
    tail: bytes = b"",
    guide: bytes | None = None,
    show_hidden: bool = False,
    guide_tips_text_map_hash: int = 0,
) -> bytes:
    mask64 = LOW_MASK
    if places is not None:
        mask64 |= 1 << BIT_EXCLUSIVE_PLACE_LIST
    if prefer:
        mask64 |= 1 << BIT_PREFER_AREA2_GUIDE_SCENE
    if order is not None:
        mask64 |= 1 << BIT_ORDER
    if is_mp_block:
        mask64 |= 1 << BIT_IS_MP_BLOCK
    if bit34:
        mask64 |= 1 << BIT_UNKNOWN_34
    if dmcmnplmckl_hidden:
        mask64 &= ~(1 << BIT_DMCMNPLMCKL)
    if ban_type is not None:
        mask64 &= ~(1 << BIT_BAN_TYPE)
    if bit40: