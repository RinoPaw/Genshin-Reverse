from __future__ import annotations

from dataclasses import dataclass
import struct


class QuestExcel71ParseError(ValueError):
    pass


SUB_ID_XOR = 0xB1571A55
EXCLUSIVE_PLACE_COUNT_XOR = 0xB51E6D91
EXCLUSIVE_PLACE_ELEMENT_SUB = 0x449FCFB9
PREFER_AREA2_GUIDE_SCENE_RAW = 0x8BFDD679
ORDER_RAW_SUB = 0x732ED834
IS_MP_BLOCK_TRUE_RAW = 0xDA
UNKNOWN_BIT34_RAW = 0x074282C5
UNKNOWN_BIT40_RAW = 0x08
STEP_DESC_TEXT_MAP_HASH_XOR = 0xABB3B4F1
GUIDE_TIPS_TEXT_MAP_HASH_XOR = 0x59B7A2F4
DMCMNPLMCKL_HIDDEN_RAW = 0x53FAFAF9
BAN_TYPE_BY_RAW = {
    0x120C27E2: "BAN_GROUP_COMMON",
    0x120C27E1: "BAN_GROUP_TRANSPORT_ONLY",
    0x120C27E0: "BAN_GROUP_TRANSPORT_MAP",
    0x120C27E7: "BAN_GROUP_TRANSPOR_GOTO_SCENE",
}

LOW_ROW_MASKS = frozenset({
    0x087EFDD5, 0x087EDDD5, 0x087FFDD5, 0x087EF9D5,
    0x083EFDD5, 0x087FDDD5, 0x287EFDD5, 0x087ED9D5,
    0x083EDDD5, 0x007FFDD5, 0x087FF9D5, 0x083EF9D5,
    0x083FFDD5,
})

BIT_DMCMNPLMCKL = 10
BIT_BAN_TYPE = 22
BIT_PREFER_AREA2_GUIDE_SCENE = 29
BIT_UNKNOWN_34 = 34
BIT_EXCLUSIVE_PLACE_LIST = 37
BIT_UNKNOWN_40 = 40
BIT_IS_MP_BLOCK = 52
BIT_ORDER = 57


@dataclass(frozen=True)
class QuestExcel71Row:
    index: int
    start: int
    end: int
    mask64: int
    unknown_prefix_u32: int
    exclusive_place_list: tuple[int, ...] | None
    prefer_area2_guide_scene: bool
    order: int | None
    is_mp_block: bool | None
    unknown_bit34_raw: int | None
    step_desc_text_map_hash: int
    dmcmnplmckl: str | None
    ban_type: str | None
    unknown_bit40_raw: int | None
    known_prefix_end: int
    raw_tail: bytes
    known_suffix_start: int
    guide_tips_text_map_hash: int
    sub_id: int

    @property
    def size(self) -> int:
        return self.end - self.start


@dataclass(frozen=True)
class QuestExcel71Table:
    table_header_u32: int
    rows: tuple[QuestExcel71Row, ...]
    payload_size: int

    @property
    def framed_bytes(self) -> int:
        return 4 + sum(row.size for row in self.rows)


def unwrap_mihoyo_bin_data(raw: bytes) -> bytes:
    if len(raw) < 4:
        raise QuestExcel71ParseError("MiHoYoBinData export is shorter than its length prefix")
    size = struct.unpack_from("<I", raw, 0)[0]
    end = 4 + size
    if end > len(raw):
        raise QuestExcel71ParseError(
            f"MiHoYoBinData declares {size} bytes, only {len(raw) - 4} remain"
        )
    trailing = raw[end:]
    if trailing.strip(b"\0"):
        raise QuestExcel71ParseError(
            f"unexpected non-zero MiHoYoBinData padding: {trailing.hex()}"
        )
    return raw[4:end]


def _u32(data: bytes, pos: int, end: int, label: str) -> int:
    if pos < 0 or pos + 4 > end:
        raise QuestExcel71ParseError(f"truncated {label} at 0x{pos:X}")
    return struct.unpack_from("<I", data, pos)[0]


def _row_starts(payload: bytes) -> list[int]:
    return [
        pos
        for pos in range(4, len(payload) - 7)
        if struct.unpack_from("<I", payload, pos)[0] in LOW_ROW_MASKS
    ]


def _parse_row(payload: bytes, index: int, start: int, end: int) -> QuestExcel71Row:
    if end - start < 24:
        raise QuestExcel71ParseError(
            f"implausibly short QuestExcel row {index} at 0x{start:X}"
        )

    mask64 = struct.unpack_from("<Q", payload, start)[0]
    unknown_prefix_u32 = _u32(payload, start + 8, end, "row +8 word")
    suffix_pos = end - 4
    sub_id = _u32(payload, suffix_pos, end, "subId") ^ SUB_ID_XOR
    p = start + 12

    exclusive_place_list = None
    if (mask64 >> BIT_EXCLUSIVE_PLACE_LIST) & 1:
        count = _u32(payload, p, suffix_pos, "exclusivePlaceList count") ^ EXCLUSIVE_PLACE_COUNT_XOR
        if count > 64:
            raise QuestExcel71ParseError(
                f"row {index} subId {sub_id} has implausible exclusivePlaceList count {count}"
            )
        p += 4
        if p + count * 4 > suffix_pos:
            raise QuestExcel71ParseError(
                f"row {index} subId {sub_id} truncates exclusivePlaceList"
            )
        values = []
        for _ in range(count):
            raw_value = _u32(payload, p, suffix_pos, "exclusivePlaceList element")
            values.append((raw_value - EXCLUSIVE_PLACE_ELEMENT_SUB) & 0xFFFFFFFF)
            p += 4
        exclusive_place_list = tuple(values)

    prefer_area2_guide_scene = bool((mask64 >> BIT_PREFER_AREA2_GUIDE_SCENE) & 1)
    if prefer_area2_guide_scene:
        raw_value = _u32(payload, p, suffix_pos, "bit29 scalar")
        if raw_value != PREFER_AREA2_GUIDE_SCENE_RAW:
            raise QuestExcel71ParseError(
                f"row {index} subId {sub_id} has unexpected bit29 raw 0x{raw_value:08X}"
            )
        p += 4

    order = None
    if (mask64 >> BIT_ORDER) & 1:
        raw_order = _u32(payload, p, suffix_pos, "order")
        order = (raw_order - ORDER_RAW_SUB) & 0xFFFFFFFF
        p += 4

    is_mp_block = None
    if (mask64 >> BIT_IS_MP_BLOCK) & 1:
        if p >= suffix_pos:
            raise QuestExcel71ParseError(f"row {index} subId {sub_id} truncates isMpBlock")
        raw_value = payload[p]
        if raw_value != IS_MP_BLOCK_TRUE_RAW:
            raise QuestExcel71ParseError(
                f"row {index} subId {sub_id} has unexpected bit52 raw 0x{raw_value:02X}"
            )
        is_mp_block = True
        p += 1

    unknown_bit34_raw = None
    if (mask64 >> BIT_UNKNOWN_34) & 1:
        unknown_bit34_raw = _u32(payload, p, suffix_pos, "bit34 scalar")
        if unknown_bit34_raw != UNKNOWN_BIT34_RAW:
            raise QuestExcel71ParseError(
                f"row {index} subId {sub_id} has unexpected bit34 raw 0x{unknown_bit34_raw:08X}"
            )
        p += 4

    step_desc_text_map_hash = (
        _u32(payload, p, suffix_pos, "stepDescTextMapHash")
        ^ STEP_DESC_TEXT_MAP_HASH_XOR
    )
    p += 4

    dmcmnplmckl = None
    if not ((mask64 >> BIT_DMCMNPLMCKL) & 1):
        raw_value = _u32(payload, p, suffix_pos, "DMCMNPLMCKL")
        if raw_value != DMCMNPLMCKL_HIDDEN_RAW:
            raise QuestExcel71ParseError(
                f"row {index} subId {sub_id} has unexpected DMCMNPLMCKL raw "
                f"0x{raw_value:08X}"
            )
        dmcmnplmckl = "QUEST_HIDDEN"
        p += 4

    ban_type = None
    if not ((mask64 >> BIT_BAN_TYPE) & 1):
        raw_value = _u32(payload, p, suffix_pos, "banType")
        ban_type = BAN_TYPE_BY_RAW.get(raw_value)
        if ban_type is None:
            raise QuestExcel71ParseError(
                f"row {index} subId {sub_id} has unexpected banType raw "
                f"0x{raw_value:08X}"
            )
        p += 4

    unknown_bit40_raw = None
    if (mask64 >> BIT_UNKNOWN_40) & 1:
        if p >= suffix_pos:
            raise QuestExcel71ParseError(f"row {index} subId {sub_id} truncates bit40 scalar")
        unknown_bit40_raw = payload[p]
        if unknown_bit40_raw != UNKNOWN_BIT40_RAW:
            raise QuestExcel71ParseError(
                f"row {index} subId {sub_id} has unexpected bit40 raw "
                f"0x{unknown_bit40_raw:02X}"
            )
        p += 1

    known_suffix_start = suffix_pos - 4
    if p > known_suffix_start:
        raise QuestExcel71ParseError(
            f"row {index} subId {sub_id} known prefix overlaps guideTipsTextMapHash"
        )
    guide_tips_text_map_hash = (
        _u32(payload, known_suffix_start, suffix_pos, "guideTipsTextMapHash")
        ^ GUIDE_TIPS_TEXT_MAP_HASH_XOR
    )

    return QuestExcel71Row(
        index=index,
        start=start,
        end=end,
        mask64=mask64,
        unknown_prefix_u32=unknown_prefix_u32,
        exclusive_place_list=exclusive_place_list,
        prefer_area2_guide_scene=prefer_area2_guide_scene,
        order=order,
        is_mp_block=is_mp_block,
        unknown_bit34_raw=unknown_bit34_raw,
        step_desc_text_map_hash=step_desc_text_map_hash,
        dmcmnplmckl=dmcmnplmckl,
        ban_type=ban_type,
        unknown_bit40_raw=unknown_bit40_raw,
        known_prefix_end=p,
        raw_tail=payload[p:known_suffix_start],
        known_suffix_start=known_suffix_start,
        guide_tips_text_map_hash=guide_tips_text_map_hash,
        sub_id=sub_id,
    )


def parse_questexcel71_payload(
    payload: bytes,
    *,
    expected_row_count: int | None = 33_214,
) -> QuestExcel71Table:
    if len(payload) < 4:
        raise QuestExcel71ParseError("QuestExcel payload is shorter than its table header")

    starts = _row_starts(payload)
    if not starts or starts[0] != 4:
        first = "none" if not starts else f"0x{starts[0]:X}"
        raise QuestExcel71ParseError(f"unexpected first QuestExcel row start: {first}")
    if expected_row_count is not None and len(starts) != expected_row_count:
        raise QuestExcel71ParseError(
            f"expected {expected_row_count} QuestExcel rows, found {len(starts)}"
        )

    rows = []
    seen_sub_ids = set()
    for index, start in enumerate(starts):
        end = starts[index + 1] if index + 1 < len(starts) else len(payload)
        row = _parse_row(payload, index, start, end)
        if row.sub_id in seen_sub_ids:
            raise QuestExcel71ParseError(f"duplicate QuestExcel subId {row.sub_id}")
        seen_sub_ids.add(row.sub_id)
        rows.append(row)

    table = QuestExcel71Table(
        table_header_u32=struct.unpack_from("<I", payload, 0)[0],
        rows=tuple(rows),
        payload_size=len(payload),
    )
    if table.framed_bytes != len(payload):
        raise QuestExcel71ParseError(
            f"QuestExcel framing consumes {table.framed_bytes} of {len(payload)} bytes"
        )
    return table


def parse_questexcel71_raw_export(
    raw: bytes,
    *,
    expected_row_count: int | None = 33_214,
) -> QuestExcel71Table:
    return parse_questexcel71_payload(
        unwrap_mihoyo_bin_data(raw),
        expected_row_count=expected_row_count,
    )