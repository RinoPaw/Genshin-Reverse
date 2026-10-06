from __future__ import annotations

from dataclasses import dataclass
from typing import Callable


class LegacyQuestParseError(ValueError):
    """Raised when a legacy QuestExcel payload violates the known wire schema."""


@dataclass(frozen=True)
class LegacyQuestRow:
    index: int
    start: int
    end: int
    fields: dict[str, object]


@dataclass(frozen=True)
class LegacyQuestPrefix:
    xor_key: int
    row_count: int
    rows: tuple[LegacyQuestRow, ...]
    consumed: int


_FIELD_LAYOUT = (
    ("sub_id", "u"),
    ("main_id", "u"),
    ("order", "s"),
    ("sub_id_set", "u"),
    ("is_mp_block", "bool"),
    ("desc", "u"),
    ("step_desc", "u"),
    ("guide_tips", "u"),
    ("show_type", "s"),
    ("ban_type", "s"),
    ("accept_cond_comb", "s"),
    ("accept_cond", "cond_array"),
    ("finish_cond_comb", "s"),
    ("finish_cond", "content_array"),
    ("fail_cond_comb", "s"),
    ("fail_cond", "content_array"),
    ("guide", "guide"),
    ("show_guide", "s"),
    ("finish_parent", "bool"),
    ("fail_parent", "bool"),
    ("fail_parent_show", "s"),
    ("is_rewind", "bool"),
    ("finish_exec", "exec_array"),
    ("fail_exec", "exec_array"),
    ("begin_exec", "exec_array"),
    ("exclusive_npc_list", "u_array"),
    ("shared_npc_list", "u_array"),
    ("exclusive_npc_priority", "u"),
    ("trial_avatar_list", "u_array"),
    ("exclusive_place_list", "u_array"),
)


def unwrap_legacy_mihoyo_bin_data(raw: bytes) -> bytes:
    """Remove the little-endian length prefix emitted by Raw MiHoYoBinData export."""
    if len(raw) < 4:
        raise LegacyQuestParseError("MiHoYoBinData export is shorter than its length prefix")
    size = int.from_bytes(raw[:4], "little")
    end = 4 + size
    if end > len(raw):
        raise LegacyQuestParseError(
            f"MiHoYoBinData declares {size} bytes, only {len(raw) - 4} remain"
        )
    trailing = raw[end:]
    if trailing.strip(b"\0"):
        raise LegacyQuestParseError(
            f"unexpected non-zero MiHoYoBinData padding: {trailing.hex()}"
        )
    return raw[4:end]


def xor_bytes(data: bytes, key: int) -> bytes:
    if not 0 <= key <= 0xFF:
        raise ValueError("XOR key must fit in one byte")
    return bytes(value ^ key for value in data)


def read_uvar(data: bytes, pos: int) -> tuple[int, int]:
    value = 0
    shift = 0
    start = pos
    for _ in range(10):
        if pos >= len(data):
            raise LegacyQuestParseError(f"truncated varint at 0x{start:X}")
        byte = data[pos]
        pos += 1
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return value, pos
        shift += 7
    raise LegacyQuestParseError(f"varint is wider than 10 bytes at 0x{start:X}")


def read_svar(data: bytes, pos: int) -> tuple[int, int]:
    unsigned, pos = read_uvar(data, pos)
    return (unsigned >> 1) ^ -(unsigned & 1), pos


def _read_bitfield(data: bytes, pos: int, *, max_bytes: int) -> tuple[bytes, int]:
    length, pos = read_uvar(data, pos)
    if length > max_bytes:
        raise LegacyQuestParseError(
            f"implausible bitfield length {length} at 0x{pos:X}"
        )
    end = pos + length
    if end > len(data):
        raise LegacyQuestParseError(f"truncated bitfield at 0x{pos:X}")
    return data[pos:end], end


def _read_bool(data: bytes, pos: int) -> tuple[bool, int]:
    if pos >= len(data):
        raise LegacyQuestParseError(f"truncated bool at 0x{pos:X}")
    value = data[pos]
    if value not in (0, 1):
        raise LegacyQuestParseError(f"invalid bool {value} at 0x{pos:X}")
    return bool(value), pos + 1


def _read_string(data: bytes, pos: int) -> tuple[str, int]:
    length, pos = read_uvar(data, pos)
    if length > 1_000_000:
        raise LegacyQuestParseError(f"implausible string length {length} at 0x{pos:X}")
    end = pos + length
    if end > len(data):
        raise LegacyQuestParseError(f"truncated string at 0x{pos:X}")
    try:
        return data[pos:end].decode("utf-8"), end
    except UnicodeDecodeError as exc:
        raise LegacyQuestParseError(f"invalid UTF-8 string at 0x{pos:X}") from exc


def _read_u_array(data: bytes, pos: int) -> tuple[list[int], int]:
    count, pos = read_uvar(data, pos)
    if count > 100_000:
        raise LegacyQuestParseError(f"implausible unsigned-array count {count}")
    values: list[int] = []
    for _ in range(count):
        value, pos = read_uvar(data, pos)
        values.append(value)
    return values, pos


def _read_s_array(data: bytes, pos: int) -> tuple[list[int], int]:
    count, pos = read_svar(data, pos)
    if not 0 <= count <= 100_000:
        raise LegacyQuestParseError(f"implausible signed-array count {count}")
    values: list[int] = []
    for _ in range(count):
        value, pos = read_svar(data, pos)
        values.append(value)
    return values, pos


def _read_string_array(data: bytes, pos: int) -> tuple[list[str], int]:
    count, pos = read_uvar(data, pos)
    if count > 100_000:
        raise LegacyQuestParseError(f"implausible string-array count {count}")
    values: list[str] = []
    for _ in range(count):
        value, pos = _read_string(data, pos)
        values.append(value)
    return values, pos


def _read_object_array(
    data: bytes,
    pos: int,
    reader: Callable[[bytes, int], tuple[dict[str, object], int]],
) -> tuple[list[dict[str, object]], int]:
    count, pos = read_svar(data, pos)
    if not 0 <= count <= 100_000:
        raise LegacyQuestParseError(f"implausible object-array count {count}")
    values: list[dict[str, object]] = []
    for _ in range(count):
        value, pos = reader(data, pos)
        values.append(value)
    return values, pos


def _read_quest_cond(data: bytes, pos: int) -> tuple[dict[str, object], int]:
    bits, pos = _read_bitfield(data, pos, max_bytes=4)
    value: dict[str, object] = {"bitfield": bits.hex()}
    if bits and bits[0] & 0x01:
        value["type"], pos = read_svar(data, pos)
    if bits and bits[0] & 0x02:
        value["param"], pos = _read_s_array(data, pos)
    return value, pos


def _read_quest_content(data: bytes, pos: int) -> tuple[dict[str, object], int]:
    bits, pos = _read_bitfield(data, pos, max_bytes=4)
    value: dict[str, object] = {"bitfield": bits.hex()}
    if bits and bits[0] & 0x01:
        value["type"], pos = read_svar(data, pos)
    if bits and bits[0] & 0x02:
        value["param"], pos = _read_s_array(data, pos)
    if bits and bits[0] & 0x04:
        value["param_str"], pos = _read_string(data, pos)
    if bits and bits[0] & 0x08:
        value["count"], pos = read_uvar(data, pos)
    return value, pos


def _read_quest_exec(data: bytes, pos: int) -> tuple[dict[str, object], int]:
    bits, pos = _read_bitfield(data, pos, max_bytes=4)
    value: dict[str, object] = {"bitfield": bits.hex()}
    if bits and bits[0] & 0x01:
        value["type"], pos = read_svar(data, pos)
    if bits and bits[0] & 0x02:
        value["param"], pos = _read_string_array(data, pos)
    return value, pos


def _read_quest_guide(data: bytes, pos: int) -> tuple[dict[str, object], int]:
    bits, pos = _read_bitfield(data, pos, max_bytes=4)
    value: dict[str, object] = {"bitfield": bits.hex()}
    if bits and bits[0] & 0x01:
        value["type"], pos = read_svar(data, pos)
    if bits and bits[0] & 0x02:
        value["auto_guide"], pos = read_svar(data, pos)
    if bits and bits[0] & 0x04:
        value["param"], pos = _read_string_array(data, pos)
    if bits and bits[0] & 0x08:
        value["guide_scene"], pos = read_uvar(data, pos)
    if bits and bits[0] & 0x10:
        value["guide_style"], pos = read_svar(data, pos)
    if bits and bits[0] & 0x20:
        value["guide_layer"], pos = read_svar(data, pos)
    return value, pos


def parse_legacy_quest_row(data: bytes, pos: int, *, index: int = 0) -> LegacyQuestRow:
    """Parse the 30-field QuestExcel row wire layout used by the 2.8/3.x family."""
    start = pos
    bits, pos = _read_bitfield(data, pos, max_bytes=8)
    fields: dict[str, object] = {"bitfield": bits.hex()}

    for field_index, (name, kind) in enumerate(_FIELD_LAYOUT):
        byte_index = field_index // 8
        if byte_index >= len(bits) or not bits[byte_index] & (1 << (field_index % 8)):
            continue

        if kind == "u":
            fields[name], pos = read_uvar(data, pos)
        elif kind == "s":
            fields[name], pos = read_svar(data, pos)
        elif kind == "bool":
            fields[name], pos = _read_bool(data, pos)
        elif kind == "u_array":
            fields[name], pos = _read_u_array(data, pos)
        elif kind == "cond_array":
            fields[name], pos = _read_object_array(data, pos, _read_quest_cond)
        elif kind == "content_array":
            fields[name], pos = _read_object_array(data, pos, _read_quest_content)
        elif kind == "exec_array":
            fields[name], pos = _read_object_array(data, pos, _read_quest_exec)
        elif kind == "guide":
            fields[name], pos = _read_quest_guide(data, pos)
        else:
            raise AssertionError(f"unknown QuestExcel field kind {kind}")

    return LegacyQuestRow(index=index, start=start, end=pos, fields=fields)


def parse_legacy_quest_prefix(
    raw: bytes,
    *,
    xor_key: int,
    max_rows: int,
) -> LegacyQuestPrefix:
    """Decrypt and parse a prefix of an old QuestExcel Raw MiHoYoBinData export."""
    encrypted = unwrap_legacy_mihoyo_bin_data(raw)
    data = xor_bytes(encrypted, xor_key)
    row_count, pos = read_svar(data, 0)
    if not 0 <= row_count <= 1_000_000:
        raise LegacyQuestParseError(f"implausible QuestExcel row count {row_count}")

    rows: list[LegacyQuestRow] = []
    for index in range(min(row_count, max_rows)):
        row = parse_legacy_quest_row(data, pos, index=index)
        rows.append(row)
        pos = row.end

    return LegacyQuestPrefix(
        xor_key=xor_key,
        row_count=row_count,
        rows=tuple(rows),
        consumed=pos,
    )


def detect_legacy_quest_xor_key(
    raw: bytes,
    *,
    probe_rows: int = 100,
    min_row_count: int = 1_000,
    max_row_count: int = 100_000,
) -> tuple[int, int]:
    """Find the single-byte XOR key by requiring a structurally valid QuestExcel prefix."""
    encrypted = unwrap_legacy_mihoyo_bin_data(raw)
    candidates: list[tuple[int, int]] = []

    for key in range(0x100):
        data = xor_bytes(encrypted, key)
        try:
            row_count, pos = read_svar(data, 0)
            if not min_row_count <= row_count <= max_row_count:
                continue

            rows_with_sub_id = 0
            for index in range(min(row_count, probe_rows)):
                row = parse_legacy_quest_row(data, pos, index=index)
                pos = row.end

                sub_id = row.fields.get("sub_id")
                main_id = row.fields.get("main_id")
                order = row.fields.get("order")
                if sub_id is not None:
                    if not isinstance(sub_id, int) or not 0 < sub_id < 100_000_000:
                        raise LegacyQuestParseError("implausible subId")
                    rows_with_sub_id += 1
                if main_id is not None and (
                    not isinstance(main_id, int) or not 0 <= main_id < 10_000_000
                ):
                    raise LegacyQuestParseError("implausible mainId")
                if order is not None and (
                    not isinstance(order, int) or not -100_000 < order < 100_000
                ):
                    raise LegacyQuestParseError("implausible order")

            if rows_with_sub_id < max(1, probe_rows // 5):
                continue
            candidates.append((key, row_count))
        except LegacyQuestParseError:
            continue

    if len(candidates) != 1:
        rendered = ", ".join(f"0x{key:02X}:{count}" for key, count in candidates)
        raise LegacyQuestParseError(
            f"expected one legacy QuestExcel XOR candidate, got {len(candidates)}"
            + (f": {rendered}" if rendered else "")
        )
    return candidates[0]


def find_quest_rows(
    prefix: LegacyQuestPrefix,
    *,
    main_id: int,
) -> tuple[LegacyQuestRow, ...]:
    return tuple(row for row in prefix.rows if row.fields.get("main_id") == main_id)
