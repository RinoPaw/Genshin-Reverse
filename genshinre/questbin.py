from __future__ import annotations

from dataclasses import dataclass
from typing import Any


_U32_MASK = 0xFFFFFFFF
_U64_MASK = 0xFFFFFFFFFFFFFFFF


class QuestBinDecodeError(ValueError):
    """Raised when a native Quest BinOutput payload violates the recovered 7.1 wire."""


@dataclass(frozen=True)
class DecodedMainQuest:
    data: dict[str, Any]
    consumed: int
    payload_size: int
    row_boundaries: tuple[tuple[int, int, int], ...]

    @property
    def fully_consumed(self) -> bool:
        return self.consumed == self.payload_size

    def to_dict(self, *, include_debug: bool = False) -> dict[str, Any]:
        out = dict(self.data)
        if include_debug:
            out["_decode"] = {
                "payloadSize": self.payload_size,
                "consumed": self.consumed,
                "fullyConsumed": self.fully_consumed,
                "rowBoundaries": [
                    {"subId": sub_id, "start": start, "end": end}
                    for sub_id, start, end in self.row_boundaries
                ],
            }
        return out


class _Reader:
    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0

    def take(self, count: int) -> bytes:
        if count < 0:
            raise QuestBinDecodeError(f"negative read length {count} at 0x{self.pos:X}")
        end = self.pos + count
        if end > len(self.data):
            raise QuestBinDecodeError(
                f"truncated Quest BinOutput at 0x{self.pos:X}: need {count} bytes, "
                f"have {len(self.data) - self.pos}"
            )
        out = self.data[self.pos:end]
        self.pos = end
        return out

    def u8(self) -> int:
        return self.take(1)[0]

    def u16(self) -> int:
        return int.from_bytes(self.take(2), "little")

    def u32(self) -> int:
        return int.from_bytes(self.take(4), "little")

    def u64(self) -> int:
        return int.from_bytes(self.take(8), "little")


def _active_bits(mask: int, width: int) -> list[int]:
    return [bit for bit in range(width) if mask & (1 << bit)]


def _require_supported_bits(mask: int, supported: set[int], *, label: str, width: int) -> None:
    unknown = [bit for bit in _active_bits(mask, width) if bit not in supported]
    if unknown:
        rendered = ", ".join(str(bit) for bit in unknown)
        raise QuestBinDecodeError(f"{label} has unsupported presence bit(s): {rendered}")


def _decode_xor_chunks(data: bytes, constant: int) -> bytes:
    key = constant.to_bytes(8, "little")
    out = bytearray()
    for offset in range(0, len(data), 8):
        chunk = data[offset : offset + 8]
        out.extend(value ^ key[index] for index, value in enumerate(chunk))
    return bytes(out)


def _decode_add_chunks(data: bytes, constant: int) -> bytes:
    out = bytearray()
    for offset in range(0, len(data), 8):
        chunk = data[offset : offset + 8]
        width = len(chunk)
        modulus = 1 << (width * 8)
        value = (int.from_bytes(chunk, "little") + (constant & (modulus - 1))) % modulus
        out.extend(value.to_bytes(width, "little"))
    return bytes(out)


def _text_or_hex(data: bytes) -> str | dict[str, str]:
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return {"decodedHex": data.hex()}


def _read_xor_string(reader: _Reader, length: int, constant: int) -> str | dict[str, str]:
    return _text_or_hex(_decode_xor_chunks(reader.take(length), constant))


def _read_add_string(reader: _Reader, length: int, constant: int) -> str | dict[str, str]:
    return _text_or_hex(_decode_add_chunks(reader.take(length), constant))


def _read_raw_string(reader: _Reader, length: int) -> dict[str, str]:
    return {"encodedHex": reader.take(length).hex()}


def _read_quest_exec(reader: _Reader) -> dict[str, Any]:
    mask = (reader.u8() + 0x44) & 0xFF
    _require_supported_bits(mask, {2, 5}, label="KIMCPAKMJMH", width=8)
    value: dict[str, Any] = {}

    if mask & (1 << 5):
        count = ((reader.u32() + 0x8DAF6E6F) & _U32_MASK) ^ 0x745258F8
        if count > 100_000:
            raise QuestBinDecodeError(f"implausible QuestExec string parameter count {count}")
        params: list[str | dict[str, str]] = []
        for _ in range(count):
            length = reader.u16() ^ 0xDEA7
            params.append(_read_add_string(reader, length, 0x0B61F31AFE80DEA7))
        value["param"] = params

    if mask & (1 << 2):
        value["type"] = (reader.u32() + 0x203BCD7F) & _U32_MASK

    return value


def _read_quest_exec_array(reader: _Reader) -> list[dict[str, Any]]:
    count = (reader.u32() + 0xB0F7C9F4) & _U32_MASK
    if count > 100_000:
        raise QuestBinDecodeError(f"implausible QuestExec array count {count}")
    return [_read_quest_exec(reader) for _ in range(count)]


def _read_quest_content(reader: _Reader) -> dict[str, Any]:
    mask = (reader.u8() + 0x8F) & 0xFF
    _require_supported_bits(mask, {0, 1, 7}, label="JPGNLOPMNHN", width=8)
    value: dict[str, Any] = {}

    if mask & (1 << 1):
        length = (reader.u16() + 0x8555) & 0xFFFF
        value["unknown_bit_1"] = _read_xor_string(reader, length, 0xA4D839D96CBB8555)

    # Runtime/semantic cross-check: this slot decodes to the current QuestContentType.
    if mask & 1:
        value["type"] = ((reader.u32() ^ 0xE9FA3068) + 0x31C7C23E) & _U32_MASK

    if mask & (1 << 7):
        count = (reader.u32() + 0xC867B940) & _U32_MASK
        if count > 100_000:
            raise QuestBinDecodeError(f"implausible QuestContent numeric parameter count {count}")
        value["param"] = [
            (reader.u32() + 0x78B6DDFA) & _U32_MASK for _ in range(count)
        ]

    if mask & (1 << 4):
        value["unknown_bit_4"] = reader.u32() ^ 0x06723F87

    return value


def _read_quest_content_array(reader: _Reader) -> list[dict[str, Any]]:
    count = ((reader.u32() + 0x9278C6C1) & _U32_MASK) ^ 0x415C14AA
    if count > 100_000:
        raise QuestBinDecodeError(f"implausible QuestContent array count {count}")
    return [_read_quest_content(reader) for _ in range(count)]


def _read_oop(reader: _Reader) -> dict[str, Any]:
    mask = (reader.u32() - 0x5816EEF2) & _U32_MASK
    # First production surface: only shapes directly exercised by the 351 gold fixture.
    supported = {3, 4, 13, 24, 25, 28, 30}
    _require_supported_bits(mask, supported, label="OOPFBIEAILL", width=32)
    value: dict[str, Any] = {}

    if mask & (1 << 21):
        value["unknown_bit_21"] = reader.u32() ^ 0xB1CEAA21
    if mask & (1 << 30):
        length = ((reader.u16() - 0x06DC) & 0xFFFF) ^ 0x3684
        value["unknown_bit_30"] = _read_xor_string(reader, length, 0x53293684354DF924)
    if mask & (1 << 4):
        count = ((reader.u32() + 0x0444371E) & _U32_MASK) ^ 0x011A3440
        if count > 100_000:
            raise QuestBinDecodeError(f"implausible OOPFBIEAILL string-array count {count}")
        items = []
        for _ in range(count):
            length = reader.u16() ^ 0xD538
            items.append(_read_add_string(reader, length, 0xE575DFB19A2DD538))
        value["unknown_bit_4"] = items

    if mask & (1 << 7):
        value["unknown_bit_7"] = reader.u32() ^ 0xF2E446C9
    if mask & (1 << 6):
        value["unknown_bit_6"] = reader.u32() ^ 0x01836AF8
    if mask & (1 << 25):
        value["unknown_bit_25"] = ((reader.u32() + 0xBB4C1A74) & _U32_MASK) ^ 0xC4348988
    if mask & (1 << 26):
        value["unknown_bit_26"] = reader.u32() ^ 0xDB7D7792
    if mask & (1 << 2):
        value["unknown_bit_2"] = (reader.u32() + 0x45C609CE) & _U32_MASK
    if mask & (1 << 1):
        value["unknown_bit_1"] = reader.u32() ^ 0xD0F3A0A3
    if mask & (1 << 24):
        value["unknown_bit_24"] = reader.u32() ^ 0xCF1202E3
    if mask & (1 << 13):
        length = (reader.u16() + 0x72FE) & 0xFFFF
        value["unknown_bit_13"] = _read_xor_string(reader, length, 0x6F1ACF7F7A3872FE)
    if mask & (1 << 28):
        value["unknown_bit_28"] = (reader.u32() + 0xC3BE4A3E) & _U32_MASK
    if mask & (1 << 3):
        value["unknown_bit_3"] = reader.u32() ^ 0xBB23DA81
    if mask & (1 << 20):
        value["unknown_bit_20"] = (reader.u32() + 0xDD1C8CBE) & _U32_MASK
    if mask & (1 << 15):
        value["unknown_bit_15"] = reader.u32() ^ 0xEDE96EF8
    if mask & (1 << 8):
        value["unknown_bit_8"] = reader.u32() ^ 0xB5A11D8E
    if mask & (1 << 5):
        value["unknown_bit_5"] = reader.u32() ^ 0xD87113B8

    return value


def _read_kph(reader: _Reader) -> dict[str, Any]:
    flags = reader.u8()
    if flags & ~0xE4:
        raise QuestBinDecodeError(
            f"KPHLFFOELCG has unsupported flag bit(s): "
            f"{', '.join(str(bit) for bit in _active_bits(flags & ~0xE4, 8))}"
        )
    value: dict[str, Any] = {"unknown_flags": flags}

    if flags & (1 << 2):
        length = reader.u16() ^ 0x78AE
        value["unknown_bit_2"] = _read_add_string(reader, length, 0xE01441134DDA78AE)

    # The native reader uses inverted guards for these two fields.
    if not flags & (1 << 6):
        value["unknown_bit_6_clear"] = reader.u32() ^ 0x3F857DF8
    if not flags & (1 << 7):
        length = reader.u16() ^ 0xEFA9
        value["unknown_bit_7_clear"] = _read_add_string(reader, length, 0x2C320EC05CBCEFA9)

    return value


# Production support is intentionally narrower than the research reader.
# Expand this set only after a new field shape is independently regression-tested.
_ROW_SUPPORTED_BITS = {
    0, 3, 12, 17, 19, 22, 25, 26, 34, 35, 39, 48, 51, 55, 56, 62,
}


def _read_quest_row(reader: _Reader) -> tuple[dict[str, Any], int, int]:
    start = reader.pos
    mask = (reader.u64() + 0x2244ECE7) & _U64_MASK
    _require_supported_bits(mask, _ROW_SUPPORTED_BITS, label="LAIMPNDEFCL", width=64)
    value: dict[str, Any] = {}

    if mask & (1 << 56):
        value["finishExec"] = _read_quest_exec_array(reader)
    if mask & (1 << 36):
        value["unknown_bit_36"] = (reader.u32() + 0xD3B00C66) & _U32_MASK
    if mask & (1 << 5):
        value["unknown_bit_5"] = (reader.u32() + 0x191BB9F3) & _U32_MASK
    if mask & (1 << 41):
        value["unknown_bit_41"] = reader.u8() != 0x18
    if mask & (1 << 22):
        value["unknown_bit_22"] = reader.u32() ^ 0x7C9371BD
    if mask & (1 << 17):
        value["unknown_bit_17"] = reader.u32() ^ 0x491C364E
    if mask & (1 << 46):
        value["unknown_bit_46"] = ((reader.u32() + 0xB5F93568) & _U32_MASK) ^ 0xBCB94817
    if mask & (1 << 34):
        value["unknown_bit_34"] = _read_oop(reader)
    if mask & (1 << 38):
        value["unknown_bit_38"] = reader.u32() ^ 0x8FE7A26B
    if mask & (1 << 19):
        value["subId"] = reader.u32() ^ 0xAB3097F8
    if mask & (1 << 21):
        value["unknown_bit_21"] = reader.u8() != 0x63
    if mask & (1 << 3):
        value["unknown_bit_3"] = reader.u32() ^ 0xB4EBB7D3
    if mask & (1 << 10):
        value["unknown_bit_10"] = reader.u32() ^ 0x011CF6ED
    if mask & (1 << 51):
        value["failCond"] = _read_quest_content_array(reader)
    if mask & (1 << 52):
        value["unknown_bit_52"] = (reader.u32() + 0xA6768BF5) & _U32_MASK
    if mask & (1 << 39):
        length = (reader.u16() + 0x6275) & 0xFFFF
        value["unknown_bit_39"] = _read_xor_string(reader, length, 0xCAB6E5555D466275)
    if mask & (1 << 33):
        value["unknown_bit_33"] = ((reader.u32() + 0x4B39F4CC) & _U32_MASK) ^ 0xC08A4FDA
    if mask & (1 << 25):
        length = (reader.u16() + 0x997F) & 0xFFFF
        value["unknown_bit_25"] = _read_xor_string(reader, length, 0xF99BB614A15B997F)
    if mask & 1:
        value["order"] = (reader.u32() + 0x1B56F89A) & _U32_MASK
    if mask & (1 << 6):
        count = reader.u32() ^ 0xA8148251
        if count > 100_000:
            raise QuestBinDecodeError(f"implausible LAIMPNDEFCL bit-6 array count {count}")
        value["unknown_bit_6"] = [reader.u32() ^ 0xA54AB96F for _ in range(count)]
    if mask & (1 << 55):
        value["failExec"] = _read_quest_exec_array(reader)
    if mask & (1 << 35):
        value["finishCond"] = _read_quest_content_array(reader)
    if mask & (1 << 53):
        value["unknown_bit_53"] = (reader.u32() + 0xA6768BF5) & _U32_MASK
    if mask & (1 << 62):
        value["unknown_bit_62"] = reader.u8() != 0xE6
    if mask & (1 << 48):
        value["unknown_bit_48"] = reader.u8() != 0x0D
    if mask & (1 << 11):
        value["unknown_bit_11"] = reader.u32() ^ 0x5E79B226
    if mask & (1 << 12):
        value["mainId"] = (reader.u32() + 0x076F8836) & _U32_MASK
    if mask & (1 << 61):
        count = ((reader.u32() ^ 0xDFED35B0) + 0x531C2D72) & _U32_MASK
        if count > 100_000:
            raise QuestBinDecodeError(f"implausible LAIMPNDEFCL bit-61 array count {count}")
        value["unknown_bit_61"] = [
            ((reader.u32() + 0x0FBADB4A) & _U32_MASK) ^ 0x71A8931C for _ in range(count)
        ]
    if mask & (1 << 26):
        value["unknown_bit_26"] = _read_kph(reader)
    if mask & (1 << 42):
        value["unknown_bit_42"] = reader.u8() != 0xB0
    if mask & (1 << 23):
        value["unknown_bit_23"] = (reader.u32() + 0x546D0AF3) & _U32_MASK
    if mask & (1 << 31):
        count = ((reader.u32() + 0x878CF5D0) & _U32_MASK) ^ 0x4051665B
        if count > 100_000:
            raise QuestBinDecodeError(f"implausible LAIMPNDEFCL bit-31 array count {count}")
        value["unknown_bit_31"] = [
            ((reader.u32() + 0xF27104B8) & _U32_MASK) ^ 0x0BBC22AB for _ in range(count)
        ]

    return value, start, reader.pos


_OUTER_SUPPORTED_BITS = {18, 31, 35, 37, 40, 41, 44, 45, 49, 50, 59, 61}


def decode_main_quest(data: bytes, *, require_full_consumption: bool = True) -> DecodedMainQuest:
    """Decode the recovered Genshin 7.1 Data/_BinOutput/Quest/* wire.

    The current production schema is deliberately fail-closed: a presence bit whose
    reader has not yet been recovered raises QuestBinDecodeError instead of guessing
    its width or semantics.
    """

    reader = _Reader(data)
    mask = (reader.u64() + 0xB19CC79B) & _U64_MASK
    _require_supported_bits(mask, _OUTER_SUPPORTED_BITS, label="AFIOOHMJHDM", width=64)
    value: dict[str, Any] = {}

    if mask & (1 << 35):
        value["mainId"] = reader.u32() ^ 0x1A9C24BC
    if mask & (1 << 59):
        count = reader.u32() ^ 0x42B0ADDA
        if count > 100_000:
            raise QuestBinDecodeError(f"implausible AFIOOHMJHDM bit-59 array count {count}")
        value["unknown_bit_59"] = [reader.u32() ^ 0x8CA1F71F for _ in range(count)]
    if mask & (1 << 44):
        length = reader.u16() ^ 0x56EA
        value["unknown_bit_44"] = _read_raw_string(reader, length)
    if mask & (1 << 50):
        length = (reader.u16() + 0xC5A5) & 0xFFFF
        value["unknown_bit_50"] = _read_raw_string(reader, length)
    if mask & (1 << 18):
        length = (reader.u16() + 0xB085) & 0xFFFF
        value["unknown_bit_18"] = _read_raw_string(reader, length)
    if mask & (1 << 31):
        count = ((reader.u32() ^ 0xB93361B5) + 0x4FD39A66) & _U32_MASK
        if count > 100_000:
            raise QuestBinDecodeError(f"implausible AFIOOHMJHDM bit-31 array count {count}")
        value["unknown_bit_31"] = [
            (reader.u32() + 0x591049E7) & _U32_MASK for _ in range(count)
        ]
    if mask & (1 << 41):
        value["unknown_bit_41"] = (reader.u32() + 0x985FAF13) & _U32_MASK
    if mask & (1 << 61):
        value["unknown_bit_61"] = reader.u32() ^ 0x957E4B93

    row_boundaries: list[tuple[int, int, int]] = []
    if mask & (1 << 45):
        count = reader.u32() ^ 0xA74F0ACB
        if count > 100_000:
            raise QuestBinDecodeError(f"implausible MainQuest row count {count}")
        rows: list[dict[str, Any]] = []
        for _ in range(count):
            row, start, end = _read_quest_row(reader)
            sub_id = row.get("subId")
            if not isinstance(sub_id, int):
                raise QuestBinDecodeError(f"Quest row at 0x{start:X} does not contain subId")
            rows.append(row)
            row_boundaries.append((sub_id, start, end))
        value["quests"] = rows

    if mask & (1 << 49):
        count = (reader.u32() + 0x8BF0777A) & _U32_MASK
        if count > 100_000:
            raise QuestBinDecodeError(f"implausible AFIOOHMJHDM bit-49 array count {count}")
        value["unknown_bit_49"] = [
            ((reader.u64() ^ 0xA6AA5B5A) + 0x729DC4AB) & _U64_MASK for _ in range(count)
        ]
    if mask & (1 << 37):
        value["resId"] = reader.u32() ^ 0x32170514
    if mask & (1 << 40):
        value["unknown_bit_40"] = reader.u32() ^ 0x6B058DBD

    result = DecodedMainQuest(
        data=value,
        consumed=reader.pos,
        payload_size=len(data),
        row_boundaries=tuple(row_boundaries),
    )
    if require_full_consumption and not result.fully_consumed:
        raise QuestBinDecodeError(
            f"Quest BinOutput left {result.payload_size - result.consumed} unexplained byte(s) "
            f"at 0x{result.consumed:X}"
        )
    return result
