from __future__ import annotations

import struct
from typing import Any


_U32 = 0xFFFFFFFF


class QuestActionParseError(ValueError):
    """Raised when a 7.1 Quest action-config payload does not match the recovered wire schema."""


class _Reader:
    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0

    def _need(self, size: int) -> None:
        if self.pos + size > len(self.data):
            raise QuestActionParseError(
                f"truncated Quest action-config at 0x{self.pos:X}: need {size} bytes"
            )

    def take(self, size: int) -> bytes:
        self._need(size)
        out = self.data[self.pos : self.pos + size]
        self.pos += size
        return out

    def u8(self) -> int:
        return self.take(1)[0]

    def u16(self) -> int:
        return int.from_bytes(self.take(2), "little")

    def u32(self) -> int:
        return int.from_bytes(self.take(4), "little")

    def u64(self) -> int:
        return int.from_bytes(self.take(8), "little")


def _add32(value: int, addend: int) -> int:
    return (value + addend) & _U32


def _bits(value: int, width: int) -> set[int]:
    return {bit for bit in range(width) if value & (1 << bit)}


def _float32(bits: int) -> float:
    return struct.unpack("<f", (bits & _U32).to_bytes(4, "little"))[0]


def _raw_native_string(
    reader: _Reader,
    length_decoder,
) -> str | dict[str, Any]:
    length = length_decoder(reader.u16()) & 0xFFFF
    encoded = reader.take(length)
    if not encoded:
        return ""
    # No non-empty instance is present in the observed 7.1 Quest action-config corpus.
    # Preserve bytes if a future same-version payload exercises the branch instead of
    # pretending the string cipher was recovered.
    return {"rawHex": encoded.hex(), "length": length}


def _parse_vector(reader: _Reader) -> dict[str, float]:
    """Decode native NFFDDFHHDHG (Vector3-like) at 7.1 RVA 0x13C58500."""

    raw_mask = reader.u8()
    mask = (raw_mask + 0xA7) & 0xFF
    unsupported = _bits(mask, 8) - {1, 2, 6}
    if unsupported:
        raise QuestActionParseError(
            f"unsupported action-config vector bits {sorted(unsupported)} "
            f"at 0x{reader.pos - 1:X}"
        )

    out: dict[str, float] = {}
    if mask & 0x02:
        out["y"] = _float32(_add32(reader.u32(), 0x66D8B127) ^ 0x3E98C6BE)
    if mask & 0x40:
        out["z"] = _float32(_add32(reader.u32(), 0x25F781DF))
    if mask & 0x04:
        out["x"] = _float32(reader.u32() ^ 0xDF729864)
    return out


def _parse_camera_rotate_setting(reader: _Reader) -> dict[str, Any]:
    """Decode ConfigCameraRotateSetting at 7.1 RVA 0x12D9AE50."""

    raw_mask = reader.u16()
    shifted = (raw_mask + 0x3240) & 0xFFFF
    mask = shifted ^ 0x9702
    out: dict[str, Any] = {}

    # Exact native read order.
    if mask & 0x0100:
        out["poleMinValue"] = _float32(reader.u32() ^ 0xEFD2A24B)
    if mask & 0x0002:
        out["elasticity"] = _float32(_add32(reader.u32(), 0x1DEFF698))
    if shifted & 0x4000:
        out["useElastic"] = reader.u8() != 0x8F
    if raw_mask & 0x0008:
        out["dampCurveIndex"] = (
            _add32(reader.u32(), 0x4ADB5FD1) ^ 0x8CF425A3
        ) & _U32
    if shifted & 0x0080:
        out["elevMinValue"] = _float32(
            _add32(reader.u32() ^ 0xB36FE18B, 0x989AB3D5)
        )
    if shifted & 0x2000:
        out["canRotate"] = reader.u8() != 0xA7
    if raw_mask & 0x0004:
        out["elevMaxValue"] = _float32(reader.u32() ^ 0x6EFA5DE5)
    if raw_mask & 0x0010:
        out["poleMaxValue"] = _float32(reader.u32() ^ 0xF623CE05)
    if shifted & 0x0800:
        out["elasticRatio"] = _float32(
            _add32(reader.u32() ^ 0xD225CA8F, 0x7A9FB7A0)
        )
    return out


_BASE_SUPPORTED_BITS = {0, 2, 3, 7, 14}


def _parse_base_action(
    reader: _Reader,
    *,
    type_name: str,
    expected_type_id: int,
) -> dict[str, Any]:
    """Decode the observed ConfigBaseInterAction wire fields."""

    start = reader.pos
    raw_mask = reader.u16()
    mask = (raw_mask - 0x69BA) & 0xFFFF
    active = _bits(mask, 16)
    unsupported = active - _BASE_SUPPORTED_BITS
    if unsupported:
        raise QuestActionParseError(
            f"unsupported ConfigBaseInterAction bits {sorted(unsupported)} at 0x{start:X}"
        )

    out: dict[str, Any] = {"type": type_name}

    # Exact 7.1 native read order for the observed fields.
    if 7 in active:
        out["delayTime"] = _float32(
            _add32(reader.u32(), 0x7E29FCAE) ^ 0xD31F5926
        )
    if 0 in active:
        type_id = _add32(reader.u32(), 0xF5846183)
        if type_id != expected_type_id:
            raise QuestActionParseError(
                f"unexpected ConfigBaseInterAction type {type_id} at 0x{start:X}; "
                f"expected {expected_type_id}"
            )
    if 14 in active:
        out["flag"] = (
            _add32(reader.u32() ^ 0xFA378A1B, 0xD86C13D0)
        ) & _U32
    if 2 in active:
        out["duration"] = _float32(_add32(reader.u32(), 0xAF668FC3))
    if 3 in active:
        out["actionId"] = reader.u32() ^ 0xCEDAAF63
    return out


_CAMERA_SUPPORTED_BITS = {
    1,
    2,
    8,
    9,
    12,
    19,
    21,
    26,
    28,
    29,
    40,
    45,
    48,
    49,
    52,
    56,
    57,
    62,
}

_CAMERA_EASE_NAMES = {
    0: "EaseInQuad",
    1: "EaseOutQuad",
    2: "EaseInOutQuad",
    5: "EaseInOutCubic",
    21: "Linear",
}


def _parse_camera_move_action(reader: _Reader) -> dict[str, Any]:
    out = _parse_base_action(
        reader,
        type_name="CAMERA_MOVE",
        expected_type_id=9,
    )

    start = reader.pos
    raw_mask = reader.u64()
    mask = raw_mask ^ 0x00000000A7053A8D
    active = _bits(mask, 64)
    unsupported = active - _CAMERA_SUPPORTED_BITS
    if unsupported:
        raise QuestActionParseError(
            f"unsupported GEEOEPCPODO bits {sorted(unsupported)} at 0x{start:X}"
        )

    # Exact 7.1 GEEOEPCPODO.FromBinaryInner read order for every field observed
    # in the complete Quest corpus.
    if 12 in active:
        out["AGNDLBACBLB"] = _raw_native_string(
            reader, lambda raw: raw ^ 0x0617
        )
    if 9 in active:
        out["HLGABAFOOMM"] = reader.u8() != 0x53
    if 8 in active:
        out["NMEENCOHBNC"] = reader.u8() != 0x18
    if 62 in active:
        out["camPosOffset"] = _parse_vector(reader)
    if 52 in active:
        out["NEGBDDEAAAH"] = _raw_native_string(
            reader, lambda raw: (raw + 0x9D47) & 0xFFFF
        )
    if 19 in active:
        out["needZAxisRotate"] = reader.u8() != 0x79
    if 28 in active:
        ease_id = _add32(reader.u32(), 0x490ADE52)
        try:
            out["cameraBlendType"] = _CAMERA_EASE_NAMES[ease_id]
        except KeyError as exc:
            raise QuestActionParseError(
                f"unsupported GEEOEPCPODO easing id {ease_id} at 0x{reader.pos - 4:X}"
            ) from exc
    if 26 in active:
        out["cutFrameTrans"] = _parse_camera_rotate_setting(reader)
    if 45 in active:
        out["BDPMLAKINNK"] = reader.u8() != 0x73
    if 2 in active:
        out["HOBHFEHDLOL"] = _float32(
            _add32(reader.u32() ^ 0xD4305273, 0x1BA953C7)
        )
    if 57 in active:
        out["camForwardTargetOffset"] = _parse_vector(reader)
    if 21 in active:
        out["GBCBGFBBCIE"] = _float32(_add32(reader.u32(), 0x3FF5FD83))
    if 29 in active:
        out["BEBDEGMLIPL"] = _raw_native_string(
            reader, lambda raw: (raw + 0x768E) & 0xFFFF
        )
    if 56 in active:
        out["DAHBICEBHDB"] = _raw_native_string(
            reader, lambda raw: (raw + 0x697F) & 0xFFFF
        )
    if 49 in active:
        out["DIGPJPDMJKF"] = reader.u8() != 0x73
    if 48 in active:
        out["GJHJGFODJCD"] = _float32(reader.u32() ^ 0x8ECDA52C)
    if 1 in active:
        out["lerpPattern"] = _add32(reader.u32(), 0x712EAF98)
    if 40 in active:
        out["camFov"] = _float32(reader.u32() ^ 0x04984060)

    return {"$type": "GEEOEPCPODO", **out}


def _parse_time_protect_action(reader: _Reader) -> dict[str, Any]:
    out = _parse_base_action(
        reader,
        type_name="TIME_PROTECT",
        expected_type_id=31,
    )
    return {"$type": "ConfigTimeProtectAction", **out}


def _parse_action(reader: _Reader) -> dict[str, Any]:
    start = reader.pos
    tag = (((reader.u8() + 4) & 0xFF) ^ 0xBB)
    if tag == 11:
        return _parse_camera_move_action(reader)
    if tag == 38:
        return _parse_time_protect_action(reader)
    raise QuestActionParseError(
        f"unsupported Quest action-config tag {tag} at 0x{start:X}"
    )


def _parse_action_group(reader: _Reader) -> list[dict[str, Any]]:
    start = reader.pos
    count = _add32(reader.u32(), 0x9F8C76C5)
    if count > 100_000:
        raise QuestActionParseError(
            f"implausible Quest action count {count} at 0x{start:X}"
        )
    return [_parse_action(reader) for _ in range(count)]


def _parse_action_groups(reader: _Reader) -> list[list[dict[str, Any]]]:
    start = reader.pos
    count = _add32(reader.u32(), 0x4399D4F1) ^ 0x4E8163C7
    if count > 100_000:
        raise QuestActionParseError(
            f"implausible Quest action-group count {count} at 0x{start:X}"
        )
    return [_parse_action_group(reader) for _ in range(count)]


def parse_quest_action_config(data: bytes) -> dict[str, Any]:
    """Decode AFIO bit23 (IACKBAAICMK) from Genshin 7.1 Quest BinOutput.

    The recovered corpus contains 74 MainQuest payloads, 231 sub-quest mappings,
    231 action groups and 586 actions. The native polymorphic stream contains only
    GEEOEPCPODO (CAMERA_MOVE) and ConfigTimeProtectAction (TIME_PROTECT).
    """

    reader = _Reader(data)
    root_start = reader.pos
    root_mask = reader.u8()

    mapping: dict[str, Any] = {}
    if root_mask & 0x02:
        count = _add32(reader.u32() ^ 0x61303C72, 0xA260B070)
        if count > 100_000:
            raise QuestActionParseError(
                f"implausible IACKBAAICMK entry count {count} at 0x{root_start:X}"
            )

        for _ in range(count):
            key = reader.u32() ^ 0x0938FB42
            value_mask = reader.u8()
            groups: list[list[dict[str, Any]]] = []
            if ((value_mask + 1) & 0xFF) & 0x02:
                groups = _parse_action_groups(reader)
            mapping[str(key)] = {"IMDGLPKIHCK": groups}

    if reader.pos != len(data):
        raise QuestActionParseError(
            f"Quest action-config has {len(data) - reader.pos} unexplained trailing bytes "
            f"at 0x{reader.pos:X}"
        )

    return {"KLKOKMBHCPI": mapping}
