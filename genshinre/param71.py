from __future__ import annotations

MASK32 = 0xFFFFFFFF
MASK64 = 0xFFFFFFFFFFFFFFFF
PARAMETER_RECORD_SIZE = 8


def parameter_key(index: int) -> int:
    """Recover the per-parameter key used by the exact 7.1 Global Windows x64 client."""
    x = (int(index) * 0xA291) & MASK64
    x = (x + 0x48B5FFB1) & MASK64
    x ^= 0x19E1D47A
    x = (x * 0x56E732D7) & MASK64
    return (((x >> 0x15) & MASK32) + 0x7B48E804) & MASK32


def decode_parameter_record(record: bytes, index: int) -> dict[str, int]:
    if len(record) < PARAMETER_RECORD_SIZE:
        raise ValueError("truncated 7.1 parameter record")
    raw_type = int.from_bytes(record[0:4], "little", signed=False)
    raw_name = int.from_bytes(record[4:8], "little", signed=False)
    key = parameter_key(index)
    type_index = raw_type ^ key ^ 0x31BF59F3
    name_token = (((raw_name + 0x96D3F6A4) & MASK32) ^ key ^ 0x4CDBD093) & MASK32
    return {
        "type_index": type_index & MASK32,
        "name_token": name_token,
        "key": key,
    }
