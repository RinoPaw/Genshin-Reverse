from __future__ import annotations


def read_varint(data: bytes, offset: int = 0) -> tuple[int, int]:
    if offset < 0:
        raise ValueError("varint offset must be non-negative")

    value = 0
    shift = 0
    pos = offset
    while pos < len(data):
        byte = data[pos]
        pos += 1
        if shift == 63 and byte > 1:
            raise ValueError("varint exceeds 64 bits")
        value |= (byte & 0x7F) << shift
        if byte < 0x80:
            return value, pos
        shift += 7
        if shift >= 70:
            raise ValueError("varint is too long")
    raise ValueError("truncated varint")


def try_packed_varints(payload: bytes) -> list[int] | None:
    values: list[int] = []
    pos = 0
    try:
        while pos < len(payload):
            value, pos = read_varint(payload, pos)
            values.append(value)
    except ValueError:
        return None
    return values


def parse_message(data: bytes) -> list[dict[str, object]]:
    fields: list[dict[str, object]] = []
    pos = 0
    while pos < len(data):
        tag, pos = read_varint(data, pos)
        field_number = tag >> 3
        wire_type = tag & 7
        if field_number == 0:
            raise ValueError("protobuf field number 0 is invalid")

        item: dict[str, object] = {
            "field_number": field_number,
            "wire_type": wire_type,
        }

        if wire_type == 0:
            value, pos = read_varint(data, pos)
            item["value"] = value
        elif wire_type == 1:
            if pos + 8 > len(data):
                raise ValueError("truncated fixed64")
            raw = data[pos : pos + 8]
            pos += 8
            item["value_hex"] = raw.hex()
            item["value_le"] = int.from_bytes(raw, "little")
        elif wire_type == 2:
            length, pos = read_varint(data, pos)
            if pos + length > len(data):
                raise ValueError("truncated length-delimited field")
            raw = data[pos : pos + length]
            pos += length
            item["length"] = length
            item["value_hex"] = raw.hex()
            packed = try_packed_varints(raw)
            if packed is not None:
                item["packed_varints"] = packed
        elif wire_type == 5:
            if pos + 4 > len(data):
                raise ValueError("truncated fixed32")
            raw = data[pos : pos + 4]
            pos += 4
            item["value_hex"] = raw.hex()
            item["value_le"] = int.from_bytes(raw, "little")
        else:
            raise ValueError(f"unsupported protobuf wire type {wire_type}")

        fields.append(item)
    return fields
