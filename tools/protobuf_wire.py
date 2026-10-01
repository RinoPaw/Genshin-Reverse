#!/usr/bin/env python3
"""Small dependency-free protobuf wire inspector for captured packet payloads."""

from __future__ import annotations

import argparse


def read_varint(data: bytes, pos: int) -> tuple[int, int]:
    value = 0
    shift = 0
    while pos < len(data):
        byte = data[pos]
        pos += 1
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return value, pos
        shift += 7
        if shift >= 70:
            raise ValueError("varint too long")
    raise ValueError("truncated varint")


def inspect(data: bytes) -> None:
    pos = 0
    while pos < len(data):
        start = pos
        tag, pos = read_varint(data, pos)
        field = tag >> 3
        wire = tag & 7
        if wire == 0:
            value, pos = read_varint(data, pos)
            print(f"@{start:04x} field={field} wire=0 varint={value}")
        elif wire == 1:
            end = pos + 8
            if end > len(data): raise ValueError("truncated fixed64")
            print(f"@{start:04x} field={field} wire=1 fixed64={data[pos:end].hex()}")
            pos = end
        elif wire == 2:
            length, pos = read_varint(data, pos)
            end = pos + length
            if end > len(data): raise ValueError("truncated length-delimited field")
            body = data[pos:end]
            packed = ""
            try:
                values = []
                p = 0
                while p < len(body):
                    value, p = read_varint(body, p)
                    values.append(value)
                if values:
                    packed = f" packed_varints={values}"
            except ValueError:
                pass
            print(f"@{start:04x} field={field} wire=2 len={length} hex={body.hex()}{packed}")
            pos = end
        elif wire == 5:
            end = pos + 4
            if end > len(data): raise ValueError("truncated fixed32")
            print(f"@{start:04x} field={field} wire=5 fixed32={data[pos:end].hex()}")
            pos = end
        else:
            raise ValueError(f"unsupported wire type {wire} at offset {start}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("hex_payload", help="protobuf payload as hex, spaces allowed")
    args = parser.parse_args()
    inspect(bytes.fromhex(args.hex_payload))


if __name__ == "__main__":
    main()
