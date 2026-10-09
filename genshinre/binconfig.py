"""Shared bounded reads and native chunk transforms for configuration decoders."""
from __future__ import annotations

import struct


class BinaryConfigReader:
    def __init__(self, data: bytes, *, error_type: type[ValueError] = ValueError,
                 label: str = 'BinConfig'):
        self.data, self.pos = data, 0
        self.error_type, self.label = error_type, label

    def take(self, count: int) -> bytes:
        end = self.pos + count
        if count < 0 or end > len(self.data):
            raise self.error_type(f'truncated {self.label} at 0x{self.pos:X}: need {count} bytes, '
                                  f'have {len(self.data)-self.pos}')
        out = self.data[self.pos:end]
        self.pos = end
        return out

    def u8(self) -> int:
        return self.take(1)[0]

    def u16(self) -> int:
        return struct.unpack('<H', self.take(2))[0]

    def u32(self) -> int:
        return struct.unpack('<I', self.take(4))[0]

    def u64(self) -> int:
        return struct.unpack('<Q', self.take(8))[0]


def decode_native_chunks(data: bytes, key: int, op: str) -> bytes:
    """Transform zero-extended little-endian chunks, truncate the final chunk."""
    out = bytearray()
    for offset in range(0, len(data), 8):
        chunk = data[offset:offset+8]
        value = int.from_bytes(chunk, 'little')
        if op == 'xor':
            value ^= key
        elif op == 'add':
            value = (value + key) & 0xFFFFFFFFFFFFFFFF
        else:
            raise ValueError(f'unsupported native chunk operation: {op}')
        out += value.to_bytes(8, 'little')[:len(chunk)]
    return bytes(out)
