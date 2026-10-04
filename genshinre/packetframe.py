from __future__ import annotations

import argparse
import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable

HEAD_MAGIC = 0x4567
TAIL_MAGIC = 0x89AB
FIXED_HEADER_SIZE = 10
FIXED_FRAME_OVERHEAD = 12


@dataclass(frozen=True)
class GamePacket:
    offset: int
    size: int
    cmd_id: int
    head_size: int
    body_size: int
    head_hex: str
    body_hex: str


def parse_frames(data: bytes) -> list[GamePacket]:
    packets: list[GamePacket] = []
    offset = 0
    while offset < len(data):
        remaining = len(data) - offset
        if remaining < FIXED_FRAME_OVERHEAD:
            raise ValueError(
                f"trailing {remaining} byte(s) at offset 0x{offset:X}; "
                "a game packet needs at least 12 bytes"
            )

        magic = int.from_bytes(data[offset : offset + 2], "big")
        if magic != HEAD_MAGIC:
            raise ValueError(
                f"bad head magic 0x{magic:04X} at offset 0x{offset:X}; "
                f"expected 0x{HEAD_MAGIC:04X}. Input must already be XOR-decrypted."
            )

        cmd_id = int.from_bytes(data[offset + 2 : offset + 4], "big")
        head_size = int.from_bytes(data[offset + 4 : offset + 6], "big")
        body_size = int.from_bytes(data[offset + 6 : offset + 10], "big")
        frame_size = FIXED_FRAME_OVERHEAD + head_size + body_size
        end = offset + frame_size
        if end > len(data):
            raise ValueError(
                f"truncated frame at offset 0x{offset:X}: declares {frame_size} bytes, "
                f"only {remaining} available"
            )

        tail = int.from_bytes(data[end - 2 : end], "big")
        if tail != TAIL_MAGIC:
            raise ValueError(
                f"bad tail magic 0x{tail:04X} for frame at offset 0x{offset:X}; "
                f"expected 0x{TAIL_MAGIC:04X}"
            )

        head_start = offset + FIXED_HEADER_SIZE
        body_start = head_start + head_size
        packets.append(
            GamePacket(
                offset=offset,
                size=frame_size,
                cmd_id=cmd_id,
                head_size=head_size,
                body_size=body_size,
                head_hex=data[head_start:body_start].hex(),
                body_hex=data[body_start : body_start + body_size].hex(),
            )
        )
        offset = end

    return packets


def parse_hex(text: str) -> bytes:
    cleaned = "".join(text.split()).replace("0x", "").replace("0X", "")
    if len(cleaned) % 2:
        raise ValueError("hex input has an odd number of digits")
    return bytes.fromhex(cleaned)


def describe_frames(data: bytes, watched_cmds: Iterable[int] = ()) -> dict[str, object]:
    watched = {int(value) for value in watched_cmds}
    rows = []
    for packet in parse_frames(data):
        row = asdict(packet)
        row["offset"] = f"0x{packet.offset:X}"
        row["watched"] = packet.cmd_id in watched
        rows.append(row)
    return {"packet_count": len(rows), "packets": rows}


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="python -m genshinre.packetframe",
        description=(
            "Parse one or more XOR-decrypted Genshin game packet frames and print their CmdIds. "
            "The input is the game packet buffer after transport XOR decryption, not raw KCP ciphertext."
        ),
    )
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--file", type=Path, help="binary file containing one or more decrypted frames")
    source.add_argument("--hex", dest="hex_data", help="decrypted frame bytes as hexadecimal")
    parser.add_argument(
        "--watch-cmd",
        action="append",
        default=[],
        help="CmdId to mark as watched; decimal or 0x-prefixed, repeatable",
    )
    args = parser.parse_args()

    data = args.file.read_bytes() if args.file is not None else parse_hex(args.hex_data)
    watched = [int(value, 0) for value in args.watch_cmd]
    print(json.dumps(describe_frames(data, watched), indent=2))


if __name__ == "__main__":
    main()
