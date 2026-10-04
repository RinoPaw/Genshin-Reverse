from __future__ import annotations

from dataclasses import dataclass
import struct
from typing import Iterable


@dataclass(frozen=True)
class XmfAsset:
    name: str
    offset: int
    size: int


@dataclass(frozen=True)
class XmfBlock:
    digest: bytes
    unique_id: tuple[int, int, int]
    size: int
    assets: tuple[XmfAsset, ...]

    @property
    def digest_hex(self) -> str:
        # The reference parser treats an all-zero upper half as a 64-bit identity.
        value = self.digest[:8] if self.digest[8:] == b"\x00" * 8 else self.digest
        return value.hex()


@dataclass(frozen=True)
class XmfIndex:
    signature: bytes
    unknown: int
    version: tuple[int, int, int, int]
    blocks: tuple[XmfBlock, ...]
    trailing: bytes = b""

    def assets(self) -> Iterable[tuple[int, XmfBlock, XmfAsset]]:
        for block_index, block in enumerate(self.blocks):
            for asset in block.assets:
                yield block_index, block, asset


class _Reader:
    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0

    def _take(self, count: int) -> bytes:
        end = self.pos + count
        if count < 0 or end > len(self.data):
            raise ValueError(
                f"truncated XMF at 0x{self.pos:x}: need {count} bytes, "
                f"have {len(self.data) - self.pos}"
            )
        value = self.data[self.pos:end]
        self.pos = end
        return value

    def u8(self) -> int:
        return self._take(1)[0]

    def i16be(self) -> int:
        return struct.unpack(">h", self._take(2))[0]

    def u32be(self) -> int:
        return struct.unpack(">I", self._take(4))[0]

    def i32be(self) -> int:
        return struct.unpack(">i", self._take(4))[0]

    def i32le(self) -> int:
        return struct.unpack("<i", self._take(4))[0]


def parse_xmf(data: bytes, *, metadata_only: bool = False) -> XmfIndex:
    """Parse a HoYoverse XMF block index.

    The layout follows the XMF metadata format used by HoYoverse AssetBundle
    containers: a little-endian fixed header followed by a big-endian block
    table.  Normal indexes additionally store asset-name/offset entries per
    block.  ``metadata_only=True`` parses only the block headers.

    This parser intentionally rejects malformed sizes, offsets, duplicate
    ordering, and undecodable names so extraction code cannot silently slice a
    wrong block.
    """

    reader = _Reader(data)
    signature = reader._take(16)
    unknown = reader.i32le()
    version = (reader.i32le(), reader.i32le(), reader.i32le(), reader.u8())
    if any(component < 0 or component > 0x40 for component in version):
        raise ValueError(f"implausible XMF version {version}")

    block_count = reader.u32be()
    # A corrupt endian interpretation can turn a small table into billions of
    # rows.  Reject it before allocating or walking off the input.
    if block_count > 1_000_000:
        raise ValueError(f"implausible XMF block count {block_count}")

    blocks: list[XmfBlock] = []
    for block_index in range(block_count):
        digest = reader._take(16)
        unique_id = (reader.i32be(), reader.i32be(), reader.i32be())
        block_size = reader.i32be()
        if block_size < 0:
            raise ValueError(f"negative block size at index {block_index}: {block_size}")

        if metadata_only:
            blocks.append(XmfBlock(digest, unique_id, block_size, ()))
            continue

        asset_count = reader.u32be()
        if asset_count > 10_000_000:
            raise ValueError(
                f"implausible XMF asset count at block {block_index}: {asset_count}"
            )

        names_and_offsets: list[tuple[str, int]] = []
        previous_offset = -1
        for asset_index in range(asset_count):
            name_length = reader.i16be()
            if name_length < 0 or name_length > 0x7FFF:
                raise ValueError(
                    f"invalid asset name length at block {block_index}, "
                    f"asset {asset_index}: {name_length}"
                )
            raw_name = reader._take(name_length)
            try:
                name = raw_name.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise ValueError(
                    f"asset name is not UTF-8 at block {block_index}, asset {asset_index}"
                ) from exc
            offset = reader.u32be()
            if offset < previous_offset:
                raise ValueError(
                    f"asset offsets are not monotonic at block {block_index}: "
                    f"{offset} < {previous_offset}"
                )
            if offset > block_size:
                raise ValueError(
                    f"asset offset outside block {block_index}: {offset} > {block_size}"
                )
            names_and_offsets.append((name, offset))
            previous_offset = offset

        assets: list[XmfAsset] = []
        for asset_index, (name, offset) in enumerate(names_and_offsets):
            end = (
                names_and_offsets[asset_index + 1][1]
                if asset_index + 1 < len(names_and_offsets)
                else block_size
            )
            assets.append(XmfAsset(name=name, offset=offset, size=end - offset))
        blocks.append(XmfBlock(digest, unique_id, block_size, tuple(assets)))

    return XmfIndex(
        signature=signature,
        unknown=unknown,
        version=version,
        blocks=tuple(blocks),
        trailing=data[reader.pos :],
    )
