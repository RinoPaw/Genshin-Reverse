from __future__ import annotations

from dataclasses import dataclass
import hashlib
import struct


@dataclass(frozen=True)
class AssetNameHash:
    path_hash_pre: int
    path_hash_last: int
    sub_asset_id: int

    @property
    def value(self) -> int:
        return (self.path_hash_last << 8) | self.path_hash_pre

    @property
    def exported_name(self) -> str:
        return f"{self.path_hash_last:08x}"


@dataclass(frozen=True)
class AssetBlockRef:
    asset_id: int
    block_id: int
    unknown0: int
    unknown1: int


@dataclass(frozen=True)
class AssetIndex:
    names: tuple[AssetNameHash, ...]
    block_groups: dict[int, int]
    block_refs: tuple[AssetBlockRef, ...]
    sort_list: tuple[int, ...]

    def name_for_hash(self, value: int) -> AssetNameHash:
        matches = [item for item in self.names if item.value == value]
        if len(matches) != 1:
            raise KeyError(f"expected one name record for hash 0x{value:010X}, got {len(matches)}")
        return matches[0]

    def names_for_sub_asset(self, sub_asset_id: int) -> tuple[AssetNameHash, ...]:
        return tuple(item for item in self.names if item.sub_asset_id == sub_asset_id)

    def block_ref_for_asset(self, asset_id: int) -> AssetBlockRef:
        matches = [item for item in self.block_refs if item.asset_id == asset_id]
        if len(matches) != 1:
            raise KeyError(f"expected one block reference for asset {asset_id}, got {len(matches)}")
        return matches[0]


class _Reader:
    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0

    def take(self, count: int) -> bytes:
        end = self.pos + count
        if count < 0 or end > len(self.data):
            raise ValueError(
                f"truncated asset index at 0x{self.pos:x}: need {count} bytes, "
                f"have {len(self.data) - self.pos}"
            )
        out = self.data[self.pos:end]
        self.pos = end
        return out

    def u8(self) -> int:
        return self.take(1)[0]

    def u32(self) -> int:
        return struct.unpack("<I", self.take(4))[0]

    def string(self) -> str:
        length = self.u32()
        try:
            return self.take(length).decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError(f"invalid UTF-8 asset-index string at 0x{self.pos - length:x}") from exc


def unwrap_mihoyo_bin_data(data: bytes) -> bytes:
    """Remove the Raw-export length prefix used by MiHoYoBinData objects."""
    if len(data) < 4:
        raise ValueError("MiHoYoBinData export is shorter than its length prefix")
    size = struct.unpack_from("<I", data)[0]
    end = 4 + size
    if end > len(data):
        raise ValueError(f"MiHoYoBinData declares {size} bytes, only {len(data) - 4} remain")
    trailing = data[end:]
    if trailing.strip(b"\0"):
        raise ValueError(f"unexpected non-zero MiHoYoBinData padding: {trailing.hex()}")
    return data[4:end]


def mihoyo_name_hash(path: str, type_suffix: str = ".MiHoYoBinData") -> int:
    """Compute the 40-bit asset-name hash used by current design asset indexes."""
    raw = (path + type_suffix).encode("ascii")
    padded_size = ((len(raw) >> 8) + 1) << 8
    digest = hashlib.md5(raw.ljust(padded_size, b"\0")).digest()
    return int.from_bytes(digest[:5], "little")


def parse_asset_index(data: bytes, *, raw_export: bool = True) -> AssetIndex:
    """Parse the observed Genshin 7.1 AssetBundle asset-index payload.

    The layout remains close to the Dedicatus545/YSAssetIdx family. Genshin 7.1
    adds a second u32 after the dependency count and stores two trailing u32s in
    every asset-to-block record. Their meaning is still unknown; the observed
    7.1 design index has both words set to zero for all 536 records, so they must
    not be treated as byte offsets or sizes without further evidence.
    """
    payload = unwrap_mihoyo_bin_data(data) if raw_export else data
    reader = _Reader(payload)

    type_count = reader.u32()
    if type_count > 100_000:
        raise ValueError(f"implausible asset-index type count {type_count}")
    for _ in range(type_count):
        reader.string()
        reader.string()

    name_count = reader.u32()
    if name_count > 20_000_000:
        raise ValueError(f"implausible asset-index name count {name_count}")
    names: list[AssetNameHash] = []
    for _ in range(name_count):
        path_hash_pre = reader.u8()
        path_hash_last = reader.u32()
        magic = reader.take(5)
        sub_asset_id = reader.u32()
        if magic[3] == 2:
            reader.take(5)
        names.append(AssetNameHash(path_hash_pre, path_hash_last, sub_asset_id))

    dependency_count = reader.u32()
    reader.u32()
    reader.u32()
    for _ in range(dependency_count):
        reader.u32()
        count = reader.u32()
        if count > 1_000_000:
            raise ValueError(f"implausible dependency list length {count}")
        reader.take(count * 4)

    preload_count = reader.u32()
    reader.take(preload_count * 4)
    shader_preload_count = reader.u32()
    reader.take(shader_preload_count * 4)

    block_group_count = reader.u32()
    block_groups: dict[int, int] = {}
    for _ in range(block_group_count):
        group_id = reader.u32()
        block_count = reader.u32()
        for _ in range(block_count):
            block_id = reader.u32()
            reader.take(2)
            if block_id in block_groups:
                raise ValueError(f"duplicate block id {block_id}")
            block_groups[block_id] = group_id

    block_info_count = reader.u32()
    block_refs: list[AssetBlockRef] = []
    for _ in range(block_info_count):
        block_id = reader.u32()
        ref_count = reader.u32()
        for _ in range(ref_count):
            asset_id = reader.u32()
            unknown0 = reader.u32()
            unknown1 = reader.u32()
            block_refs.append(AssetBlockRef(asset_id, block_id, unknown0, unknown1))

    sort_count = reader.u32()
    sort_list = tuple(reader.u32() for _ in range(sort_count))
    if reader.pos != len(payload):
        raise ValueError(
            f"asset index has {len(payload) - reader.pos} unexplained trailing bytes "
            f"at 0x{reader.pos:x}"
        )

    return AssetIndex(tuple(names), block_groups, tuple(block_refs), sort_list)
