from __future__ import annotations

from dataclasses import dataclass
import struct
from typing import Any

from .assetindex import AssetIndex, mihoyo_name_hash, parse_asset_index, unwrap_mihoyo_bin_data


_U32 = 0xFFFFFFFF
_U64 = 0xFFFFFFFFFFFFFFFF
_LOW40 = (1 << 40) - 1


class QuestResourceIndexError(ValueError):
    """Raised when the exact 7.1 MainQuest resource indexes violate known framing."""


@dataclass(frozen=True)
class MainQuestIndexEntry:
    index: int
    main_id: int
    handle: int


@dataclass(frozen=True)
class IndexedAssetLocation:
    path: str
    path_hash: int
    exported_name: str
    sub_asset_id: int
    block_id: int
    group_id: int
    unknown0: int
    unknown1: int


@dataclass(frozen=True)
class QuestAssetLocation:
    main_id: int
    handle: int
    path_hash: int
    exported_name: str
    sub_asset_id: int
    block_id: int
    group_id: int
    unknown0: int
    unknown1: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "mainId": self.main_id,
            "handle": self.handle,
            "handleHex": f"0x{self.handle:016X}",
            "path": f"Data/_BinOutput/Quest/{self.main_id}",
            "pathHash": f"0x{self.path_hash:010X}",
            "exportedName": self.exported_name,
            "subAssetId": self.sub_asset_id,
            "blockId": self.block_id,
            "groupId": self.group_id,
            "unknown0": self.unknown0,
            "unknown1": self.unknown1,
        }


def parse_main_quest_index(
    data: bytes,
    *,
    raw_export: bool = True,
) -> tuple[MainQuestIndexEntry, ...]:
    """Decode exact 7.1 Data/_BinOutput/IndexDic/MainQuestIndex framing."""

    payload = unwrap_mihoyo_bin_data(data) if raw_export else data
    if len(payload) < 4:
        raise QuestResourceIndexError("truncated MainQuestIndex payload")

    encoded_count = struct.unpack_from("<I", payload, 0)[0]
    count = ((encoded_count ^ 0x5785D208) + 0x0A34766E) & _U32
    expected = 4 + count * 12
    if expected != len(payload):
        raise QuestResourceIndexError(
            f"MainQuestIndex framing mismatch: count={count} expected={expected} "
            f"actual={len(payload)}"
        )

    rows: list[MainQuestIndexEntry] = []
    seen: set[int] = set()
    pos = 4
    for index in range(count):
        encoded_id = struct.unpack_from("<I", payload, pos)[0]
        encoded_handle = struct.unpack_from("<Q", payload, pos + 4)[0]
        pos += 12

        main_id = encoded_id ^ 0x92C938B5
        handle = (encoded_handle + 0x2B6567EA) & _U64
        if main_id in seen:
            raise QuestResourceIndexError(f"duplicate MainQuestIndex mainId {main_id}")
        seen.add(main_id)
        rows.append(MainQuestIndexEntry(index=index, main_id=main_id, handle=handle))

    return tuple(rows)


def resolve_asset_path(design_index: AssetIndex, path: str) -> IndexedAssetLocation:
    path_hash = mihoyo_name_hash(path)
    name = design_index.name_for_hash(path_hash)
    ref = design_index.block_ref_for_asset(name.sub_asset_id)
    try:
        group_id = design_index.block_groups[ref.block_id]
    except KeyError as exc:
        raise QuestResourceIndexError(
            f"{path}: block {ref.block_id} has no group"
        ) from exc
    return IndexedAssetLocation(
        path=path,
        path_hash=path_hash,
        exported_name=name.exported_name,
        sub_asset_id=name.sub_asset_id,
        block_id=ref.block_id,
        group_id=group_id,
        unknown0=ref.unknown0,
        unknown1=ref.unknown1,
    )


def resolve_main_quest_assets(
    entries: tuple[MainQuestIndexEntry, ...],
    design_index: AssetIndex,
) -> tuple[QuestAssetLocation, ...]:
    """Resolve every MainQuest handle to its exact design AssetIndex block location."""

    out: list[QuestAssetLocation] = []
    for entry in entries:
        path = f"Data/_BinOutput/Quest/{entry.main_id}"
        expected_hash = mihoyo_name_hash(path)
        low40 = entry.handle & _LOW40
        if low40 != expected_hash:
            raise QuestResourceIndexError(
                f"mainId {entry.main_id}: handle low40 0x{low40:010X} does not match "
                f"{path} hash 0x{expected_hash:010X}"
            )

        location = resolve_asset_path(design_index, path)
        out.append(
            QuestAssetLocation(
                main_id=entry.main_id,
                handle=entry.handle,
                path_hash=low40,
                exported_name=location.exported_name,
                sub_asset_id=location.sub_asset_id,
                block_id=location.block_id,
                group_id=location.group_id,
                unknown0=location.unknown0,
                unknown1=location.unknown1,
            )
        )

    return tuple(out)


def build_quest_asset_manifest(
    design_asset_index_raw: bytes,
    main_quest_index_raw: bytes,
) -> dict[str, Any]:
    """Build a machine-readable extraction plan from exact raw MiHoYoBinData exports."""

    design_index = parse_asset_index(design_asset_index_raw)
    entries = parse_main_quest_index(main_quest_index_raw)
    locations = resolve_main_quest_assets(entries, design_index)
    unique_blocks = sorted({(item.group_id, item.block_id) for item in locations})
    return {
        "count": len(locations),
        "uniqueBlocks": len(unique_blocks),
        "blocks": [
            {"groupId": group_id, "blockId": block_id}
            for group_id, block_id in unique_blocks
        ],
        "assets": [item.to_dict() for item in locations],
    }
