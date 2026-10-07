#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
import shlex
import subprocess

from genshinre.assetindex import parse_asset_index
from genshinre.nativeprofile import PROFILE_71
from genshinre.questcollect import collect_quest_payloads
from genshinre.questresources import build_quest_asset_manifest, resolve_asset_path
from genshinre.samplefetch import (
    decompress_zstd,
    download,
    normalized_name,
    parse_manifest,
    reconstruct,
)


DESIGN_INDEX_GROUP = 0
DESIGN_INDEX_BLOCK = 31049741
DESIGN_INDEX_EXPORTED_NAME = "0000006f"
MAIN_QUEST_INDEX_PATH = "Data/_BinOutput/IndexDic/MainQuestIndex"


def _manifest_row(rows, group_id: int, block_id: int):
    suffixes = (
        f"/assetbundles/blocks/{group_id:02x}/{block_id}.blk",
        f"/assetbundles/blocks/{group_id:02d}/{block_id}.blk",
    )
    matches = [
        row
        for row in rows
        if any(normalized_name(row).endswith(suffix) for suffix in suffixes)
    ]
    if len(matches) != 1:
        raise RuntimeError(
            f"block {block_id} group {group_id}: expected one manifest row, got {len(matches)}"
        )
    return matches[0]


def _reconstruct_block(rows, group_id: int, block_id: int, target: Path, workers: int):
    if target.is_file():
        return
    row = _manifest_row(rows, group_id, block_id)
    reconstruct(PROFILE_71.sophon_chunk_prefix, row, target, workers=workers)


def _run_raw_export(command: list[str], block: Path, output: Path) -> None:
    marker = output / ".complete"
    if marker.is_file():
        return
    output.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        [
            *command,
            str(block),
            str(output),
            "--game",
            "GI",
            "--export_type",
            "Raw",
            "--logger_flags",
            "Error",
        ],
        check=True,
    )
    marker.write_text("ok\n", encoding="ascii")


def _raw_object(output: Path, exported_name: str) -> Path:
    target = output / "MiHoYoBinData" / f"{exported_name}.dat"
    if not target.is_file():
        candidates = list((output / "MiHoYoBinData").glob("*.dat"))
        raise RuntimeError(
            f"missing Raw export {target}; candidates={candidates[:20]}"
        )
    return target


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Extract the exact 7.1 native MainQuest corpus and run coverage."
    )
    parser.add_argument(
        "--animestudio",
        required=True,
        help="AnimeStudio CLI command, e.g. /path/AnimeStudio.CLI or 'dotnet /path/AnimeStudio.CLI.dll'",
    )
    parser.add_argument("--workdir", type=Path, default=Path("quest-batch-7.1"))
    parser.add_argument("--workers", type=int, default=8)
    args = parser.parse_args()

    command = shlex.split(args.animestudio)
    if not command:
        parser.error("--animestudio command is empty")

    root = args.workdir
    blocks = root / "blocks"
    exports = root / "exports"
    payloads = root / "payloads"
    root.mkdir(parents=True, exist_ok=True)

    rows = parse_manifest(decompress_zstd(download(PROFILE_71.sophon_manifest_url)))

    design_block = blocks / str(DESIGN_INDEX_GROUP) / f"{DESIGN_INDEX_BLOCK}.blk"
    _reconstruct_block(
        rows,
        DESIGN_INDEX_GROUP,
        DESIGN_INDEX_BLOCK,
        design_block,
        args.workers,
    )
    design_output = root / "design-index-export"
    _run_raw_export(command, design_block, design_output)
    design_raw = _raw_object(design_output, DESIGN_INDEX_EXPORTED_NAME)
    design_index = parse_asset_index(design_raw.read_bytes())

    main_index_location = resolve_asset_path(design_index, MAIN_QUEST_INDEX_PATH)
    main_index_block = (
        blocks
        / str(main_index_location.group_id)
        / f"{main_index_location.block_id}.blk"
    )
    _reconstruct_block(
        rows,
        main_index_location.group_id,
        main_index_location.block_id,
        main_index_block,
        args.workers,
    )
    main_index_output = root / "mainquest-index-export"
    _run_raw_export(command, main_index_block, main_index_output)
    main_index_raw = _raw_object(main_index_output, main_index_location.exported_name)

    asset_manifest = build_quest_asset_manifest(
        design_raw.read_bytes(),
        main_index_raw.read_bytes(),
    )
    manifest_path = root / "quest-assets.json"
    manifest_path.write_text(
        json.dumps(asset_manifest, indent=2, ensure_ascii=False, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    for item in asset_manifest["blocks"]:
        group_id = int(item["groupId"])
        block_id = int(item["blockId"])
        block = blocks / str(group_id) / f"{block_id}.blk"
        _reconstruct_block(rows, group_id, block_id, block, args.workers)
        output = exports / str(group_id) / str(block_id)
        _run_raw_export(command, block, output)

    result = collect_quest_payloads(
        manifest_path,
        exports,
        payloads,
        coverage_path=root / "coverage.json",
    )
    (root / "summary.json").write_text(
        json.dumps(result, indent=2, ensure_ascii=False, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(
        json.dumps(
            {
                "assets": result["expected"],
                "collected": result["collected"],
                "fullConsumed": result["coverage"]["fullConsumed"],
                "failed": result["coverage"]["failed"],
                "workdir": str(root),
            },
            indent=2,
            ensure_ascii=False,
        )
    )


if __name__ == "__main__":
    main()
