#!/usr/bin/env python3
"""Fetch only the two pinned 7.1 Global design blocks needed for chest path research.

The official Sophon manifest supplies chunks. Independent recorded block MD5,
size and SHA-256 prevent a later manifest or different game build from silently
being accepted. No client resources are committed.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from genshinre.nativeprofile import PROFILE_71
from genshinre.samplefetch import (
    choose_file, decompress_zstd, download, parse_manifest, reconstruct,
)

BLOCKS = {
    31049741: (2464870, "a390222739d22aafb110019d10bff7e8",
               "7364cb91628b27fd299bef6a8d3e5f58b618552a63f118fe1107da2ae57d0504"),
    25539185: (25812595, "8ce0bb0ac5ec42315f0f98d52e5d7c73",
               "afa9512cf4fb5d629558cd972b48b104752fa56d8a9f440f71dd8110d2121bf7"),
}
PREFIX = "GenshinImpact_Data/StreamingAssets/AssetBundles/blocks/00/"


def hash_file(path: Path, algorithm: str) -> str:
    digest = hashlib.new(algorithm)
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def verify(path: Path, block_id: int) -> dict:
    size, expected_md5, expected_sha256 = BLOCKS[block_id]
    if path.stat().st_size != size:
        raise ValueError(f"block {block_id} size mismatch")
    actual_md5 = hash_file(path, "md5")
    actual_sha256 = hash_file(path, "sha256")
    if actual_md5 != expected_md5 or actual_sha256 != expected_sha256:
        raise ValueError(f"block {block_id} identity mismatch")
    return {
        "blockId": block_id, "groupId": 0, "manifestPath": PREFIX + f"{block_id}.blk",
        "size": size, "md5": actual_md5, "sha256": actual_sha256,
    }


def fetch_blocks(output: Path, *, workers: int = 8) -> dict:
    if workers < 1:
        raise ValueError("workers must be positive")
    raw_manifest = download(PROFILE_71.sophon_manifest_url)
    manifest = parse_manifest(decompress_zstd(raw_manifest))
    output.mkdir(parents=True, exist_ok=True)
    blocks = []
    for block_id in BLOCKS:
        row = choose_file(manifest, PREFIX + f"{block_id}.blk")
        if str(row.get("filename", "")).replace("\\", "/").lower() != (
                PREFIX + f"{block_id}.blk").lower():
            raise ValueError(f"unexpected manifest path for block {block_id}")
        path = output / f"{block_id}.blk"
        if not path.is_file():
            staging = output / f"{block_id}.blk.partial"
            try:
                reconstruct(PROFILE_71.sophon_chunk_prefix, row, staging, workers)
                verify(staging, block_id)
                staging.replace(path)
            finally:
                staging.unlink(missing_ok=True)
        blocks.append(verify(path, block_id))
    return {
        "status": "OFFICIAL_SOPHON_BLOCK_IDENTITIES_VERIFIED__CONTENTS_NOT_INTERPRETED",
        "sample": PROFILE_71.identity,
        "manifestUrl": PROFILE_71.sophon_manifest_url,
        "manifestCompressedSha256": hashlib.sha256(raw_manifest).hexdigest(),
        "blocks": blocks,
        "limitation": "Verified source blocks do not authenticate decoded gadget fields or server-only loot.",
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--workers", type=int, default=8)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    result = fetch_blocks(args.output, workers=args.workers)
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
