#!/usr/bin/env python3
"""Reproduce bounded 7.1 Global chest asset evidence from pinned Sophon blocks.

Requires the official block fetcher output, the pinned AnimeStudio Linux CLI
release archive, and dotnet 10.0. Never commits proprietary asset bytes.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
from importlib import util
import io
import json
from pathlib import Path, PurePosixPath
import subprocess
import tarfile

from genshinre.assetindex import unwrap_mihoyo_bin_data

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/fetch-7.1-design-blocks.py"
_spec = util.spec_from_file_location("pinned_chest_design_blocks_71", SCRIPT)
blocks = util.module_from_spec(_spec)
_spec.loader.exec_module(blocks)

PROBE = ROOT / "scripts/probe-7.1-chest-native-assets.py"
_probe_spec = util.spec_from_file_location("chest_asset_probe_71", PROBE)
probe = util.module_from_spec(_probe_spec)
_probe_spec.loader.exec_module(probe)

CLI_ARCHIVE_SHA256 = "12e2dfb2ab35880eda4274fcd393091d47e204d4b6e4b5838421fa3b4d1720a1"
QUEST_PAYLOAD_SHA256 = "07ab4816ee1eaa68fefd636b92dcfa923fe58a15731d18de0c0fb26863791fe5"


def unpack_pinned_cli(archive: Path, output: Path) -> Path:
    if blocks.hash_file(archive, "sha256") != CLI_ARCHIVE_SHA256:
        raise ValueError("AnimeStudio archive SHA-256 mismatch")
    output.mkdir(parents=True, exist_ok=True)
    dlls: list[Path] = []
    with tarfile.open(archive, mode="r:gz") as tar:
        for member in tar:
            # Official CLI tarballs may contain a harmless root-directory
            # entry ".". Never extract or traverse it as a file.
            if member.isdir() and member.name in (".", "./"):
                continue
            name = PurePosixPath(member.name)
            if (not name.parts or name.is_absolute()
                    or any(part in ("..", ".") for part in name.parts)
                    or not (member.isfile() or member.isdir())):
                raise ValueError(f"unexpected CLI archive member {member.name!r}")
            dest = output.joinpath(*name.parts)
            if member.isdir():
                dest.mkdir(parents=True, exist_ok=True)
                continue
            dest.parent.mkdir(parents=True, exist_ok=True)
            source = tar.extractfile(member)
            if source is None:
                raise ValueError(f"missing archive payload for {member.name}")
            with source, dest.open("wb") as target:
                while chunk := source.read(1024 * 1024):
                    target.write(chunk)
            if dest.name == "AnimeStudio.CLI.dll":
                dlls.append(dest)
    if len(dlls) != 1:
        raise ValueError(f"expected exactly one AnimeStudio.CLI.dll; got {len(dlls)}")
    return dlls[0]


def examine(block_dir: Path, cli_archive: Path, work_dir: Path) -> dict:
    source_blocks = [blocks.verify(block_dir / f"{key}.blk", key)
                     for key in blocks.BLOCKS]
    dll = unpack_pinned_cli(cli_archive, work_dir / "tool")
    for row in source_blocks:
        block_id = row["blockId"]
        raw_export = work_dir / f"export-{block_id}"
        subprocess.run([
            "dotnet", str(dll), str(block_dir / f"{block_id}.blk"), str(raw_export),
            "--game", "GI", "--types", "MiHoYoBinData",
            "--export_type", "Raw", "--logger_flags", "Error",
        ], check=True)

    index = work_dir / "export-31049741" / "MiHoYoBinData" / "0000006f.dat"
    report = probe.run(index.read_bytes())
    # An independently published Quest table fingerprint checks the producer
    # and the second exported block before trusting *any* candidate assets.
    quest = report["controls"][0]
    if (quest["status"] != "HASH_RESOLVED" or quest["blockId"] != 25539185):
        raise ValueError("Quest path control points to an unexpected block")
    raw_quest = (work_dir / "export-25539185" / "MiHoYoBinData"
                 / (quest["exportedName"] + ".dat")).read_bytes()
    if hashlib.sha256(unwrap_mihoyo_bin_data(raw_quest)).hexdigest() != QUEST_PAYLOAD_SHA256:
        raise ValueError("pinned Quest export payload SHA-256 mismatch")

    # Each index hit must be read only from its own confirmed block export.
    # Hits in other blocks stay unresolved and never inherit another block's bytes.
    exports = []
    for group in report["groups"].values():
        for hit in group:
            if hit["status"] != "HASH_RESOLVED":
                continue
            block_id = hit["blockId"]
            if block_id not in blocks.BLOCKS or hit["groupId"] != 0:
                exports.append({
                    "candidatePath": hit["path"], "pathHash": hit["pathHash"],
                    "groupId": hit["groupId"], "blockId": block_id,
                    "status": "SOURCE_BLOCK_NOT_ACQUIRED",
                })
                continue
            minimal_report = {"groups": {"single": [hit]}}
            items = probe.inspect_candidate_exports(
                minimal_report, work_dir / f"export-{block_id}", strict=True)["exports"]
            exports.extend(items)

    report["candidateRawExports"] = {
        "status": "PINNED_BLOCK_EXPORTS__SCHEMA_AND_SERVER_REWARD_UNVERIFIED",
        "statusCounts": dict(sorted(Counter(row["status"] for row in exports).items())),
        "exports": exports,
    }
    report["reproduction"] = {
        "officialManifestUrl": blocks.PROFILE_71.sophon_manifest_url,
        "sourceBlocks": source_blocks,
        "exporter": "EIHRTeam/AnimeStudio v1.0.0-CI Linux x64",
        "exporterArchiveSha256": CLI_ARCHIVE_SHA256,
        "commandArguments": "--game GI --types MiHoYoBinData --export_type Raw --logger_flags Error",
        "questPayloadControlSha256": QUEST_PAYLOAD_SHA256,
        "indexRawExportSha256": probe.INDEX_SHA256,
    }
    report["limitations"].extend([
        "Exported binary assets are local and must not be committed.",
        "Exact block identity and exported payload hashes do not prove a decoded Gadget schema.",
        "Nothing here authenticates server-only chest selectors or reward probabilities.",
    ])
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--blocks", type=Path, required=True)
    parser.add_argument("--cli-archive", type=Path, required=True)
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    result = examine(args.blocks, args.cli_archive, args.work)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n",
                           encoding="utf-8")
    print(json.dumps({
        "indexRawExportSha256": result["indexExportSha256"],
        "candidateStatusCounts": result["candidateStatusCounts"],
        "rawExportStatusCounts": result["candidateRawExports"]["statusCounts"],
        "groups": {name: [item for item in group
                         if item["status"] != "HASH_ABSENT"]
                   for name, group in result["groups"].items()},
    }, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
