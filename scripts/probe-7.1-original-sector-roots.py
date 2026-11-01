#!/usr/bin/env python3
"""Verify exact Global 7.1 original sector root assets exported as Raw MonoBehaviour."""
from __future__ import annotations

import argparse
from dataclasses import asdict
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from genshinre.nativeprofile import PROFILE_71
from genshinre.sectorroot71 import parse_sector_root
from genshinre.worldsector71 import file_sha256


# Seven exact blocks identified by original-client, read-only sector-class scan.
BLOCKS = {
    "00809146": ("e3a30035239e4bb4d43045e4905d86f0e8d61e61a81709bb8e9c1cbd17b2abe6", "BW_BirdPinball"),
    "02888851": ("ce2196d8ad7f224dffac77c2cde82baeafef01f5c787b3370742ec0fce376697", "BW_ActivityPacMan_01"),
    "03531956": ("6786581c81002d3de9c2df7282c7a9971de300f710b56ef030892bb34b1ffba6", "BW_Custom_Edit01"),
    "07711412": ("4d69a9bcb7219e64ef4c3fd15a0f4b0436c9a1bacc41ed954609514a5f03c170", "BW_Act_Lantern02"),
    "07752668": ("0a3ab5b2d16abb235d1ddb32cffd25de015559cbcf1df8a31b18d83e74e35900", "BW_Private_Witch"),
    "12278082": ("cd3ca665a5ba4d883476bf441d2f786a923ece7455e10ff397b0cbbb951ea6c4", "BW_Private_Drxg"),
    "15523354": ("369330d009abea1e4df0d3f4356ecbdae0f1c981b45e08123e2016527a88f0ab", "BW_Combat_Fd_Studio"),
}


def audit(exe: Path, blocks: Path, raw_exports: Path) -> dict:
    if file_sha256(exe) != PROFILE_71.exe_sha256:
        raise ValueError("wrong Global 7.1 original EXE")
    entries = []
    for block_id, (expected_sha, world) in BLOCKS.items():
        block = blocks / f"{block_id}.blk"
        digest = file_sha256(block)
        if digest != expected_sha:
            raise ValueError(f"wrong original block {block_id}: {digest}")
        if block.open("rb").read(4) != b"Blb\x03":
            raise ValueError(f"missing original Blb3 container {block_id}")
        obj = raw_exports / f"streamer-root-{block_id}" / "MonoBehaviour" / "SECTR_StreamerRoot.dat"
        raw = obj.read_bytes()
        decoded = parse_sector_root(raw)
        if decoded.world_name != world:
            raise ValueError(f"incorrect original sector-root identity in {block_id}")
        entries.append({
            "blockId": block_id, "blockSha256": digest,
            "monoBehaviourExportRawSha256": file_sha256(obj),
            "monoBehaviourExportRawSize": len(raw),
            **asdict(decoded),
            "sectors": list(decoded.sectors),
            "blacklisted_sectors": list(decoded.blacklisted_sectors),
        })
    return {
        "schemaVersion": 1,
        "target": "Genshin Impact Global 7.1 Windows x64",
        "exeSha256": PROFILE_71.exe_sha256,
        "exporter": {
            "repo": "EIHRTeam/AnimeStudio", "release": "v1.0.0-CI",
            "windowsArchiveSha256": "c94eddbe3fe46c5c400d050591a46eb297d71ededc8c2376d685c988774ed110",
            "flags": "--game GI --types MonoBehaviour:Both --names ^SECTR_StreamerRoot$ --export_type Raw",
        },
        "verifiedRootCount": len(entries),
        "roots": entries,
        "limits": {
            "sourceSectorNameLists": "VERIFIED_ORIGINAL_SERIALIZED_BYTES",
            "scene3MondstadtInstancePosition": "UNRESOLVED",
            "originalSectorObjectTransforms": "UNRESOLVED",
            "originalColliderBindings": "UNRESOLVED",
            "safeServerRaycastEnabled": False,
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--exe", type=Path, required=True)
    parser.add_argument("--blocks", type=Path, required=True)
    parser.add_argument("--raw-exports", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    output = audit(args.exe, args.blocks, args.raw_exports)
    if args.check:
        if json.loads(args.output.read_text(encoding="utf-8")) != output:
            raise SystemExit("original sector root evidence differs from snapshot")
        print("PASS: seven exact Global 7.1 original serialized sector roots")
    else:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(output, ensure_ascii=False, indent=2)+"\n", encoding="utf-8")
        print("wrote",args.output)


if __name__ == "__main__":
    main()
