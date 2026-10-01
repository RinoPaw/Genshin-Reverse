#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
from pathlib import Path

import HoyoDL

TARGETS = (
    ("GenshinImpact.exe", "GenshinImpact.exe"),
    ("GenshinImpact_Data/Managed/Metadata/global-metadata.dat", "global-metadata.dat"),
)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(8 * 1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def download_target(client, remote_path: str, local_path: Path) -> None:
    url = client.getFileURL(remote_path)
    print(f"{remote_path}: {url}")
    response = client.downloadFile(remote_path)
    response.raise_for_status()
    local_path.parent.mkdir(parents=True, exist_ok=True)
    with local_path.open("wb") as f:
        for chunk in response.iter_content(chunk_size=8 * 1024 * 1024):
            if chunk:
                f.write(chunk)
    print(f"wrote {local_path} ({local_path.stat().st_size} bytes)")


def main() -> None:
    parser = argparse.ArgumentParser(description="Fetch the exact global Genshin 7.1 files required by Genshin-Reverse.")
    parser.add_argument("--version", default="7.1.0")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--expected-exe-sha256", required=True)
    parser.add_argument("--expected-metadata-sha256", required=True)
    args = parser.parse_args()

    client = HoyoDL(game="hk4e", version=args.version)
    for remote, local in TARGETS:
        download_target(client, remote, args.output / local)

    exe = args.output / "GenshinImpact.exe"
    metadata = args.output / "global-metadata.dat"
    exe_sha = sha256_file(exe)
    metadata_sha = sha256_file(metadata)
    print("exe sha256:", exe_sha)
    print("metadata sha256:", metadata_sha)
    if exe_sha != args.expected_exe_sha256.lower():
        raise SystemExit("global EXE SHA-256 does not match the preserved 7.1 sample")
    if metadata_sha != args.expected_metadata_sha256.lower():
        raise SystemExit("global metadata SHA-256 does not match the preserved 7.1 sample")


if __name__ == "__main__":
    main()
