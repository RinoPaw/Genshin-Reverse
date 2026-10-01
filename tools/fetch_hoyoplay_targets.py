#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from urllib.parse import quote

import requests

API = "https://sg-hyp-api.hoyoverse.com/hyp/hyp-connect/api/getGamePackages"
LAUNCHER_ID = "VYTpXlbWo8"
GAME_ID = "gopR6Cufr3"
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


def md5_file(path: Path) -> str:
    digest = hashlib.md5()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(8 * 1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def get_major(session: requests.Session) -> dict:
    response = session.get(
        API,
        params={"launcher_id": LAUNCHER_ID, "language": "en-us"},
        timeout=60,
    )
    response.raise_for_status()
    payload = response.json()
    for package in payload.get("data", {}).get("game_packages", []):
        game = package.get("game", {})
        if game.get("id") == GAME_ID or game.get("biz") == "hk4e_global":
            return package["main"]["major"]
    raise RuntimeError("global Genshin package was not present in HoYoPlay getGamePackages")


def load_manifest(session: requests.Session, base_url: str) -> dict[str, dict]:
    response = session.get(base_url.rstrip("/") + "/pkg_version", timeout=120)
    response.raise_for_status()
    result: dict[str, dict] = {}
    for raw_line in response.text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        row = json.loads(line)
        remote = row.get("remoteName")
        if remote:
            result[str(remote)] = row
    return result


def download_target(
    session: requests.Session,
    base_url: str,
    remote_name: str,
    local_path: Path,
    manifest_row: dict,
) -> None:
    # Keep slashes as path separators and quote only unsafe path characters.
    url = base_url.rstrip("/") + "/" + quote(remote_name, safe="/._-~")
    print(f"downloading {remote_name} from {url}")
    with session.get(url, stream=True, timeout=(30, 300)) as response:
        response.raise_for_status()
        local_path.parent.mkdir(parents=True, exist_ok=True)
        with local_path.open("wb") as f:
            for chunk in response.iter_content(chunk_size=8 * 1024 * 1024):
                if chunk:
                    f.write(chunk)
    expected_size = manifest_row.get("fileSize")
    if expected_size is not None and local_path.stat().st_size != int(expected_size):
        raise RuntimeError(
            f"{remote_name}: size {local_path.stat().st_size} != manifest {expected_size}"
        )
    expected_md5 = str(manifest_row.get("md5", "")).lower()
    if expected_md5:
        actual_md5 = md5_file(local_path)
        if actual_md5 != expected_md5:
            raise RuntimeError(f"{remote_name}: md5 {actual_md5} != manifest {expected_md5}")
    print(f"wrote {local_path} ({local_path.stat().st_size} bytes)")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Fetch exact current global Genshin files through HoYoPlay's official resource list."
    )
    parser.add_argument("--version", default="7.1.0")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--expected-exe-sha256", required=True)
    parser.add_argument("--expected-metadata-sha256", required=True)
    args = parser.parse_args()

    session = requests.Session()
    session.headers.update({"User-Agent": "HYP/1.0 Genshin-Reverse/0.1"})
    major = get_major(session)
    current_version = str(major.get("version", ""))
    print("HoYoPlay global Genshin version:", current_version)
    if current_version != args.version:
        raise SystemExit(f"HoYoPlay live version {current_version!r} != requested {args.version!r}")

    base_url = str(major.get("res_list_url", "")).rstrip("/")
    if not base_url:
        raise SystemExit("HoYoPlay package has no res_list_url")
    print("resource base:", base_url)
    manifest = load_manifest(session, base_url)
    print("resource entries:", len(manifest))

    for remote, local in TARGETS:
        row = manifest.get(remote)
        if row is None:
            raise SystemExit(f"target missing from pkg_version: {remote}")
        download_target(session, base_url, remote, args.output / local, row)

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
