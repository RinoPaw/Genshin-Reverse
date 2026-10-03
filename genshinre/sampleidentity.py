from __future__ import annotations

import hashlib
from pathlib import Path

from .nativeprofile import NativeProfile


def sha256_file(path: Path, *, chunk_size: int = 8 * 1024 * 1024) -> str:
    if chunk_size <= 0:
        raise ValueError("chunk_size must be positive")
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(chunk_size), b""):
            digest.update(chunk)
    return digest.hexdigest()


def require_sha256(path: Path, expected_sha256: str, *, label: str | None = None) -> str:
    expected = expected_sha256.strip().lower()
    if len(expected) != 64:
        raise ValueError("expected_sha256 must be a 64-character hexadecimal digest")
    try:
        int(expected, 16)
    except ValueError as exc:
        raise ValueError("expected_sha256 must be hexadecimal") from exc

    actual = sha256_file(path)
    if actual != expected:
        name = label or path.name
        raise ValueError(
            f"unexpected {name} SHA-256: {actual}; expected {expected}"
        )
    return actual


def require_profile_exe(path: Path, profile: NativeProfile) -> str:
    return require_sha256(path, profile.exe_sha256, label="GenshinImpact.exe")


def require_profile_metadata(path: Path, profile: NativeProfile) -> str:
    return require_sha256(path, profile.metadata_sha256, label="global-metadata.dat")
