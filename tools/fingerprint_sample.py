#!/usr/bin/env python3
"""Emit stable hashes and a small format fingerprint for a local reverse-engineering input."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


def digest(path: Path, algorithm: str) -> str:
    h = hashlib.new(algorithm)
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(8 * 1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("sample", type=Path)
    parser.add_argument("--game-version")
    parser.add_argument("--region")
    parser.add_argument("--platform")
    args = parser.parse_args()

    with args.sample.open("rb") as f:
        head = f.read(32)

    out = {
        "file_name": args.sample.name,
        "size_bytes": args.sample.stat().st_size,
        "header_32_hex": head.hex(),
        "sha256": digest(args.sample, "sha256"),
        "sha1": digest(args.sample, "sha1"),
        "md5": digest(args.sample, "md5"),
    }
    if head.startswith(b"MZ"):
        out["format"] = "pe"
    elif head.startswith(b"MHY\x00"):
        out["format"] = "mhy-obfuscated-metadata"
    elif head.startswith(bytes.fromhex("af1bb1fa")):
        out["format"] = "standard-il2cpp-metadata"
    else:
        out["format"] = "unknown"

    for key in ("game_version", "region", "platform"):
        value = getattr(args, key)
        if value:
            out[key] = value

    print(json.dumps(out, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
