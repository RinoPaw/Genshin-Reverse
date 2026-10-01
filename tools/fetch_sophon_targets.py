#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import io
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import zstandard


def read_varint(data: bytes, pos: int) -> tuple[int, int]:
    value = 0
    shift = 0
    while True:
        if pos >= len(data):
            raise ValueError("truncated protobuf varint")
        b = data[pos]
        pos += 1
        value |= (b & 0x7F) << shift
        if not b & 0x80:
            return value, pos
        shift += 7
        if shift >= 70:
            raise ValueError("protobuf varint is too long")


def fields(data: bytes):
    pos = 0
    while pos < len(data):
        key, pos = read_varint(data, pos)
        number, wire = key >> 3, key & 7
        if wire == 0:
            value, pos = read_varint(data, pos)
        elif wire == 1:
            value = data[pos : pos + 8]
            pos += 8
        elif wire == 2:
            size, pos = read_varint(data, pos)
            value = data[pos : pos + size]
            pos += size
        elif wire == 5:
            value = data[pos : pos + 4]
            pos += 4
        else:
            raise ValueError(f"unsupported protobuf wire type {wire}")
        if pos > len(data):
            raise ValueError("truncated protobuf field")
        yield number, wire, value


def text(value: bytes) -> str:
    return value.decode("utf-8")


def parse_chunk(data: bytes) -> dict[str, object]:
    row: dict[str, object] = {}
    for number, wire, value in fields(data):
        if number == 1 and wire == 2:
            row["chunk_id"] = text(value)
        elif number == 2 and wire == 2:
            row["md5"] = text(value)
        elif number == 3 and wire == 0:
            row["offset"] = int(value)
        elif number == 4 and wire == 0:
            row["compressed_size"] = int(value)
        elif number == 5 and wire == 0:
            row["uncompressed_size"] = int(value)
        elif number == 6 and wire == 0:
            row["xxhash"] = int(value)
    return row


def parse_file(data: bytes) -> dict[str, object]:
    row: dict[str, object] = {"chunks": []}
    for number, wire, value in fields(data):
        if number == 1 and wire == 2:
            row["filename"] = text(value)
        elif number == 2 and wire == 2:
            row["chunks"].append(parse_chunk(value))
        elif number == 3 and wire == 0:
            row["flags"] = int(value)
        elif number == 4 and wire == 0:
            row["size"] = int(value)
        elif number == 5 and wire == 2:
            row["md5"] = text(value)
    return row


def parse_manifest(data: bytes) -> list[dict[str, object]]:
    result = []
    for number, wire, value in fields(data):
        if number == 1 and wire == 2:
            result.append(parse_file(value))
    if not result:
        raise ValueError("decoded Sophon manifest contains no files")
    return result


def download(url: str, attempts: int = 4) -> bytes:
    error: Exception | None = None
    for attempt in range(attempts):
        try:
            request = urllib.request.Request(url, headers={"User-Agent": "Genshin-Reverse/1.0"})
            with urllib.request.urlopen(request, timeout=90) as response:
                return response.read()
        except Exception as exc:
            error = exc
            if attempt + 1 < attempts:
                time.sleep(2 ** attempt)
    raise RuntimeError(f"download failed after {attempts} attempts: {url}: {error}")


def decompress_zstd(data: bytes) -> bytes:
    with zstandard.ZstdDecompressor().stream_reader(io.BytesIO(data)) as reader:
        return reader.read()


def md5(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(8 * 1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def normalized_name(row: dict[str, object]) -> str:
    return str(row.get("filename", "")).replace("\\", "/").lower()


def choose_file(manifest: list[dict[str, object]], target: str) -> dict[str, object]:
    target_lower = target.replace("\\", "/").lower()
    exact = [row for row in manifest if normalized_name(row) == target_lower]
    if len(exact) == 1:
        return exact[0]
    basename = target_lower.rsplit("/", 1)[-1]
    suffix = [row for row in manifest if normalized_name(row).endswith("/" + basename) or normalized_name(row) == basename]
    if len(suffix) != 1:
        names = [str(row.get("filename", "")) for row in suffix[:20]]
        raise ValueError(f"target {target!r} matched {len(suffix)} manifest files: {names}")
    return suffix[0]


def choose_executable(manifest: list[dict[str, object]]) -> dict[str, object]:
    errors = []
    for name in ("GenshinImpact.exe", "YuanShen.exe"):
        try:
            return choose_file(manifest, name)
        except ValueError as exc:
            errors.append(str(exc))
    exe_names = [str(row.get("filename", "")) for row in manifest if normalized_name(row).endswith(".exe")]
    raise ValueError(f"could not locate game executable; manifest executables={exe_names[:40]}; errors={errors}")


def choose_managed_metadata(manifest: list[dict[str, object]]) -> dict[str, object]:
    candidates = [row for row in manifest if normalized_name(row).endswith("/managed/metadata/global-metadata.dat")]
    if len(candidates) != 1:
        names = [str(row.get("filename", "")) for row in candidates]
        raise ValueError(f"Managed global-metadata.dat matched {len(candidates)} files: {names}")
    return candidates[0]


def fetch_chunk(prefix: str, chunk: dict[str, object]) -> tuple[int, bytes]:
    chunk_id = str(chunk["chunk_id"])
    compressed = download(prefix.rstrip("/") + "/" + chunk_id)
    expected_compressed = int(chunk.get("compressed_size", 0) or 0)
    if expected_compressed and len(compressed) != expected_compressed:
        raise ValueError(f"chunk {chunk_id} compressed size {len(compressed)} != {expected_compressed}")
    data = decompress_zstd(compressed)
    expected_size = int(chunk.get("uncompressed_size", 0) or 0)
    if expected_size and len(data) != expected_size:
        raise ValueError(f"chunk {chunk_id} uncompressed size {len(data)} != {expected_size}")
    expected_md5 = str(chunk.get("md5", "")).lower()
    if expected_md5 and md5(data) != expected_md5:
        raise ValueError(f"chunk {chunk_id} MD5 mismatch")
    return int(chunk.get("offset", 0) or 0), data


def reconstruct(prefix: str, row: dict[str, object], output: Path, workers: int) -> None:
    size = int(row.get("size", 0) or 0)
    chunks = list(row.get("chunks", []))
    if not size or not chunks:
        raise ValueError(f"manifest row is not a regular file: {row.get('filename')}")
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("wb") as f:
        f.truncate(size)
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(fetch_chunk, prefix, chunk) for chunk in chunks]
        with output.open("r+b") as f:
            for future in as_completed(futures):
                offset, data = future.result()
                f.seek(offset)
                f.write(data)
    if output.stat().st_size != size:
        raise ValueError(f"reconstructed size mismatch for {output.name}")
    expected_md5 = str(row.get("md5", "")).lower()
    if expected_md5:
        digest = hashlib.md5()
        with output.open("rb") as f:
            for block in iter(lambda: f.read(8 * 1024 * 1024), b""):
                digest.update(block)
        if digest.hexdigest() != expected_md5:
            raise ValueError(f"final MD5 mismatch for {output.name}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Reconstruct selected 7.1 files from the official Sophon chunk CDN.")
    parser.add_argument("--manifest-url", required=True)
    parser.add_argument("--chunk-prefix", required=True)
    parser.add_argument("--manifest-md5", default="")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--expected-exe-sha256", required=True)
    parser.add_argument("--expected-metadata-sha256", required=True)
    parser.add_argument("--workers", type=int, default=8)
    args = parser.parse_args()

    raw_manifest = download(args.manifest_url)
    if args.manifest_md5 and md5(raw_manifest) != args.manifest_md5.lower():
        raise SystemExit("official Sophon manifest MD5 mismatch")
    decoded = decompress_zstd(raw_manifest)
    manifest = parse_manifest(decoded)
    print(f"manifest files: {len(manifest)}")

    exe_row = choose_executable(manifest)
    metadata_row = choose_managed_metadata(manifest)
    print("exe manifest path:", exe_row.get("filename"))
    print("metadata manifest path:", metadata_row.get("filename"))

    exe = args.output / "GenshinImpact.exe"
    metadata = args.output / "global-metadata.dat"
    reconstruct(args.chunk_prefix, exe_row, exe, args.workers)
    reconstruct(args.chunk_prefix, metadata_row, metadata, args.workers)

    exe_sha = sha256_file(exe)
    metadata_sha = sha256_file(metadata)
    print("exe sha256:", exe_sha)
    print("metadata sha256:", metadata_sha)
    if exe_sha != args.expected_exe_sha256.lower():
        raise SystemExit("reconstructed EXE SHA-256 does not match the preserved 7.1 sample")
    if metadata_sha != args.expected_metadata_sha256.lower():
        raise SystemExit("reconstructed metadata SHA-256 does not match the preserved 7.1 sample")


if __name__ == "__main__":
    main()
