from __future__ import annotations

import argparse
import hashlib
import io
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

from .nativeprofile import get_native_profile
from .sampleidentity import sha256_file


def read_varint(data: bytes, pos: int) -> tuple[int, int]:
    value = 0
    shift = 0
    while True:
        if pos >= len(data):
            raise ValueError("truncated protobuf varint")
        byte = data[pos]
        pos += 1
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
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
                time.sleep(2**attempt)
    raise RuntimeError(f"download failed after {attempts} attempts: {url}: {error}")


def decompress_zstd(data: bytes) -> bytes:
    try:
        import zstandard  # type: ignore[import-not-found]
    except ImportError as exc:
        raise RuntimeError(
            "Sophon sample fetching requires the optional 'zstandard' package"
        ) from exc
    with zstandard.ZstdDecompressor().stream_reader(io.BytesIO(data)) as reader:
        return reader.read()


def md5(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()


def normalized_name(row: dict[str, object]) -> str:
    return str(row.get("filename", "")).replace("\\", "/").lower()


def choose_file(manifest: list[dict[str, object]], target: str) -> dict[str, object]:
    target_lower = target.replace("\\", "/").lower()
    exact = [row for row in manifest if normalized_name(row) == target_lower]
    if len(exact) == 1:
        return exact[0]
    basename = target_lower.rsplit("/", 1)[-1]
    suffix = [
        row
        for row in manifest
        if normalized_name(row).endswith("/" + basename) or normalized_name(row) == basename
    ]
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
    exe_names = [
        str(row.get("filename", ""))
        for row in manifest
        if normalized_name(row).endswith(".exe")
    ]
    raise ValueError(
        f"could not locate game executable; manifest executables={exe_names[:40]}; errors={errors}"
    )


def choose_managed_metadata(manifest: list[dict[str, object]]) -> dict[str, object]:
    candidates = [
        row
        for row in manifest
        if normalized_name(row).endswith("/managed/metadata/global-metadata.dat")
    ]
    if len(candidates) != 1:
        names = [str(row.get("filename", "")) for row in candidates]
        raise ValueError(f"Managed global-metadata.dat matched {len(candidates)} files: {names}")
    return candidates[0]


def fetch_chunk(prefix: str, chunk: dict[str, object]) -> tuple[int, bytes]:
    chunk_id = str(chunk["chunk_id"])
    compressed = download(prefix.rstrip("/") + "/" + chunk_id)
    expected_compressed = int(chunk.get("compressed_size", 0) or 0)
    if expected_compressed and len(compressed) != expected_compressed:
        raise ValueError(
            f"chunk {chunk_id} compressed size {len(compressed)} != {expected_compressed}"
        )
    data = decompress_zstd(compressed)
    expected_size = int(chunk.get("uncompressed_size", 0) or 0)
    if expected_size and len(data) != expected_size:
        raise ValueError(
            f"chunk {chunk_id} uncompressed size {len(data)} != {expected_size}"
        )
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
    with output.open("wb") as file:
        file.truncate(size)
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(fetch_chunk, prefix, chunk) for chunk in chunks]
        with output.open("r+b") as file:
            for future in as_completed(futures):
                offset, data = future.result()
                file.seek(offset)
                file.write(data)
    if output.stat().st_size != size:
        raise ValueError(f"reconstructed size mismatch for {output.name}")
    expected_md5 = str(row.get("md5", "")).lower()
    if expected_md5:
        digest = hashlib.md5()
        with output.open("rb") as file:
            for block in iter(lambda: file.read(8 * 1024 * 1024), b""):
                digest.update(block)
        if digest.hexdigest() != expected_md5:
            raise ValueError(f"final MD5 mismatch for {output.name}")


def fetch_samples(
    *,
    manifest_url: str,
    chunk_prefix: str,
    output: Path,
    expected_exe_sha256: str,
    expected_metadata_sha256: str,
    manifest_md5: str = "",
    workers: int = 8,
) -> dict[str, Any]:
    raw_manifest = download(manifest_url)
    if manifest_md5 and md5(raw_manifest) != manifest_md5.lower():
        raise ValueError("official Sophon manifest MD5 mismatch")
    decoded = decompress_zstd(raw_manifest)
    manifest = parse_manifest(decoded)

    exe_row = choose_executable(manifest)
    metadata_row = choose_managed_metadata(manifest)
    exe = output / "GenshinImpact.exe"
    metadata = output / "global-metadata.dat"
    reconstruct(chunk_prefix, exe_row, exe, workers)
    reconstruct(chunk_prefix, metadata_row, metadata, workers)

    exe_sha = sha256_file(exe)
    metadata_sha = sha256_file(metadata)
    if exe_sha != expected_exe_sha256.lower():
        raise ValueError("reconstructed EXE SHA-256 does not match the expected sample")
    if metadata_sha != expected_metadata_sha256.lower():
        raise ValueError("reconstructed metadata SHA-256 does not match the expected sample")

    return {
        "manifest_files": len(manifest),
        "exe_manifest_path": exe_row.get("filename"),
        "metadata_manifest_path": metadata_row.get("filename"),
        "exe_sha256": exe_sha,
        "metadata_sha256": metadata_sha,
        "output": str(output),
    }


def _resolve_source(args: argparse.Namespace) -> tuple[str, str, str, str, str]:
    explicit_values = (
        args.manifest_url,
        args.chunk_prefix,
        args.expected_exe_sha256,
        args.expected_metadata_sha256,
        args.manifest_md5,
    )
    if args.profile:
        if any(explicit_values):
            raise ValueError("--profile cannot be combined with explicit Sophon source/hash options")
        profile = get_native_profile(args.profile)
        return (
            profile.sophon_manifest_url,
            profile.sophon_chunk_prefix,
            profile.exe_sha256,
            profile.metadata_sha256,
            profile.sophon_manifest_md5,
        )

    required = {
        "--manifest-url": args.manifest_url,
        "--chunk-prefix": args.chunk_prefix,
        "--expected-exe-sha256": args.expected_exe_sha256,
        "--expected-metadata-sha256": args.expected_metadata_sha256,
    }
    missing = [name for name, value in required.items() if not value]
    if missing:
        raise ValueError("explicit Sophon mode requires " + ", ".join(missing))
    return (
        args.manifest_url,
        args.chunk_prefix,
        args.expected_exe_sha256,
        args.expected_metadata_sha256,
        args.manifest_md5,
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Reconstruct exact client samples from an official Sophon chunk manifest."
    )
    parser.add_argument("--profile", help="exact native profile identity")
    parser.add_argument("--manifest-url")
    parser.add_argument("--chunk-prefix")
    parser.add_argument("--manifest-md5", default="")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--expected-exe-sha256")
    parser.add_argument("--expected-metadata-sha256")
    parser.add_argument("--workers", type=int, default=8)
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    try:
        manifest_url, chunk_prefix, exe_sha, metadata_sha, manifest_md5 = _resolve_source(args)
        result = fetch_samples(
            manifest_url=manifest_url,
            chunk_prefix=chunk_prefix,
            output=args.output,
            expected_exe_sha256=exe_sha,
            expected_metadata_sha256=metadata_sha,
            manifest_md5=manifest_md5,
            workers=args.workers,
        )
    except (KeyError, ValueError, RuntimeError) as exc:
        parser.error(str(exc))
    for key, value in result.items():
        print(f"{key}: {value}")


if __name__ == "__main__":
    main()
