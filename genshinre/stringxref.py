from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from .pe import PEImage
from .pointerxref import scan_pointer_xrefs
from .xrefs import scan_rip_xrefs, write_json


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(8 * 1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _encoded_literal(literal: str, encoding: str) -> bytes:
    if encoding == "ascii":
        return literal.encode("ascii")
    if encoding == "utf-16le":
        return literal.encode("utf-16le")
    raise ValueError(f"unsupported literal encoding: {encoding}")


def find_pe_string_hits(
    exe: Path,
    literal: str,
    *,
    encodings: tuple[str, ...] = ("ascii", "utf-16le"),
) -> list[dict[str, object]]:
    """Find exact encoded literal bytes in file-backed PE sections."""

    rows: list[dict[str, object]] = []
    with PEImage(exe) as image:
        for section in image.sections:
            if section.raw_size <= 0:
                continue
            blob = image.read_rva(section.virtual_address, section.raw_size)
            if not blob:
                continue
            for encoding in encodings:
                needle = _encoded_literal(literal, encoding)
                start = 0
                while True:
                    offset = blob.find(needle, start)
                    if offset < 0:
                        break
                    rva = section.virtual_address + offset
                    rows.append(
                        {
                            "literal": literal,
                            "encoding": encoding,
                            "section": section.name,
                            "section_offset": f"0x{offset:X}",
                            "rva": f"0x{rva:X}",
                            "va": f"0x{image.image_base + rva:X}",
                            "byte_length": len(needle),
                        }
                    )
                    start = offset + 1
    return rows


def find_raw_string_hits(
    path: Path,
    literal: str,
    *,
    encodings: tuple[str, ...] = ("ascii", "utf-16le"),
) -> list[dict[str, object]]:
    """Find exact encoded literal bytes in an arbitrary file."""

    data = path.read_bytes()
    rows: list[dict[str, object]] = []
    for encoding in encodings:
        needle = _encoded_literal(literal, encoding)
        start = 0
        while True:
            offset = data.find(needle, start)
            if offset < 0:
                break
            rows.append(
                {
                    "literal": literal,
                    "encoding": encoding,
                    "file_offset": f"0x{offset:X}",
                    "byte_length": len(needle),
                }
            )
            start = offset + 1
    return rows


def locate_pe_string_xrefs(
    exe: Path,
    literals: list[str],
    *,
    methods_csv: Path | None = None,
    expected_sha256: str | None = None,
    encodings: tuple[str, ...] = ("ascii", "utf-16le"),
    window: int = 48,
) -> dict[str, object]:
    """Locate PE string literals and simple direct/indirect native xrefs."""

    actual_sha256 = _sha256(exe)
    if expected_sha256 and actual_sha256.casefold() != expected_sha256.casefold():
        raise ValueError(
            f"unexpected executable SHA-256: {actual_sha256}; expected {expected_sha256}"
        )

    all_hits: list[dict[str, object]] = []
    for literal in literals:
        all_hits.extend(find_pe_string_hits(exe, literal, encodings=encodings))

    target_rvas = sorted({int(str(row["rva"]), 0) for row in all_hits})
    direct = (
        scan_rip_xrefs(
            exe,
            target_rvas,
            window=window,
            methods_csv=methods_csv,
        )
        if target_rvas
        else {"matches": {}, "scanned_sections": []}
    )

    enriched: list[dict[str, object]] = []
    for row in all_hits:
        rva = int(str(row["rva"]), 0)
        byte_length = int(row["byte_length"])
        pointer_scan = scan_pointer_xrefs(
            exe,
            rva,
            rva + byte_length,
            window=window,
        )
        enriched.append(
            {
                **row,
                "direct_code_xrefs": direct["matches"].get(f"0x{rva:X}", []),
                "pointer_holders": pointer_scan["holders"],
            }
        )

    return {
        "executable": str(exe),
        "executable_sha256": actual_sha256,
        "expected_sha256": expected_sha256,
        "methods_csv": None if methods_csv is None else str(methods_csv),
        "encodings": list(encodings),
        "literals": literals,
        "literal_hit_count": len(enriched),
        "direct_code_xref_count": sum(len(row["direct_code_xrefs"]) for row in enriched),
        "pointer_holder_count": sum(len(row["pointer_holders"]) for row in enriched),
        "hits": enriched,
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="python -m genshinre.stringxref",
        description=(
            "Locate exact strings in PE sections and recover simple RIP-relative "
            "or pointer-mediated native xrefs."
        ),
    )
    parser.add_argument("exe", type=Path)
    parser.add_argument("--literal", action="append", required=True)
    parser.add_argument("--encoding", action="append", choices=("ascii", "utf-16le"))
    parser.add_argument("--methods-csv", type=Path)
    parser.add_argument("--expected-sha256")
    parser.add_argument("--window", type=int, default=48)
    parser.add_argument("--raw-file", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    encodings = tuple(args.encoding or ("ascii", "utf-16le"))
    result = locate_pe_string_xrefs(
        args.exe,
        args.literal,
        methods_csv=args.methods_csv,
        expected_sha256=args.expected_sha256,
        encodings=encodings,
        window=args.window,
    )
    if args.raw_file is not None:
        result["raw_file"] = str(args.raw_file)
        result["raw_file_sha256"] = _sha256(args.raw_file)
        raw_hits: list[dict[str, object]] = []
        for literal in args.literal:
            raw_hits.extend(find_raw_string_hits(args.raw_file, literal, encodings=encodings))
        result["raw_file_hits"] = raw_hits
        result["raw_file_hit_count"] = len(raw_hits)

    if args.output:
        write_json(result, args.output)
    print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
