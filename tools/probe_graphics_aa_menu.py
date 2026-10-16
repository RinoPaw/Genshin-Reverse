"""Read-only, fingerprinted reconnaissance for the Genshin graphics AA menu.

The report contains search candidates, never verified UI owners or hook offsets.
Works with the repository's published 7.1 IL2CPP metadata and a local EXE.
"""
from __future__ import annotations

import argparse
import csv
import json
import re
from pathlib import Path

from genshinre.sampleidentity import sha256_file
from genshinre.stringxref import find_pe_string_hits, locate_pe_string_xrefs

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SAMPLE = ROOT / "versions/7.1.0-global/windows-x64"
LITERALS = (
    "FSR2", "FSR 2", "SMAA", "AntiAliasing", "Anti-Aliasing",
    "anti-aliasing", "TAA", "DLSS", "GraphicsSettings", "PostProcessLayer",
)
# The public metadata may be obfuscated. No textual hit is not proof of absence.
METADATA_PATTERN = re.compile(
    r"(?:anti.?alias|\bfsr\b|fsr2|smaa|dlss|graphics|render.?scale|post.?process)",
    re.IGNORECASE,
)
# Exact 7.1 owners: game graphics UI, setting group, AA mode, FSR quality,
# followed by rendering-side consumer. Do not confuse renderer with UI owner.
FOCUS_TYPE_INDICES = (18970, 13019, 9450, 18971, 9330, 9384)

SOURCE_FIELDS = {
    "types.csv": ("type_name", "namespace"),
    "methods.csv": ("type_name", "method_name", "return_type", "parameter_types"),
    "fields.csv": ("type_name", "field_name", "field_type"),
}


def scan_metadata(metadata_dir: Path, *, max_rows: int = 100) -> dict[str, object]:
    if max_rows < 1:
        raise ValueError("max_rows must be positive")
    result: dict[str, object] = {}
    for filename, columns in SOURCE_FIELDS.items():
        path = metadata_dir / filename
        matches: list[dict[str, str]] = []
        count = 0
        with path.open("r", newline="", encoding="utf-8-sig") as stream:
            reader = csv.DictReader(stream)
            for row in reader:
                if not any(METADATA_PATTERN.search(row.get(c) or "") for c in columns):
                    continue
                count += 1
                if len(matches) < max_rows:
                    matches.append({key: value for key, value in row.items()
                                    if key in (*columns, "type_definition_index", "method_index", "rva",
                                               "field_index", "field_type_index")})
        result[filename] = {"count": count, "truncated": count > len(matches), "rows": matches}
    return result



def scan_type_owners(
    metadata_dir: Path, type_indices: tuple[int, ...], *, max_rows: int = 150
) -> dict[str, object]:
    """Select every row owned by targeted exact-build type definitions.

    This is independent of keyword matching: obfuscated method and field names
    are included as long as their owning typeDefinitionIndex is known.
    """
    if max_rows < 1:
        raise ValueError("max_rows must be positive")
    selected = set(type_indices)
    if any(value < 0 for value in selected):
        raise ValueError("type indices must be non-negative")
    result: dict[str, object] = {}
    for filename in SOURCE_FIELDS:
        matches: list[dict[str, str]] = []
        count = 0
        with (metadata_dir / filename).open("r", newline="", encoding="utf-8-sig") as stream:
            for row in csv.DictReader(stream):
                raw_id = row.get("type_definition_index", "")
                if not raw_id or int(raw_id) not in selected:
                    continue
                count += 1
                if len(matches) < max_rows:
                    matches.append({
                        key: value for key, value in row.items()
                        if key in (*SOURCE_FIELDS[filename], "type_definition_index",
                                   "method_index", "rva", "field_index", "field_type_index",
                                   "offset", "parameter_count")
                    })
        result[filename] = {
            "count": count, "truncated": count > len(matches), "rows": matches
        }
    return result


def verify_sample(exe: Path, hashes: Path, *, allow_unpinned: bool = False) -> dict[str, object]:
    fingerprint = json.loads(hashes.read_text(encoding="utf-8"))
    expected = fingerprint["samples"]["GenshinImpact.exe"]["sha256"].lower()
    actual = sha256_file(exe)
    pinned = actual.lower() == expected
    if not pinned and not allow_unpinned:
        raise ValueError(
            f"client fingerprint mismatch; observed SHA-256 {actual}, pinned {expected}. "
            "The published 7.1 IL2CPP metadata MUST NOT be applied to this client. "
            "To gather literal-only exploratory evidence, pass --allow-unpinned."
        )
    return {
        "sha256": actual, "expected_sha256": expected,
        "matches_pinned_7_1_sample": pinned,
        "game_version_claim": "7.1.0-global" if pinned else None,
    }


def probe(
    exe: Path,
    *,
    sample_dir: Path = DEFAULT_SAMPLE,
    allow_unpinned: bool = False,
    max_rows: int = 100,
    with_xrefs: bool = False,
    literals: tuple[str, ...] = LITERALS,
    focus_type_indices: tuple[int, ...] = FOCUS_TYPE_INDICES,
    focus_only: bool = False,
) -> dict[str, object]:
    identity = verify_sample(exe, sample_dir / "hashes.json", allow_unpinned=allow_unpinned)
    native_xrefs = None
    if focus_only and with_xrefs:
        raise ValueError("focus_only and with_xrefs cannot both be enabled")
    if focus_only:
        hits: list[dict[str, object]] = []
    elif with_xrefs:
        # This opt-in path may take longer on large game clients. It reports
        # native code references, not ownership of the game settings UI.
        native_xrefs = locate_pe_string_xrefs(
            exe, list(literals),
            methods_csv=(sample_dir / "metadata/methods.csv"
                         if identity["matches_pinned_7_1_sample"] else None),
            expected_sha256=identity["sha256"],
        )
        hits = native_xrefs["hits"]
    else:
        hits: list[dict[str, object]] = []
        for literal in literals:
            hits.extend(find_pe_string_hits(exe, literal))
    # Metadata belongs exclusively to the pinned 7.1 client; never merge candidates
    # from unrelated builds, even if some type names appear to match.
    metadata = (scan_metadata(sample_dir / "metadata", max_rows=max_rows)
                if identity["matches_pinned_7_1_sample"] and not focus_only else None)
    focused = (scan_type_owners(sample_dir / "metadata", focus_type_indices,
                                max_rows=max_rows)
               if identity["matches_pinned_7_1_sample"] else None)
    return {
        "schema_version": 1,
        "topic": "graphics-aa-menu",
        "state": "CANDIDATE_COLLECTION",
        "executable": str(exe),
        "identity": identity,
        "pe_string_hits": hits,
        "pe_string_hit_count": len(hits),
        "native_xrefs": native_xrefs,
        "metadata_keyword_hits": metadata,
        "metadata_focus_type_indices": list(focus_type_indices),
        "metadata_focus_type_owners": focused,
        "searched_literals": list(literals),
        "limitations": [
            "String references and keyword matches do not establish dropdown ownership.",
            "A zero-hit search does not exclude strings stored in Unity asset bundles or obfuscated metadata.",
            "No UI structures, enums, rendering state, or game files have been modified.",
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Read-only graphics AA menu candidate probe")
    parser.add_argument("exe", type=Path, help="Path to GenshinImpact.exe")
    parser.add_argument("--sample-dir", type=Path, default=DEFAULT_SAMPLE)
    parser.add_argument("--allow-unpinned", action="store_true",
                        help="Only scan PE literals; do not combine mismatched metadata")
    parser.add_argument("--max-rows", type=int, default=100)
    parser.add_argument("--literal", action="append", dest="literals",
                        help="Limit PE scan to these literals; repeatable. Defaults to the built-in set.")
    parser.add_argument("--focus-type", action="append", dest="focus_types", type=int,
                        help="Explicit 7.1 typeDefinitionIndex to inspect; repeatable.")
    parser.add_argument("--focus-only", action="store_true",
                        help="Skip PE search and broad keyword scan; emit only exact-owner metadata.")
    parser.add_argument("--with-xrefs", action="store_true",
                        help="Also resolve native xrefs, which is slower")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = probe(args.exe, sample_dir=args.sample_dir,
                   allow_unpinned=args.allow_unpinned, max_rows=args.max_rows,
                   with_xrefs=args.with_xrefs,
                   literals=tuple(args.literals or LITERALS),
                   focus_type_indices=tuple(args.focus_types or FOCUS_TYPE_INDICES),
                   focus_only=args.focus_only)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"Probe written: {args.output}")
    print(f"Pinned 7.1 match: {result['identity']['matches_pinned_7_1_sample']}")
    print(f"PE string hits: {result['pe_string_hit_count']}")
    if result["metadata_focus_type_owners"] is not None:
        print("Focused type-owner counts:", ", ".join(
            f"{name}={entry['count']}"
            for name, entry in result["metadata_focus_type_owners"].items()))
    if result["metadata_keyword_hits"] is not None:
        print("Metadata candidate counts:", ", ".join(
            f"{name}={entry['count']}"
            for name, entry in result["metadata_keyword_hits"].items()))


if __name__ == "__main__":
    main()
