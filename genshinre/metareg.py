from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from .mhy71 import EXPECTED_EXE_SHA256, TYPE_ARRAY_POINTER_RVA
from .pe import PEImage

QWORD = 8
PAIR_SIZE = 16


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(8 * 1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _mapped_rva(image: PEImage, rva: int) -> bool:
    return image.rva_to_offset(rva) is not None


def _pointer_info(image: PEImage, value: int) -> dict[str, object]:
    if value == 0:
        return {"value": "0x0", "mapped": False}
    rva = value - image.image_base
    section = next(
        (
            item
            for item in image.sections
            if item.virtual_address <= rva < item.virtual_address + max(item.virtual_size, item.raw_size)
        ),
        None,
    )
    return {
        "value": f"0x{value:X}",
        "rva": f"0x{rva:X}",
        "mapped": _mapped_rva(image, rva),
        "section": None if section is None else section.name,
    }


def decode_count_pointer_pair(image: PEImage, source_rva: int) -> dict[str, object]:
    """Decode a candidate `<count:qword, pointer:qword>` pair at source_rva."""
    blob = image.read_rva(source_rva, PAIR_SIZE)
    if len(blob) < PAIR_SIZE:
        raise ValueError(f"cannot read candidate pair at RVA 0x{source_rva:X}")
    count = int.from_bytes(blob[:8], "little", signed=False)
    pointer = int.from_bytes(blob[8:16], "little", signed=False)
    return {
        "source_rva": f"0x{source_rva:X}",
        "count": count,
        "pointer": _pointer_info(image, pointer),
    }


def _qword_window(image: PEImage, center_rva: int, before: int, after: int) -> list[dict[str, object]]:
    start = center_rva - before * QWORD
    count = before + after + 1
    blob = image.read_rva(start, count * QWORD)
    rows: list[dict[str, object]] = []
    for index in range(len(blob) // QWORD):
        rva = start + index * QWORD
        value = int.from_bytes(blob[index * QWORD : (index + 1) * QWORD], "little", signed=False)
        rows.append(
            {
                "rva": f"0x{rva:X}",
                "relative_qword": index - before,
                "value": f"0x{value:X}",
                "decimal": value,
                "pointer": _pointer_info(image, value),
            }
        )
    return rows


def _find_qword_occurrences(image: PEImage, value: int) -> list[dict[str, object]]:
    needle = value.to_bytes(8, "little", signed=False)
    matches: list[dict[str, object]] = []
    for section in image.sections:
        # Registration structures live in mapped data; executable sections are also
        # retained because protected builds sometimes place static data unusually.
        blob = image.read_rva(section.virtual_address, section.raw_size)
        if not blob:
            continue
        cursor = 0
        while True:
            offset = blob.find(needle, cursor)
            if offset < 0:
                break
            matches.append(
                {
                    "rva": section.virtual_address + offset,
                    "section": section.name,
                    "aligned_8": (offset % 8) == 0,
                    "aligned_16": (offset % 16) == 0,
                }
            )
            cursor = offset + 1
    return matches


def _score_pair_run(pairs: list[dict[str, object]], known_type_pointer_va: int) -> dict[str, object]:
    mapped_pointers = sum(1 for pair in pairs if bool(pair["pointer"].get("mapped")))
    plausible_counts = sum(1 for pair in pairs if 0 < int(pair["count"]) < 10_000_000)
    contains_types = any(int(pair["pointer"]["value"], 0) == known_type_pointer_va for pair in pairs)
    return {
        "mapped_pointers": mapped_pointers,
        "plausible_counts": plausible_counts,
        "pair_count": len(pairs),
        "contains_runtime_type_array": contains_types,
        "score": mapped_pointers * 2 + plausible_counts + (8 if contains_types else 0),
    }


def probe_metadata_registration_71(
    exe: Path,
    output_json: Path,
    pairs_before: int = 6,
    pairs_after: int = 8,
    allow_unknown_sample: bool = False,
) -> dict[str, object]:
    exe_sha = _sha256(exe)
    if not allow_unknown_sample and exe_sha != EXPECTED_EXE_SHA256:
        raise ValueError(f"unexpected GenshinImpact.exe SHA-256: {exe_sha}")

    with PEImage(exe) as image:
        pointer_blob = image.read_rva(TYPE_ARRAY_POINTER_RVA, QWORD)
        if len(pointer_blob) != QWORD:
            raise ValueError("cannot read runtime type-array pointer source")
        type_array_va = int.from_bytes(pointer_blob, "little", signed=False)
        type_array_rva = type_array_va - image.image_base
        if not _mapped_rva(image, type_array_rva):
            raise ValueError(f"runtime type-array pointer 0x{type_array_va:X} does not map into the PE")

        occurrences = _find_qword_occurrences(image, type_array_va)
        candidates: list[dict[str, object]] = []
        for match in occurrences:
            pointer_field_rva = int(match["rva"])
            # In Il2CppMetadataRegistration-style layouts a pointer is commonly
            # preceded by its count. Align the candidate run to that preceding count.
            type_pair_rva = pointer_field_rva - QWORD
            first_pair_rva = type_pair_rva - pairs_before * PAIR_SIZE
            pairs: list[dict[str, object]] = []
            for pair_index in range(pairs_before + 1 + pairs_after):
                source_rva = first_pair_rva + pair_index * PAIR_SIZE
                try:
                    pair = decode_count_pointer_pair(image, source_rva)
                except ValueError:
                    break
                pair["relative_pair"] = pair_index - pairs_before
                if pair_index == pairs_before:
                    pair["role"] = "runtime-types-candidate"
                pairs.append(pair)
            score = _score_pair_run(pairs, type_array_va)
            preceding_count = None
            if pairs_before < len(pairs):
                target_pair = pairs[pairs_before]
                if int(target_pair["pointer"]["value"], 0) == type_array_va:
                    preceding_count = int(target_pair["count"])
            candidates.append(
                {
                    **match,
                    "rva": f"0x{pointer_field_rva:X}",
                    "type_pair_rva": f"0x{type_pair_rva:X}",
                    "preceding_count": preceding_count,
                    "count_covers_preserved_type_index_405772": (
                        preceding_count is not None and preceding_count > 405_772
                    ),
                    "score": score,
                    "pairs": pairs,
                }
            )

        candidates.sort(key=lambda item: int(item["score"]["score"]), reverse=True)
        source_window = _qword_window(image, TYPE_ARRAY_POINTER_RVA, before=8, after=12)

    result: dict[str, object] = {
        "exe": str(exe),
        "exe_sha256": exe_sha,
        "image_base": f"0x{image.image_base:X}",
        "runtime_type_array": {
            "pointer_source_rva": f"0x{TYPE_ARRAY_POINTER_RVA:X}",
            "va": f"0x{type_array_va:X}",
            "rva": f"0x{type_array_rva:X}",
        },
        "source_qword_window": source_window,
        "occurrence_count": len(occurrences),
        "candidates": candidates,
        "status": "candidate-evidence",
        "notes": [
            "candidate runs are structural probes; no metadata-registration layout is asserted solely from score",
            "a plausible typesCount should exceed the preserved runtime type index 405772 and have a mapped type-array pointer",
            "neighbor count/pointer pairs should be independently identified before assigning semantic field names",
        ],
    }
    output_json.parent.mkdir(parents=True, exist_ok=True)
    output_json.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return result


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="python -m genshinre.metareg",
        description="Probe 7.1 IL2CPP metadata-registration count/pointer structure around the runtime type array.",
    )
    parser.add_argument("exe", type=Path)
    parser.add_argument("output_json", type=Path)
    parser.add_argument("--pairs-before", type=int, default=6)
    parser.add_argument("--pairs-after", type=int, default=8)
    parser.add_argument("--allow-unknown-sample", action="store_true")
    parser.add_argument("--require-plausible-types-count", action="store_true")
    args = parser.parse_args()

    result = probe_metadata_registration_71(
        args.exe,
        args.output_json,
        pairs_before=args.pairs_before,
        pairs_after=args.pairs_after,
        allow_unknown_sample=args.allow_unknown_sample,
    )
    print(json.dumps(result, indent=2, ensure_ascii=False))
    if args.require_plausible_types_count:
        if not any(bool(item["count_covers_preserved_type_index_405772"]) for item in result["candidates"]):
            raise SystemExit(1)


if __name__ == "__main__":
    main()
