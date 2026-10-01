from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from .mhy71 import EXPECTED_EXE_SHA256, TYPE_ARRAY_POINTER_RVA
from .pe import PEImage
from .usage import ANCHOR_9369, INITIALIZER_RVA_71
from .xrefs import decode_simple_rip_relative

FUNCTION_SCAN_SIZE = 0x800
ANCHOR_USAGE_INDEX = int(ANCHOR_9369["usage_destination"])
ANCHOR_TYPE_INDEX = 405_772
TYPE_ENTRY_SIZE = 16
LOW29_MASK = 0x1FFFFFFF


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(8 * 1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def classify_source_value(value: int, type_array_va: int) -> list[dict[str, object]]:
    matches: list[dict[str, object]] = []
    if value == ANCHOR_TYPE_INDEX:
        matches.append({"kind": "direct-type-index", "decoded_type_index": value})

    decoded_low29 = value & LOW29_MASK
    encoded_kind = (value >> 29) & 0x7
    if decoded_low29 == ANCHOR_TYPE_INDEX and value != ANCHOR_TYPE_INDEX:
        matches.append(
            {
                "kind": "low29-encoded-index",
                "decoded_type_index": decoded_low29,
                "encoded_usage_kind": encoded_kind,
            }
        )

    if value >= type_array_va:
        delta = value - type_array_va
        if delta % TYPE_ENTRY_SIZE == 0:
            index = delta // TYPE_ENTRY_SIZE
            if index == ANCHOR_TYPE_INDEX:
                matches.append(
                    {
                        "kind": "runtime-type-entry-pointer",
                        "decoded_type_index": index,
                    }
                )
    return matches


def _rip_targets_in_function(image: PEImage, function_rva: int, size: int) -> list[dict[str, object]]:
    code = image.read_rva(function_rva, size)
    targets: list[dict[str, object]] = []
    seen: set[tuple[int, int]] = set()
    for offset in range(len(code)):
        decoded = decode_simple_rip_relative(code, offset, function_rva + offset)
        if decoded is None:
            continue
        instruction_rva = int(decoded["instruction_rva"])
        target_rva = int(decoded["target_rva"])
        key = (instruction_rva, target_rva)
        if key in seen:
            continue
        seen.add(key)
        targets.append(
            {
                "instruction_rva": instruction_rva,
                "target_rva": target_rva,
                "mnemonic": decoded["mnemonic"],
                "access": decoded["access"],
                "instruction_hex": decoded["instruction_hex"],
            }
        )
    return targets


def _read_scalar(image: PEImage, rva: int, width: int) -> int | None:
    blob = image.read_rva(rva, width)
    if len(blob) != width:
        return None
    return int.from_bytes(blob, "little", signed=False)


def _probe_table_base(
    image: PEImage,
    table_rva: int,
    table_origin: str,
    type_array_va: int,
) -> list[dict[str, object]]:
    results: list[dict[str, object]] = []
    for stride, width in ((4, 4), (8, 8)):
        entry_rva = table_rva + ANCHOR_USAGE_INDEX * stride
        value = _read_scalar(image, entry_rva, width)
        if value is None:
            continue
        classifications = classify_source_value(value, type_array_va)
        results.append(
            {
                "table_origin": table_origin,
                "table_rva": f"0x{table_rva:X}",
                "stride": stride,
                "width": width,
                "anchor_usage_index": ANCHOR_USAGE_INDEX,
                "entry_rva": f"0x{entry_rva:X}",
                "value": f"0x{value:X}",
                "classifications": classifications,
                "anchor_match": bool(classifications),
            }
        )
    return results


def probe_usage_source_tables_71(
    exe: Path,
    output_json: Path,
    function_size: int = FUNCTION_SCAN_SIZE,
    allow_unknown_sample: bool = False,
) -> dict[str, object]:
    exe_sha = _sha256(exe)
    if not allow_unknown_sample and exe_sha != EXPECTED_EXE_SHA256:
        raise ValueError(f"unexpected GenshinImpact.exe SHA-256: {exe_sha}")

    with PEImage(exe) as image:
        type_pointer = image.read_rva(TYPE_ARRAY_POINTER_RVA, 8)
        if len(type_pointer) != 8:
            raise ValueError("cannot read runtime type-array pointer")
        type_array_va = int.from_bytes(type_pointer, "little", signed=False)

        rip_refs = _rip_targets_in_function(image, INITIALIZER_RVA_71, function_size)
        probes: list[dict[str, object]] = []
        seen_bases: set[tuple[int, str]] = set()
        for ref in rip_refs:
            target_rva = int(ref["target_rva"])
            if image.rva_to_offset(target_rva) is not None:
                key = (target_rva, "direct-rip-target")
                if key not in seen_bases:
                    seen_bases.add(key)
                    probes.extend(_probe_table_base(image, target_rva, "direct-rip-target", type_array_va))

            pointer_value = _read_scalar(image, target_rva, 8)
            if pointer_value is not None and pointer_value >= image.image_base:
                deref_rva = pointer_value - image.image_base
                if image.rva_to_offset(deref_rva) is not None:
                    key = (deref_rva, "dereferenced-rip-target")
                    if key not in seen_bases:
                        seen_bases.add(key)
                        probes.extend(
                            _probe_table_base(image, deref_rva, "dereferenced-rip-target", type_array_va)
                        )

        anchor_matches = [probe for probe in probes if bool(probe["anchor_match"])]

    result: dict[str, object] = {
        "exe": str(exe),
        "exe_sha256": exe_sha,
        "initializer_rva": f"0x{INITIALIZER_RVA_71:X}",
        "function_scan_size": function_size,
        "runtime_type_array_va": f"0x{type_array_va:X}",
        "anchor": {
            "usage_index": ANCHOR_USAGE_INDEX,
            "expected_type_index": ANCHOR_TYPE_INDEX,
        },
        "rip_reference_count": len(rip_refs),
        "rip_references": [
            {
                **ref,
                "instruction_rva": f"0x{int(ref['instruction_rva']):X}",
                "target_rva": f"0x{int(ref['target_rva']):X}",
            }
            for ref in rip_refs
        ],
        "table_probe_count": len(probes),
        "table_probes": probes,
        "anchor_match_count": len(anchor_matches),
        "anchor_matches": anchor_matches,
        "status": "candidate-evidence",
        "notes": [
            "the probe does not assign semantics to arbitrary helper data references",
            "an anchor match means table[37523] can be interpreted as runtime type index 405772 under at least one tested representation",
            "a matching table still needs neighboring-index and registration evidence before it becomes a canonical source map",
        ],
    }
    output_json.parent.mkdir(parents=True, exist_ok=True)
    output_json.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return result


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="python -m genshinre.usagesource",
        description="Probe data tables referenced by the 7.1 metadata-usage initializer using the preserved 37523 -> 405772 anchor.",
    )
    parser.add_argument("exe", type=Path)
    parser.add_argument("output_json", type=Path)
    parser.add_argument("--function-size", type=lambda value: int(value, 0), default=FUNCTION_SCAN_SIZE)
    parser.add_argument("--allow-unknown-sample", action="store_true")
    parser.add_argument("--require-anchor", action="store_true")
    args = parser.parse_args()

    result = probe_usage_source_tables_71(
        args.exe,
        args.output_json,
        function_size=args.function_size,
        allow_unknown_sample=args.allow_unknown_sample,
    )
    print(json.dumps(result, indent=2, ensure_ascii=False))
    if args.require_anchor and not result["anchor_matches"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
