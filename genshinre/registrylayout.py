from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from pathlib import Path

from .mhy71 import EXPECTED_EXE_SHA256
from .pe import PEImage

HISTORICAL_ROW_COUNT = 4_896


@dataclass(frozen=True)
class RowAnchor:
    index: int
    cmd_id: int
    registry_flag: int
    type_slot_rva: int
    name: str


ANCHOR_9369 = RowAnchor(
    index=2232,
    cmd_id=9369,
    registry_flag=1,
    type_slot_rva=0x057E6498,
    name="UnlockTransPointReq / DMMJNICDOHM",
)

# `notify-22899-evidence.md` says "第 3118 项". Preserve both plausible
# interpretations until the native layout itself resolves the 0/1-based wording.
ANCHOR_22899_INDEX_CANDIDATES = (3118, 3117)
ANCHOR_22899 = RowAnchor(
    index=3118,
    cmd_id=22899,
    registry_flag=0,
    type_slot_rva=0x057F6F60,
    name="DoSetPlayerBornDataNotify / ONKOPMILDMF",
)


def _read_uint(image: PEImage, rva: int, width: int) -> int | None:
    blob = image.read_rva(rva, width)
    if len(blob) != width:
        return None
    return int.from_bytes(blob, "little", signed=False)


def _find_value_occurrences(image: PEImage, value: int, width: int) -> list[dict[str, object]]:
    needle = value.to_bytes(width, "little", signed=False)
    rows: list[dict[str, object]] = []
    for section in image.sections:
        # Static registries should live in mapped image data. Keep executable
        # sections too because protected builds can place constants unusually.
        blob = image.read_rva(section.virtual_address, section.raw_size)
        if not blob:
            continue
        cursor = 0
        while True:
            offset = blob.find(needle, cursor)
            if offset < 0:
                break
            rows.append(
                {
                    "rva": section.virtual_address + offset,
                    "section": section.name,
                    "aligned_width": (offset % width) == 0,
                }
            )
            cursor = offset + 1
    return rows


def _column_metrics(
    image: PEImage,
    column_base_rva: int,
    stride: int,
    width: int,
    row_count: int,
) -> dict[str, object]:
    values: list[int] = []
    readable = 0
    protocol_range = 0
    nonzero = 0
    for index in range(row_count):
        value = _read_uint(image, column_base_rva + index * stride, width)
        if value is None:
            break
        readable += 1
        values.append(value)
        if value != 0:
            nonzero += 1
        if 1 <= value <= 65535:
            protocol_range += 1
    unique_nonzero = len({value for value in values if value != 0})
    return {
        "readable_rows": readable,
        "nonzero_rows": nonzero,
        "protocol_range_rows": protocol_range,
        "unique_nonzero_values": unique_nonzero,
        "protocol_range_ratio": (protocol_range / readable) if readable else 0.0,
        "unique_ratio": (unique_nonzero / nonzero) if nonzero else 0.0,
    }


def _slot_field_matches(
    image: PEImage,
    cmd1_rva: int,
    cmd2_rva: int,
    stride: int,
    anchor1: RowAnchor,
    anchor2: RowAnchor,
) -> list[dict[str, object]]:
    matches: list[dict[str, object]] = []
    expected_forms = (
        ("rva32", 4, anchor1.type_slot_rva, anchor2.type_slot_rva),
        ("rva64", 8, anchor1.type_slot_rva, anchor2.type_slot_rva),
        (
            "va64",
            8,
            image.image_base + anchor1.type_slot_rva,
            image.image_base + anchor2.type_slot_rva,
        ),
    )
    for relative in range(-(stride - 1), stride):
        for encoding, width, expected1, expected2 in expected_forms:
            if _read_uint(image, cmd1_rva + relative, width) != expected1:
                continue
            if _read_uint(image, cmd2_rva + relative, width) != expected2:
                continue
            matches.append(
                {
                    "relative_to_cmd": relative,
                    "encoding": encoding,
                    "width": width,
                }
            )
    return matches


def _flag_field_matches(
    image: PEImage,
    cmd1_rva: int,
    cmd2_rva: int,
    stride: int,
    anchor1: RowAnchor,
    anchor2: RowAnchor,
) -> list[dict[str, object]]:
    matches: list[dict[str, object]] = []
    for relative in range(-(stride - 1), stride):
        for width in (1, 2, 4):
            if _read_uint(image, cmd1_rva + relative, width) != anchor1.registry_flag:
                continue
            if _read_uint(image, cmd2_rva + relative, width) != anchor2.registry_flag:
                continue
            matches.append({"relative_to_cmd": relative, "width": width})
    return matches


def infer_layout_candidates(
    image: PEImage,
    anchor1: RowAnchor = ANCHOR_9369,
    anchor2_indices: tuple[int, ...] = ANCHOR_22899_INDEX_CANDIDATES,
    min_stride: int = 2,
    max_stride: int = 96,
    row_count: int = HISTORICAL_ROW_COUNT,
) -> list[dict[str, object]]:
    candidates: list[dict[str, object]] = []

    for width in (2, 4):
        occurrences = _find_value_occurrences(image, anchor1.cmd_id, width)
        for occurrence in occurrences:
            cmd1_rva = int(occurrence["rva"])
            for index2 in anchor2_indices:
                anchor2 = RowAnchor(
                    index=index2,
                    cmd_id=ANCHOR_22899.cmd_id,
                    registry_flag=ANCHOR_22899.registry_flag,
                    type_slot_rva=ANCHOR_22899.type_slot_rva,
                    name=ANCHOR_22899.name,
                )
                delta_index = anchor2.index - anchor1.index
                if delta_index <= 0:
                    continue
                for stride in range(min_stride, max_stride + 1):
                    cmd2_rva = cmd1_rva + delta_index * stride
                    if _read_uint(image, cmd2_rva, width) != anchor2.cmd_id:
                        continue
                    column_base_rva = cmd1_rva - anchor1.index * stride
                    if image.rva_to_offset(column_base_rva) is None:
                        continue

                    slot_matches = _slot_field_matches(
                        image, cmd1_rva, cmd2_rva, stride, anchor1, anchor2
                    )
                    flag_matches = _flag_field_matches(
                        image, cmd1_rva, cmd2_rva, stride, anchor1, anchor2
                    )
                    metrics = _column_metrics(
                        image, column_base_rva, stride, width, row_count
                    )

                    score = 0
                    if slot_matches:
                        score += 100
                    if flag_matches:
                        score += 30
                    score += round(float(metrics["protocol_range_ratio"]) * 20)
                    score += round(float(metrics["unique_ratio"]) * 20)
                    if int(metrics["readable_rows"]) == row_count:
                        score += 10
                    if int(metrics["unique_nonzero_values"]) == row_count:
                        score += 10

                    candidates.append(
                        {
                            "score": score,
                            "cmd_width": width,
                            "stride": stride,
                            "anchor_22899_index_interpretation": index2,
                            "cmd_column_base_rva": f"0x{column_base_rva:X}",
                            "anchor_9369_cmd_rva": f"0x{cmd1_rva:X}",
                            "anchor_22899_cmd_rva": f"0x{cmd2_rva:X}",
                            "section": occurrence["section"],
                            "slot_field_matches": slot_matches,
                            "flag_field_matches": flag_matches,
                            "column_metrics": metrics,
                            "status": (
                                "strong-layout-candidate"
                                if slot_matches and flag_matches
                                else "cmd-spacing-candidate"
                            ),
                        }
                    )

    candidates.sort(
        key=lambda item: (
            int(item["score"]),
            bool(item["slot_field_matches"]),
            bool(item["flag_field_matches"]),
            float(item["column_metrics"]["unique_ratio"]),
        ),
        reverse=True,
    )
    return candidates


def probe_registry_layout_71(
    exe: Path,
    output_json: Path,
    allow_unknown_sample: bool = False,
    max_results: int = 100,
) -> dict[str, object]:
    from .mhy71 import _sha256

    exe_sha = _sha256(exe)
    if not allow_unknown_sample and exe_sha != EXPECTED_EXE_SHA256:
        raise ValueError(f"unexpected GenshinImpact.exe SHA-256: {exe_sha}")

    with PEImage(exe) as image:
        candidates = infer_layout_candidates(image)

    strong = [row for row in candidates if row["status"] == "strong-layout-candidate"]
    result: dict[str, object] = {
        "exe": str(exe),
        "exe_sha256": exe_sha,
        "historical_row_count_reference": HISTORICAL_ROW_COUNT,
        "anchors": [
            {
                "index": ANCHOR_9369.index,
                "cmd_id": ANCHOR_9369.cmd_id,
                "registry_flag": ANCHOR_9369.registry_flag,
                "type_slot_rva": f"0x{ANCHOR_9369.type_slot_rva:X}",
                "name": ANCHOR_9369.name,
            },
            {
                "index_candidates": list(ANCHOR_22899_INDEX_CANDIDATES),
                "cmd_id": ANCHOR_22899.cmd_id,
                "registry_flag": ANCHOR_22899.registry_flag,
                "type_slot_rva": f"0x{ANCHOR_22899.type_slot_rva:X}",
                "name": ANCHOR_22899.name,
            },
        ],
        "candidate_count": len(candidates),
        "strong_candidate_count": len(strong),
        "candidates": candidates[:max_results],
        "status": "candidate-evidence",
        "notes": [
            "the 22899 historical source says 'item 3118'; both zero/one-based interpretations are tested",
            "4,896 is used only to measure candidate-column shape and is never used to fabricate rows",
            "promotion requires a layout that simultaneously explains both CmdIds, both type slots and the preserved 1/0 direction flags",
        ],
    }
    output_json.parent.mkdir(parents=True, exist_ok=True)
    output_json.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return result


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="python -m genshinre.registrylayout",
        description="Infer the native 7.1 protocol-registry row layout from preserved indexed anchors.",
    )
    parser.add_argument("exe", type=Path)
    parser.add_argument("output_json", type=Path)
    parser.add_argument("--allow-unknown-sample", action="store_true")
    parser.add_argument("--max-results", type=int, default=100)
    parser.add_argument("--require-strong", action="store_true")
    args = parser.parse_args()

    result = probe_registry_layout_71(
        args.exe,
        args.output_json,
        allow_unknown_sample=args.allow_unknown_sample,
        max_results=args.max_results,
    )
    print(json.dumps(result, indent=2, ensure_ascii=False))
    if args.require_strong and int(result["strong_candidate_count"]) == 0:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
