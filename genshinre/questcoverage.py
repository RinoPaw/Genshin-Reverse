from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
import re
from typing import Any, Iterable

from .questbin import QuestBinParseError, parse_main_quest


# Batch coverage is diagnostic by default: unsupported shapes are ranked, not hidden.
@dataclass(frozen=True)
class QuestPayloadSample:
    """One exact native Quest payload supplied to the batch coverage analyzer."""

    name: str
    data: bytes
    main_id_hint: int | None = None


_BITS_RE = re.compile(
    r"unsupported (AFIOOHMJHDM|LAIMPNDEFCL|OOPFBIEAILL|FBKMIOOJCKG presence|"
    r"QuestExec presence|QuestContent presence) bits \[([^]]*)\]"
)
_MAIN_ID_RE = re.compile(r"(?:quest)?(\d+)$", re.IGNORECASE)
_OFFSET_RE = re.compile(r" at 0x([0-9A-Fa-f]+)")
_FBKM_COUNT_RE = re.compile(r"implausible FBKMIOOJCKG ([A-Za-z0-9]+) count")


def _counter_dict(counter: Counter[int] | Counter[str]) -> dict[str, int]:
    return {str(key): counter[key] for key in sorted(counter)}


def _infer_main_id(path: Path) -> int | None:
    match = _MAIN_ID_RE.fullmatch(path.stem)
    return int(match.group(1)) if match else None


def _read_payload(path: Path) -> bytes:
    if path.suffix.lower() == ".hex":
        return bytes.fromhex(path.read_text(encoding="ascii"))
    return path.read_bytes()


def load_quest_samples(path: Path) -> tuple[QuestPayloadSample, ...]:
    """Load raw Quest payloads from a file or a dedicated extraction directory.

    Raw exports commonly have numeric filenames without extensions. Repository fixtures
    use .hex and are accepted as a convenience for regression and local coverage runs.
    """

    if path.is_file():
        files = [path]
    elif path.is_dir():
        files = [
            item
            for item in path.rglob("*")
            if item.is_file()
            and not item.name.startswith(".")
            and item.suffix.lower() in {"", ".bin", ".dat", ".bytes", ".hex"}
        ]
    else:
        raise FileNotFoundError(path)

    samples = [
        QuestPayloadSample(
            name=str(item.relative_to(path)) if path.is_dir() else item.name,
            data=_read_payload(item),
            main_id_hint=_infer_main_id(item),
        )
        for item in files
    ]
    samples.sort(
        key=lambda sample: (
            sample.main_id_hint is None,
            sample.main_id_hint if sample.main_id_hint is not None else 0,
            sample.name,
        )
    )
    return tuple(samples)


def _failure_families(message: str) -> tuple[str, ...]:
    match = _BITS_RE.search(message)
    if match:
        owner = match.group(1).replace(" presence", "")
        bits = tuple(
            int(text.strip())
            for text in match.group(2).split(",")
            if text.strip()
        )
        if bits:
            return tuple(f"{owner}.bit{bit}" for bit in bits)
        return (f"{owner}.bits",)

    count_match = _FBKM_COUNT_RE.search(message)
    if count_match:
        return (f"FBKMIOOJCKG.{count_match.group(1)}Count",)

    known = (
        ("unsupported FBKMIOOJCKG raw bit1", "FBKMIOOJCKG.rawBit1"),
        ("unsupported FBKMIOOJCKG raw mask", "FBKMIOOJCKG.rawMask"),
        ("unsupported FBKMIOOJCKG condition mask", "FBKMIOOJCKG.conditionMask"),
        ("unsupported FBKMIOOJCKG condition param-count", "FBKMIOOJCKG.conditionParamCount"),
        ("unsupported FBKMIOOJCKG first-array count", "FBKMIOOJCKG.firstArrayCount"),
        ("unsupported FBKMIOOJCKG optional-bit42 count", "FBKMIOOJCKG.optionalBit42Count"),
        ("FBKMIOOJCKG condition string length", "FBKMIOOJCKG.conditionString"),
        ("unsupported non-empty FBKMIOOJCKG field5", "FBKMIOOJCKG.field5String"),
        ("unexplained trailing bytes", "trailingBytes"),
        ("truncated Quest BinOutput", "truncated"),
    )
    for needle, family in known:
        if needle in message:
            return (family,)
    return ("other",)


def _failure_offset(message: str) -> int | None:
    match = _OFFSET_RE.search(message)
    return int(match.group(1), 16) if match else None


def analyze_quest_samples(samples: Iterable[QuestPayloadSample]) -> dict[str, Any]:
    """Decode a batch and aggregate native coverage/failure families.

    Failures are data: the analyzer keeps scanning so one unsupported native shape can be
    ranked across the corpus instead of stopping at the first Quest that exercises it.
    """

    sample_list = tuple(samples)
    afio_bits: Counter[int] = Counter()
    laim_bits: Counter[int] = Counter()
    afio_structural: Counter[str] = Counter()
    laim_structural: Counter[str] = Counter()
    content_types: Counter[int] = Counter()
    exec_types: Counter[int] = Counter()
    failure_counts: Counter[str] = Counter()
    failure_examples: dict[str, list[dict[str, Any]]] = defaultdict(list)
    quests: list[dict[str, Any]] = []
    id_mismatches: list[dict[str, Any]] = []
    full = 0

    for sample in sample_list:
        try:
            quest = parse_main_quest(sample.data)
        except QuestBinParseError as exc:
            message = str(exc)
            families = _failure_families(message)
            offset = _failure_offset(message)
            item: dict[str, Any] = {
                "name": sample.name,
                "mainIdHint": sample.main_id_hint,
                "size": len(sample.data),
                "status": "failed",
                "error": message,
                "failureFamilies": list(families),
            }
            if offset is not None:
                item["offset"] = offset
            quests.append(item)
            for family in families:
                failure_counts[family] += 1
                examples = failure_examples[family]
                if len(examples) < 5:
                    examples.append(
                        {
                            "name": sample.name,
                            "mainIdHint": sample.main_id_hint,
                            "error": message,
                        }
                    )
            continue

        full += 1
        afio_bits.update(quest.presence_bits)
        afio_structural.update(f"bit{bit}" for bit in quest.presence_bits)
        for row in quest.quests:
            laim_bits.update(row.presence_bits)
            laim_structural.update(f"bit{bit}" for bit in row.presence_bits)
            for item in row.fail_cond + row.finish_cond:
                content_types[item.type_id] += 1
            for item in row.fail_exec + row.finish_exec:
                exec_types[item.type_id] += 1

        if (
            sample.main_id_hint is not None
            and quest.main_id is not None
            and sample.main_id_hint != quest.main_id
        ):
            id_mismatches.append(
                {
                    "name": sample.name,
                    "mainIdHint": sample.main_id_hint,
                    "decodedMainId": quest.main_id,
                }
            )

        quests.append(
            {
                "name": sample.name,
                "mainIdHint": sample.main_id_hint,
                "mainId": quest.main_id,
                "size": quest.size,
                "consumed": quest.consumed,
                "rows": len(quest.quests),
                "status": "full",
            }
        )

    failures = [
        {
            "family": family,
            "count": failure_counts[family],
            "examples": failure_examples[family],
        }
        for family in sorted(
            failure_counts,
            key=lambda family: (-failure_counts[family], family),
        )
    ]

    return {
        "total": len(sample_list),
        "fullConsumed": full,
        "failed": len(sample_list) - full,
        "payloadBytes": sum(len(sample.data) for sample in sample_list),
        "observedAfioBits": _counter_dict(afio_bits),
        "observedLaimBits": _counter_dict(laim_bits),
        "structuralAfioFields": _counter_dict(afio_structural),
        "structuralLaimFields": _counter_dict(laim_structural),
        "questContentTypeIds": _counter_dict(content_types),
        "questExecTypeIds": _counter_dict(exec_types),
        "failureFamilies": failures,
        "idMismatches": id_mismatches,
        "quests": quests,
    }


def analyze_quest_path(path: Path) -> dict[str, Any]:
    samples = load_quest_samples(path)
    if not samples:
        raise ValueError(f"no Quest payload candidates under {path}")
    return analyze_quest_samples(samples)
