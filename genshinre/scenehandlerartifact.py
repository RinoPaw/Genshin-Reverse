from __future__ import annotations

import argparse
import csv
import json
import re
from pathlib import Path

_ANALYSIS_REL = Path("analyses") / "scene-handler-dispatch"
_CSV_NAME = "scene-handler-slots.csv"
_EVIDENCE_NAME = "evidence.json"
_README_NAME = "README.md"
_COLUMNS = (
    "slots",
    "cmd_id",
    "type_name",
    "method_name",
    "method_index",
    "method_position",
    "method_rva",
    "method_size",
    "hit_count",
)
_HEX = re.compile(r"^0x[0-9A-Fa-f]+$")
_SHA256 = re.compile(r"^[0-9a-fA-F]{64}$")
_DIGEST = re.compile(r"^sha256:[0-9a-fA-F]{64}$")


def _load_json(path: Path, errors: list[str]) -> dict[str, object] | None:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        errors.append(f"{path.as_posix()}: {exc}")
        return None
    if not isinstance(data, dict):
        errors.append(f"{path.as_posix()}: root must be an object")
        return None
    return data


def _positive_int(value: object, label: str, errors: list[str]) -> int | None:
    if isinstance(value, bool):
        errors.append(f"{label}: must be a positive integer")
        return None
    try:
        parsed = int(str(value), 0)
    except (TypeError, ValueError):
        errors.append(f"{label}: must be a positive integer")
        return None
    if parsed <= 0:
        errors.append(f"{label}: must be a positive integer")
        return None
    return parsed


def _registry_pairs(path: Path, errors: list[str]) -> set[tuple[int, str]]:
    if not path.is_file():
        errors.append("scene-handler-dispatch: registry/registry.csv is required")
        return set()
    pairs: set[tuple[int, str]] = set()
    try:
        with path.open("r", encoding="utf-8-sig", newline="") as f:
            reader = csv.DictReader(f)
            fields = set(reader.fieldnames or ())
            if not {"cmd_id", "type_name"} <= fields:
                errors.append(
                    "scene-handler-dispatch: registry/registry.csv lacks cmd_id/type_name"
                )
                return set()
            for row in reader:
                pairs.add((int(row["cmd_id"], 0), row["type_name"].strip()))
    except Exception as exc:
        errors.append(f"scene-handler-dispatch registry check: {exc}")
    return pairs


def validate_scene_handler_dispatch(version_dir: Path) -> list[str]:
    """Validate the optional persisted scene-handler dispatch research artifact."""

    analysis_dir = version_dir / _ANALYSIS_REL
    if not analysis_dir.exists():
        return []

    errors: list[str] = []
    csv_path = analysis_dir / _CSV_NAME
    evidence_path = analysis_dir / _EVIDENCE_NAME
    readme_path = analysis_dir / _README_NAME
    for path in (csv_path, evidence_path, readme_path):
        if not path.is_file():
            errors.append(
                f"scene-handler-dispatch: missing {path.relative_to(version_dir).as_posix()}"
            )
    if errors:
        return errors

    evidence = _load_json(evidence_path, errors)
    hashes = _load_json(version_dir / "hashes.json", errors)
    if evidence is None or hashes is None:
        return errors

    if evidence.get("topic") != "scene-handler-dispatch":
        errors.append("scene-handler-dispatch: evidence topic mismatch")
    owner_type = evidence.get("owner_type")
    if not isinstance(owner_type, str) or not owner_type.strip():
        errors.append("scene-handler-dispatch: owner_type must be a non-empty string")

    expected_sha = ""
    samples = hashes.get("samples")
    if isinstance(samples, dict):
        exe = samples.get("GenshinImpact.exe")
        if isinstance(exe, dict):
            expected_sha = str(exe.get("sha256", ""))
    if not _SHA256.fullmatch(expected_sha):
        errors.append("scene-handler-dispatch: hashes.json lacks a valid executable SHA-256")

    exact_sample = evidence.get("exact_sample")
    actual_sha = ""
    if isinstance(exact_sample, dict):
        actual_sha = str(exact_sample.get("GenshinImpact.exe_sha256", ""))
    if not _SHA256.fullmatch(actual_sha):
        errors.append("scene-handler-dispatch: exact_sample executable SHA-256 is invalid")
    elif expected_sha and actual_sha.lower() != expected_sha.lower():
        errors.append("scene-handler-dispatch: exact_sample hash does not match hashes.json")

    provenance = evidence.get("provenance")
    if not isinstance(provenance, dict):
        errors.append("scene-handler-dispatch: provenance must be an object")
    else:
        _positive_int(
            provenance.get("workflow_run_id"),
            "scene-handler-dispatch: provenance.workflow_run_id",
            errors,
        )
        _positive_int(
            provenance.get("artifact_id"),
            "scene-handler-dispatch: provenance.artifact_id",
            errors,
        )
        digest = provenance.get("artifact_digest")
        if not isinstance(digest, str) or not _DIGEST.fullmatch(digest):
            errors.append(
                "scene-handler-dispatch: provenance.artifact_digest must be sha256:<64 hex>"
            )
        head_sha = provenance.get("workflow_head_sha")
        if not isinstance(head_sha, str) or not re.fullmatch(r"[0-9a-fA-F]{40}", head_sha):
            errors.append(
                "scene-handler-dispatch: provenance.workflow_head_sha must be a Git SHA-1"
            )

    summary = evidence.get("scan_summary")
    if not isinstance(summary, dict):
        errors.append("scene-handler-dispatch: scan_summary must be an object")
        return errors
    expected_rows = _positive_int(
        summary.get("method_row_count"),
        "scene-handler-dispatch: scan_summary.method_row_count",
        errors,
    )
    expected_hits = _positive_int(
        summary.get("instruction_hit_count"),
        "scene-handler-dispatch: scan_summary.instruction_hit_count",
        errors,
    )
    expected_slots = _positive_int(
        summary.get("unique_slot_count"),
        "scene-handler-dispatch: scan_summary.unique_slot_count",
        errors,
    )

    rows: list[dict[str, str]] = []
    try:
        with csv_path.open("r", encoding="utf-8-sig", newline="") as f:
            reader = csv.DictReader(f)
            fields = tuple(reader.fieldnames or ())
            if fields != _COLUMNS:
                errors.append(
                    "scene-handler-dispatch: CSV header mismatch; "
                    f"expected {','.join(_COLUMNS)}; got {','.join(fields)}"
                )
                return errors
            rows = [dict(row) for row in reader]
    except Exception as exc:
        errors.append(f"scene-handler-dispatch: cannot read CSV: {exc}")
        return errors

    registry_pairs = _registry_pairs(version_dir / "registry" / "registry.csv", errors)
    total_hits = 0
    unique_slots: set[int] = set()
    seen_methods: set[int] = set()
    parsed_rows: list[dict[str, object]] = []
    for line_no, row in enumerate(rows, start=2):
        label = f"scene-handler-dispatch/{_CSV_NAME}:{line_no}"
        raw_slots = [item.strip() for item in row["slots"].split(";") if item.strip()]
        if not raw_slots:
            errors.append(f"{label}: slots must contain at least one RVA-like displacement")
            continue
        slots: list[int] = []
        for raw in raw_slots:
            if not _HEX.fullmatch(raw):
                errors.append(f"{label}: invalid slot {raw!r}")
                continue
            slot = int(raw, 16)
            if slot % 8:
                errors.append(f"{label}: slot {raw} is not 8-byte aligned")
            slots.append(slot)
            unique_slots.add(slot)

        try:
            cmd_id = int(row["cmd_id"], 0)
            method_index = int(row["method_index"], 0)
            method_position = int(row["method_position"], 0)
            method_size = int(row["method_size"], 0)
            hit_count = int(row["hit_count"], 0)
        except ValueError as exc:
            errors.append(f"{label}: invalid integer field: {exc}")
            continue
        if not 0 <= cmd_id <= 65535:
            errors.append(f"{label}: cmd_id out of range")
        if method_index < 0 or method_position < 0 or method_size <= 0 or hit_count <= 0:
            errors.append(f"{label}: invalid method index/position/size/hit_count")
        if method_index in seen_methods:
            errors.append(f"{label}: duplicate method_index {method_index}")
        seen_methods.add(method_index)
        if not row["type_name"].strip() or not row["method_name"].strip():
            errors.append(f"{label}: type_name and method_name must be non-empty")
        if not _HEX.fullmatch(row["method_rva"]):
            errors.append(f"{label}: invalid method_rva {row['method_rva']!r}")
        if registry_pairs and (cmd_id, row["type_name"].strip()) not in registry_pairs:
            errors.append(
                f"{label}: CmdId/type pair {cmd_id}/{row['type_name']} is absent from canonical registry"
            )
        total_hits += hit_count
        parsed_rows.append(
            {
                "slots": set(slots),
                "cmd_id": cmd_id,
                "type_name": row["type_name"].strip(),
                "method_index": method_index,
                "method_rva": row["method_rva"],
            }
        )

    if expected_rows is not None and len(rows) != expected_rows:
        errors.append(
            "scene-handler-dispatch: CSV row count does not match scan_summary "
            f"({len(rows)} != {expected_rows})"
        )
    if expected_hits is not None and total_hits != expected_hits:
        errors.append(
            "scene-handler-dispatch: hit count does not match scan_summary "
            f"({total_hits} != {expected_hits})"
        )
    if expected_slots is not None and len(unique_slots) != expected_slots:
        errors.append(
            "scene-handler-dispatch: unique slot count does not match scan_summary "
            f"({len(unique_slots)} != {expected_slots})"
        )

    for count_name in ("destination_register_counts", "base_register_counts"):
        counts = summary.get(count_name)
        if not isinstance(counts, dict):
            errors.append(f"scene-handler-dispatch: scan_summary.{count_name} must be an object")
            continue
        try:
            count_total = sum(int(value) for value in counts.values())
        except (TypeError, ValueError):
            errors.append(
                f"scene-handler-dispatch: scan_summary.{count_name} values must be integers"
            )
            continue
        if expected_hits is not None and count_total != expected_hits:
            errors.append(
                f"scene-handler-dispatch: scan_summary.{count_name} total "
                f"{count_total} != instruction_hit_count {expected_hits}"
            )

    controls = evidence.get("controls")
    if not isinstance(controls, list) or not controls:
        errors.append("scene-handler-dispatch: controls must be a non-empty array")
    else:
        for index, control in enumerate(controls):
            label = f"scene-handler-dispatch: controls[{index}]"
            if not isinstance(control, dict):
                errors.append(f"{label}: must be an object")
                continue
            try:
                slot = int(str(control.get("slot", "")), 0)
                cmd_id = int(str(control.get("cmd_id", "")), 0)
                method_index = int(str(control.get("method_index", "")), 0)
            except ValueError:
                errors.append(f"{label}: invalid slot/cmd_id/method_index")
                continue
            type_name = str(control.get("type_name", ""))
            method_rva = str(control.get("method_rva", ""))
            found = any(
                slot in row["slots"]
                and row["cmd_id"] == cmd_id
                and row["type_name"] == type_name
                and row["method_index"] == method_index
                and row["method_rva"].lower() == method_rva.lower()
                for row in parsed_rows
            )
            if not found:
                errors.append(f"{label}: control is not present in scene-handler-slots.csv")

    return errors


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="python -m genshinre.scenehandlerartifact",
        description="Validate the persisted scene-handler dispatch analysis artifact.",
    )
    parser.add_argument("version_dir", type=Path)
    args = parser.parse_args()
    errors = validate_scene_handler_dispatch(args.version_dir)
    for error in errors:
        print(f"ERROR: {error}")
    if errors:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
