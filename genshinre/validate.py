from __future__ import annotations

import csv
import json
import re
from pathlib import Path

from .artifactmanifest import validate_generated_manifest
from .cmdobservations import (
    validate_confirmed_semantic_alignment,
    validate_observation_summary,
)
from .contracts import ANALYSIS_STATES, ANALYSIS_STATUSES, MESSAGE_DIRECTIONS
from .registry import ALLOWED_STATUS, CANONICAL_REGISTRY_COLUMNS
from .registryxrefpublish import _validated_known_opcodes
from .scenehandlerartifact import validate_scene_handler_dispatch
from .xrefartifacts import XREF_TABLE_CONTRACTS, validate_xref_table

HEX64 = re.compile(r"^[0-9a-fA-F]{64}$")
HEXADDR = re.compile(r"^0x[0-9A-Fa-f]+$")
HEXBYTES = re.compile(r"^(?:[0-9a-fA-F]{2})*$")

KNOWN_OPCODE_REQUIRED_COLUMNS = (
    "semantic_name",
    "cmd_id",
    "direction",
    "status",
    "evidence",
)
PROTOBUF_WIRE_TYPES = {0, 1, 2, 3, 4, 5}
PUBLICATION_EVIDENCE = (
    "registry/registry.summary.json",
    "metadata/native-decoder-summary.json",
    "metadata/runtime-types.summary.json",
    "metadata/types.csv",
    "metadata/fields.csv",
    "metadata/methods.csv",
    "metadata/method-pointers.csv",
    "registry/getcmdid-candidates.summary.json",
)


def _extend_unique(target: list[str], values: list[str]) -> None:
    seen = set(target)
    for value in values:
        if value not in seen:
            target.append(value)
            seen.add(value)


def _validate_string_list(value: object, label: str, errors: list[str]) -> None:
    if not isinstance(value, list):
        errors.append(f"{label}: must be an array")
        return
    for index, item in enumerate(value):
        if not isinstance(item, str) or not item.strip():
            errors.append(f"{label}[{index}]: must be a non-empty string")


def _validate_evidence_refs(value: object, label: str, errors: list[str]) -> None:
    if not isinstance(value, list):
        errors.append(f"{label}: must be an array")
        return
    for index, item in enumerate(value):
        prefix = f"{label}[{index}]"
        if not isinstance(item, dict):
            errors.append(f"{prefix}: must be an object")
            continue
        for key in ("kind", "source"):
            field = item.get(key)
            if not isinstance(field, str) or not field.strip():
                errors.append(f"{prefix}.{key}: must be a non-empty string")


def _validate_hashes_file(
    hashes_path: Path,
    allow_partial: bool,
    errors: list[str],
    warnings: list[str],
) -> None:
    if not hashes_path.is_file():
        errors.append("missing hashes.json")
        return
    try:
        data = json.loads(hashes_path.read_text(encoding="utf-8"))
    except Exception as exc:
        errors.append(f"hashes.json: {exc}")
        return
    if not isinstance(data, dict):
        errors.append("hashes.json: root must be an object")
        return

    for key in ("game_version", "region", "platform"):
        value = data.get(key)
        if not isinstance(value, str) or not value.strip():
            errors.append(f"hashes.json: {key} must be a non-empty string")

    samples = data.get("samples")
    if not isinstance(samples, dict):
        errors.append("hashes.json: samples must be an object")
        return
    if not samples:
        if allow_partial:
            warnings.append("hashes.json: samples are not fingerprinted yet")
        else:
            errors.append("hashes.json: samples must not be empty")
        return

    for name, sample in samples.items():
        if not isinstance(name, str) or not name.strip():
            errors.append("hashes.json: sample names must be non-empty strings")
            continue
        if not isinstance(sample, dict):
            errors.append(f"hashes.json: sample {name} must be an object")
            continue
        sha = sample.get("sha256")
        if not isinstance(sha, str) or not HEX64.fullmatch(sha):
            errors.append(f"{name}: invalid sha256")


def _validate_analysis_evidence(evidence_path: Path, errors: list[str]) -> None:
    label = evidence_path.as_posix()
    try:
        data = json.loads(evidence_path.read_text(encoding="utf-8"))
    except Exception as exc:
        errors.append(f"{label}: {exc}")
        return
    if not isinstance(data, dict):
        errors.append(f"{label}: root must be an object")
        return

    topic = data.get("topic")
    if not isinstance(topic, str) or not topic.strip():
        errors.append(f"{label}: topic must be a non-empty string")
    elif topic != evidence_path.parent.name:
        errors.append(f"{label}: topic {topic!r} does not match directory {evidence_path.parent.name!r}")

    state = data.get("state")
    if state not in ANALYSIS_STATES:
        errors.append(f"{label}: bad state {state}")

    sample = data.get("sample")
    if not isinstance(sample, dict):
        errors.append(f"{label}: sample must be an object")
    else:
        for key in ("game_version", "region", "platform", "hashes_ref"):
            value = sample.get(key)
            if not isinstance(value, str) or not value.strip():
                errors.append(f"{label}: sample.{key} must be a non-empty string")
        hashes_ref = sample.get("hashes_ref")
        if isinstance(hashes_ref, str) and hashes_ref.strip():
            referenced = evidence_path.parent / hashes_ref
            if not referenced.exists():
                errors.append(f"{label}: sample.hashes_ref does not exist: {hashes_ref}")

    for key in ("questions", "artifacts", "next_steps"):
        if key not in data:
            errors.append(f"{label}: missing {key}")
        else:
            _validate_string_list(data[key], f"{label}:{key}", errors)

    claims = data.get("claims")
    if not isinstance(claims, list):
        errors.append(f"{label}: claims must be an array")
    else:
        seen_ids: set[str] = set()
        for index, claim in enumerate(claims):
            prefix = f"{label}:claims[{index}]"
            if not isinstance(claim, dict):
                errors.append(f"{prefix}: must be an object")
                continue
            claim_id = claim.get("id")
            if not isinstance(claim_id, str) or not claim_id.strip():
                errors.append(f"{prefix}.id: must be a non-empty string")
            elif claim_id in seen_ids:
                errors.append(f"{prefix}.id: duplicate claim id {claim_id}")
            else:
                seen_ids.add(claim_id)
            status = claim.get("status")
            if status not in ANALYSIS_STATUSES:
                errors.append(f"{prefix}: bad status {status}")
            statement = claim.get("statement")
            if not isinstance(statement, str) or not statement.strip():
                errors.append(f"{prefix}.statement: must be a non-empty string")
            _validate_evidence_refs(claim.get("evidence"), f"{prefix}.evidence", errors)

    rejected = data.get("rejected_paths", [])
    if not isinstance(rejected, list):
        errors.append(f"{label}: rejected_paths must be an array")
    else:
        for index, item in enumerate(rejected):
            prefix = f"{label}:rejected_paths[{index}]"
            if not isinstance(item, dict):
                errors.append(f"{prefix}: must be an object")
                continue
            for key in ("statement", "reason"):
                value = item.get(key)
                if not isinstance(value, str) or not value.strip():
                    errors.append(f"{prefix}.{key}: must be a non-empty string")
            if "evidence" in item:
                _validate_evidence_refs(item["evidence"], f"{prefix}.evidence", errors)


def _validate_canonical_registry_publication(path: Path, errors: list[str]) -> None:
    registry_path = path / "registry" / "registry.csv"
    summary_path = path / "registry" / "registry.summary.json"

    if not registry_path.is_file():
        errors.append(
            "generated-artifacts.json: canonical_registry_published is true but registry/registry.csv is missing"
        )
        return
    if not summary_path.is_file():
        errors.append(
            "generated-artifacts.json: canonical_registry_published is true but registry/registry.summary.json is missing"
        )
        return

    try:
        summary = json.loads(summary_path.read_text(encoding="utf-8"))
    except Exception as exc:
        errors.append(f"registry/registry.summary.json: {exc}")
        return
    if not isinstance(summary, dict):
        errors.append("registry/registry.summary.json: root must be an object")
        return

    if summary.get("status") != "canonical-static-identity-registry":
        errors.append(
            "registry/registry.summary.json: status must be canonical-static-identity-registry"
        )
    if summary.get("strict_slot_type_cmd_bijection") is not True:
        errors.append(
            "registry/registry.summary.json: strict_slot_type_cmd_bijection must be true"
        )

    try:
        with registry_path.open("r", encoding="utf-8-sig", newline="") as f:
            reader = csv.DictReader(f)
            fields = tuple(reader.fieldnames or ())
            if fields != CANONICAL_REGISTRY_COLUMNS:
                errors.append(
                    "registry/registry.csv: canonical header mismatch; "
                    f"expected {','.join(CANONICAL_REGISTRY_COLUMNS)}; got {','.join(fields)}"
                )
                return
            rows = list(reader)
        cmd_ids = {int(row["cmd_id"]) for row in rows}
    except Exception as exc:
        errors.append(f"registry/registry.csv canonical publication check: {exc}")
        return

    row_count = len(rows)
    unique_cmd_ids = len(cmd_ids)
    if summary.get("row_count") != row_count:
        errors.append(
            "registry/registry.summary.json: row_count does not match registry.csv "
            f"({summary.get('row_count')} != {row_count})"
        )
    if summary.get("unique_cmd_ids") != unique_cmd_ids:
        errors.append(
            "registry/registry.summary.json: unique_cmd_ids does not match registry.csv "
            f"({summary.get('unique_cmd_ids')} != {unique_cmd_ids})"
        )
    if unique_cmd_ids != row_count:
        errors.append("registry/registry.csv: canonical publication contains duplicate CmdIds")


def _has_publication_evidence(path: Path) -> bool:
    return any((path / rel).exists() for rel in PUBLICATION_EVIDENCE)


def _validate_generated_artifacts(
    path: Path,
    errors: list[str],
    warnings: list[str],
    *,
    allow_partial: bool,
) -> None:
    manifest_path = path / "generated-artifacts.json"
    if not manifest_path.exists():
        message = "missing generated-artifacts.json publication manifest"
        if allow_partial and not _has_publication_evidence(path):
            warnings.append(message)
        else:
            errors.append(message)
        return

    _extend_unique(errors, validate_generated_manifest(path))
    try:
        data = json.loads(manifest_path.read_text(encoding="utf-8"))
    except Exception:
        return
    if not isinstance(data, dict):
        return

    if data.get("canonical_registry_published") is not True:
        errors.append("generated-artifacts.json: canonical_registry_published must be true")
    else:
        _validate_canonical_registry_publication(path, errors)


def _validate_known_opcodes(
    known_path: Path,
    registry_path: Path,
    errors: list[str],
) -> None:
    try:
        with known_path.open("r", encoding="utf-8-sig", newline="") as f:
            reader = csv.DictReader(f)
            fields = tuple(reader.fieldnames or ())
            missing = [column for column in KNOWN_OPCODE_REQUIRED_COLUMNS if column not in fields]
            if missing:
                errors.append(
                    "proto/known-opcodes.csv missing columns: " + ", ".join(missing)
                )
                return
            known_rows = list(reader)
        known_by_cmd = _validated_known_opcodes(known_rows)
    except Exception as exc:
        errors.append(f"proto/known-opcodes.csv: {exc}")
        return

    if not registry_path.exists():
        return

    try:
        with registry_path.open("r", encoding="utf-8-sig", newline="") as f:
            registry_rows = list(csv.DictReader(f))
        registry_by_cmd = {int(row["cmd_id"]): row for row in registry_rows}
    except Exception as exc:
        errors.append(f"proto/known-opcodes.csv registry consistency check: {exc}")
        return

    for cmd_id, known in known_by_cmd.items():
        registry = registry_by_cmd.get(cmd_id)
        if registry is None:
            errors.append(
                f"proto/known-opcodes.csv: CmdId {cmd_id} is missing from registry/registry.csv"
            )
            continue

        semantic_name = str(known.get("semantic_name", "")).strip()
        direction = str(known.get("direction", "")).strip()
        if str(registry.get("semantic_name", "")).strip() != semantic_name:
            errors.append(
                f"registry/registry.csv: CmdId {cmd_id} semantic_name does not match known-opcodes.csv"
            )
        if str(registry.get("direction", "")).strip() != direction:
            errors.append(
                f"registry/registry.csv: CmdId {cmd_id} direction does not match known-opcodes.csv"
            )
        if registry.get("direction_status") != "control-confirmed":
            errors.append(
                f"registry/registry.csv: CmdId {cmd_id} direction_status must be control-confirmed"
            )

    summary_path = registry_path.with_name("registry.summary.json")
    canonical = False
    if summary_path.exists():
        try:
            summary = json.loads(summary_path.read_text(encoding="utf-8"))
        except Exception as exc:
            errors.append(f"registry/registry.summary.json: {exc}")
            return
        if not isinstance(summary, dict):
            errors.append("registry/registry.summary.json: root must be an object")
            return
        canonical = summary.get("status") == "canonical-static-identity-registry"

    if canonical:
        enriched_cmds = {
            int(row["cmd_id"])
            for row in registry_rows
            if str(row.get("semantic_name", "")).strip()
            or str(row.get("direction", "")).strip() in {"C2S", "S2C"}
        }
        known_cmds = set(known_by_cmd)
        if enriched_cmds != known_cmds:
            extra = sorted(enriched_cmds - known_cmds)
            missing = sorted(known_cmds - enriched_cmds)
            errors.append(
                "registry/registry.csv: canonical semantic enrichment does not match "
                f"proto/known-opcodes.csv; extra={extra[:20]} missing={missing[:20]}"
            )


def _validate_message_shapes(shapes_path: Path, errors: list[str]) -> None:
    label = "proto/message-shapes.json"
    try:
        shapes = json.loads(shapes_path.read_text(encoding="utf-8"))
    except Exception as exc:
        errors.append(f"{label}: {exc}")
        return
    if not isinstance(shapes, dict):
        errors.append(f"{label}: root must be an object")
        return

    seen_cmd_ids: dict[int, str] = {}
    for message_name, shape in shapes.items():
        prefix = f"{label}:{message_name}"
        if not isinstance(shape, dict):
            errors.append(f"{prefix}: must be an object")
            continue

        cmd_id = shape.get("cmd_id")
        if isinstance(cmd_id, bool) or not isinstance(cmd_id, int) or not 0 <= cmd_id <= 65535:
            errors.append(f"{prefix}: cmd_id must be an integer in 0..65535")
        elif cmd_id in seen_cmd_ids:
            errors.append(
                f"{prefix}: duplicate cmd_id {cmd_id} already used by {seen_cmd_ids[cmd_id]}"
            )
        else:
            seen_cmd_ids[cmd_id] = str(message_name)

        direction = shape.get("direction")
        if direction not in MESSAGE_DIRECTIONS:
            errors.append(f"{prefix}: bad direction {direction}")

        status = shape.get("status")
        if status not in ANALYSIS_STATUSES:
            errors.append(f"{prefix}: bad status {status}")

        for key in ("evidence",):
            if key in shape and (not isinstance(shape[key], str) or not shape[key].strip()):
                errors.append(f"{prefix}.{key}: must be a non-empty string")

        payload_hex = shape.get("observed_payload_hex")
        if payload_hex is not None and (
            not isinstance(payload_hex, str) or not HEXBYTES.fullmatch(payload_hex)
        ):
            errors.append(f"{prefix}.observed_payload_hex: must be whole-byte hex")

        fields = shape.get("fields")
        if not isinstance(fields, list):
            errors.append(f"{prefix}.fields: must be an array")
            continue

        seen_field_numbers: set[int] = set()
        for index, field in enumerate(fields):
            field_prefix = f"{prefix}.fields[{index}]"
            if not isinstance(field, dict):
                errors.append(f"{field_prefix}: must be an object")
                continue

            number = field.get("number")
            if (
                isinstance(number, bool)
                or not isinstance(number, int)
                or not 1 <= number <= 536870911
            ):
                errors.append(
                    f"{field_prefix}.number: must be an integer in 1..536870911"
                )
            elif number in seen_field_numbers:
                errors.append(f"{field_prefix}.number: duplicate field number {number}")
            else:
                seen_field_numbers.add(number)

            wire_type = field.get("wire_type")
            if (
                isinstance(wire_type, bool)
                or not isinstance(wire_type, int)
                or wire_type not in PROTOBUF_WIRE_TYPES
            ):
                errors.append(f"{field_prefix}.wire_type: invalid protobuf wire type")

            for key in ("likely_type", "semantic"):
                if key in field and (
                    not isinstance(field[key], str) or not field[key].strip()
                ):
                    errors.append(f"{field_prefix}.{key}: must be a non-empty string")

            value_hex = field.get("observed_value_hex")
            if value_hex is not None and (
                not isinstance(value_hex, str) or not HEXBYTES.fullmatch(value_hex)
            ):
                errors.append(f"{field_prefix}.observed_value_hex: must be whole-byte hex")

            packed = field.get("packed_varint_candidate")
            if packed is not None:
                if not isinstance(packed, list):
                    errors.append(f"{field_prefix}.packed_varint_candidate: must be an array")
                elif any(
                    isinstance(value, bool) or not isinstance(value, int) or value < 0
                    for value in packed
                ):
                    errors.append(
                        f"{field_prefix}.packed_varint_candidate: values must be non-negative integers"
                    )


def validate_version(path: Path, allow_partial: bool = False) -> tuple[list[str], list[str]]:
    errors: list[str] = []
    warnings: list[str] = []

    _validate_hashes_file(path / "hashes.json", allow_partial, errors, warnings)

    registry_path = path / "registry" / "registry.csv"
    if registry_path.exists():
        try:
            with registry_path.open("r", encoding="utf-8-sig", newline="") as f:
                reader = csv.DictReader(f)
                fields = tuple(reader.fieldnames or ())
                if fields != CANONICAL_REGISTRY_COLUMNS:
                    errors.append(
                        "registry.csv canonical header mismatch; "
                        f"expected {','.join(CANONICAL_REGISTRY_COLUMNS)}; got {','.join(fields)}"
                    )

                seen: set[int] = set()
                for line_no, row in enumerate(reader, start=2):
                    cmd = int(row["cmd_id"])
                    if not 0 <= cmd <= 65535:
                        errors.append(f"registry.csv:{line_no}: cmd_id out of range")
                    if cmd in seen:
                        errors.append(f"registry.csv:{line_no}: duplicate cmd_id {cmd}")
                    seen.add(cmd)
                    direction = row.get("direction", "")
                    if direction not in ({""} | MESSAGE_DIRECTIONS):
                        errors.append(f"registry.csv:{line_no}: bad direction {direction}")
                    status = row.get("status", "")
                    if status not in ALLOWED_STATUS:
                        errors.append(f"registry.csv:{line_no}: bad status {status}")
                    for column in ("type_slot_rva", "get_cmd_id_rva"):
                        value = row.get(column, "")
                        if value and not HEXADDR.fullmatch(value):
                            errors.append(f"registry.csv:{line_no}: bad {column} {value}")
        except Exception as exc:
            errors.append(f"registry.csv: {exc}")
    elif allow_partial:
        warnings.append("registry/registry.csv is not generated yet")
    else:
        errors.append("missing registry/registry.csv")

    known_path = path / "proto" / "known-opcodes.csv"
    if known_path.exists():
        _validate_known_opcodes(known_path, registry_path, errors)
    else:
        (warnings if allow_partial else errors).append("missing proto/known-opcodes.csv")

    shapes_path = path / "proto" / "message-shapes.json"
    if shapes_path.exists():
        _validate_message_shapes(shapes_path, errors)
    elif allow_partial:
        warnings.append("proto/message-shapes.json is not generated yet")
    else:
        errors.append("missing proto/message-shapes.json")

    analyses_path = path / "analyses"
    if analyses_path.exists():
        for evidence_path in sorted(analyses_path.glob("*/evidence.json")):
            _validate_analysis_evidence(evidence_path, errors)

    _extend_unique(errors, validate_scene_handler_dispatch(path))

    _validate_generated_artifacts(
        path,
        errors,
        warnings,
        allow_partial=allow_partial,
    )

    observations = path / "cmdids" / "observations.csv"
    if observations.is_file():
        _extend_unique(errors, validate_observation_summary(observations))
        if known_path.is_file():
            _extend_unique(
                errors,
                validate_confirmed_semantic_alignment(observations, known_path),
            )

    xref_dir = path / "xrefs"
    for filename in XREF_TABLE_CONTRACTS:
        table = xref_dir / filename
        if table.is_file():
            _extend_unique(errors, validate_xref_table(table))

    for rel in (
        "metadata/types.csv",
        "metadata/methods.csv",
        "metadata/fields.csv",
        "metadata/method-pointers.csv",
        "xrefs/message-handlers.csv",
        "xrefs/message-senders.csv",
    ):
        if not (path / rel).exists():
            warnings.append(f"pending high-value artifact: {rel}")

    return errors, warnings
