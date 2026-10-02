from __future__ import annotations

import csv
from pathlib import Path

from .contracts import ANALYSIS_STATUSES, MESSAGE_DIRECTIONS

COLUMNS = ("name", "cmd_id", "direction", "status", "evidence")


def validate_observation_summary(path: Path) -> list[str]:
    """Validate the version-level CmdId semantic observation summary.

    This table is distinct from raw trace-import CSVs. A blank CmdId is allowed for
    a named unresolved semantic target such as a response whose current mapping is
    still unknown.
    """

    errors: list[str] = []
    seen_names: set[str] = set()
    try:
        with path.open("r", encoding="utf-8-sig", newline="") as f:
            reader = csv.DictReader(f)
            actual = tuple(reader.fieldnames or ())
            if actual != COLUMNS:
                return [
                    f"{path.name}: header mismatch; expected {','.join(COLUMNS)}; "
                    f"got {','.join(actual)}"
                ]

            for line_no, row in enumerate(reader, start=2):
                prefix = f"{path.name}:{line_no}"
                name = str(row.get("name", "")).strip()
                if not name:
                    errors.append(f"{prefix}: name must be non-empty")
                elif name in seen_names:
                    errors.append(f"{prefix}: duplicate name {name}")
                else:
                    seen_names.add(name)

                cmd_text = str(row.get("cmd_id", "")).strip()
                if cmd_text:
                    try:
                        cmd_id = int(cmd_text, 0)
                    except ValueError:
                        errors.append(f"{prefix}: bad cmd_id {cmd_text}")
                    else:
                        if not 0 <= cmd_id <= 65535:
                            errors.append(f"{prefix}: cmd_id out of range {cmd_id}")

                direction = str(row.get("direction", "")).strip()
                if direction not in MESSAGE_DIRECTIONS:
                    errors.append(f"{prefix}: bad direction {direction}")

                status = str(row.get("status", "")).strip()
                if status not in ANALYSIS_STATUSES:
                    errors.append(f"{prefix}: bad status {status}")

                evidence = str(row.get("evidence", "")).strip()
                if not evidence:
                    errors.append(f"{prefix}: evidence must be non-empty")
    except Exception as exc:
        errors.append(f"{path.name}: {exc}")

    return errors


def validate_confirmed_semantic_alignment(
    observations_path: Path,
    known_opcodes_path: Path,
) -> list[str]:
    """Ensure confirmed observation-summary rows agree with canonical semantics.

    Candidate and unresolved rows intentionally remain outside this gate. The
    observation summary may also be a subset of the canonical semantic table.
    """

    errors: list[str] = []
    try:
        with known_opcodes_path.open("r", encoding="utf-8-sig", newline="") as f:
            known_rows = list(csv.DictReader(f))
        known_by_cmd = {
            int(str(row["cmd_id"]).strip(), 0): row
            for row in known_rows
            if str(row.get("cmd_id", "")).strip()
        }

        with observations_path.open("r", encoding="utf-8-sig", newline="") as f:
            for line_no, row in enumerate(csv.DictReader(f), start=2):
                if str(row.get("status", "")).strip() != "CONFIRMED":
                    continue
                cmd_text = str(row.get("cmd_id", "")).strip()
                if not cmd_text:
                    errors.append(
                        f"{observations_path.name}:{line_no}: CONFIRMED row must have cmd_id"
                    )
                    continue
                try:
                    cmd_id = int(cmd_text, 0)
                except ValueError:
                    continue

                known = known_by_cmd.get(cmd_id)
                if known is None:
                    errors.append(
                        f"{observations_path.name}:{line_no}: confirmed CmdId {cmd_id} "
                        "is absent from proto/known-opcodes.csv"
                    )
                    continue

                name = str(row.get("name", "")).strip()
                known_name = str(known.get("semantic_name", "")).strip()
                if name != known_name:
                    errors.append(
                        f"{observations_path.name}:{line_no}: CmdId {cmd_id} name {name!r} "
                        f"does not match known-opcodes {known_name!r}"
                    )

                direction = str(row.get("direction", "")).strip()
                known_direction = str(known.get("direction", "")).strip()
                if direction != known_direction:
                    errors.append(
                        f"{observations_path.name}:{line_no}: CmdId {cmd_id} direction "
                        f"{direction!r} does not match known-opcodes {known_direction!r}"
                    )
    except Exception as exc:
        errors.append(f"confirmed observation alignment: {exc}")

    return errors
