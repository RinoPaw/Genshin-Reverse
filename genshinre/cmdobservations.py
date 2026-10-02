from __future__ import annotations

import csv
from pathlib import Path

from .validate import ANALYSIS_STATUSES, MESSAGE_DIRECTIONS

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
