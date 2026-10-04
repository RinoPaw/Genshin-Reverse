from __future__ import annotations

import json


def parse_parameter_types(value: str) -> list[str]:
    """Parse the JSON-encoded parameter_types cell used by metadata CSV artifacts."""

    value = (value or "").strip()
    if not value:
        return []
    parsed = json.loads(value)
    if not isinstance(parsed, list):
        raise ValueError("parameter_types must be a JSON array")
    return [str(item) for item in parsed]
