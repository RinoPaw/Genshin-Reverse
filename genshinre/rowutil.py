from __future__ import annotations


def parse_optional_int(value: object) -> int | None:
    """Parse a decimal/0x-prefixed scalar, returning None for blank or invalid input."""

    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    try:
        return int(text, 0)
    except ValueError:
        return None


def int_matches(value: object, expected: int | None) -> bool:
    """Return whether a scalar matches an optional integer filter."""

    if expected is None:
        return True
    return parse_optional_int(value) == expected
