from __future__ import annotations

from pathlib import Path

from .metadataindex import build_type_methods

_QUERY_EXPORTS = (
    "load_methods",
    "query_fields",
    "query_method_references",
    "query_methods",
)

__all__ = ["build_type_methods", *_QUERY_EXPORTS]


def __getattr__(name: str):
    if name not in _QUERY_EXPORTS:
        raise AttributeError(name)
    from . import metadataquery

    return getattr(metadataquery, name)


def __dir__() -> list[str]:
    return sorted(set(globals()) | set(_QUERY_EXPORTS))
