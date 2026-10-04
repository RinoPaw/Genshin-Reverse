from __future__ import annotations

from .registrycontract import (
    ALLOWED_STATUS,
    CANONICAL_REGISTRY_COLUMNS,
    EXPECTED_REGISTRY_ROW_COUNT,
)

__all__ = [
    "ALLOWED_STATUS",
    "CANONICAL_REGISTRY_COLUMNS",
    "EXPECTED_REGISTRY_ROW_COUNT",
    "query_registry",
]


def __getattr__(name: str):
    if name == "query_registry":
        from .registryquery import query_registry

        return query_registry
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def __dir__() -> list[str]:
    return sorted(set(globals()) | {"query_registry"})
