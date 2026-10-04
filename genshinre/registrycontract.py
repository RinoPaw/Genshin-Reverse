from __future__ import annotations

from .contracts import ANALYSIS_STATUSES
from .nativeprofile import PROFILE_71

EXPECTED_REGISTRY_ROW_COUNT = PROFILE_71.registry_row_count

CANONICAL_REGISTRY_COLUMNS = (
    "index",
    "cmd_id",
    "type_name",
    "type_definition_index",
    "direction",
    "direction_status",
    "semantic_name",
    "type_slot_rva",
    "get_cmd_id_rva",
    "get_cmd_id_method",
    "load_rva",
    "store_rva",
    "xref_count",
    "xref_method_count",
    "status",
    "evidence",
)

ALLOWED_STATUS = {""} | ANALYSIS_STATUSES | {
    "runtime-verified",
    "static-verified",
    "static-verified-identity",
    "cross-project-supported",
    "observed-unresolved",
    "mapped-not-observed",
    "historical-only",
    "hypothesis",
}
