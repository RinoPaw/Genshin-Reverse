from __future__ import annotations

from dataclasses import dataclass

from .mhy71 import (
    BODY_SKIP,
    EMBEDDED_HEADER_RVA,
    EMBEDDED_HEADER_SIZE,
    EXPECTED_EXE_SHA256,
    EXPECTED_FIELD_COUNT,
    EXPECTED_METADATA_SHA256,
    EXPECTED_METHOD_COUNT,
    EXPECTED_TYPE_COUNT,
    METHOD_POINTER_TABLE_RVA,
    TYPE_ARRAY_POINTER_RVA,
)


@dataclass(frozen=True)
class RuntimeTypeAnchor:
    type_index: int
    kind: int
    type_definition_index: int
    type_name: str


@dataclass(frozen=True)
class GetCmdIdAnchor:
    cmd_id: int
    type_name: str
    rva: int


@dataclass(frozen=True)
class NativeProfile:
    version: str
    region: str
    platform: str
    exe_sha256: str
    metadata_sha256: str
    type_definition_count: int
    field_count: int
    method_count: int
    metadata_body_skip: int
    embedded_header_rva: int
    embedded_header_size: int
    type_array_pointer_rva: int
    method_pointer_table_rva: int
    runtime_type_count: int
    runtime_type_boundary_rva: int
    runtime_type_anchor: RuntimeTypeAnchor
    getcmdid_anchor: GetCmdIdAnchor

    @property
    def identity(self) -> str:
        return f"{self.version}-{self.region}/{self.platform}"


PROFILE_71 = NativeProfile(
    version="7.1.0",
    region="global",
    platform="windows-x64",
    exe_sha256=EXPECTED_EXE_SHA256,
    metadata_sha256=EXPECTED_METADATA_SHA256,
    type_definition_count=EXPECTED_TYPE_COUNT,
    field_count=EXPECTED_FIELD_COUNT,
    method_count=EXPECTED_METHOD_COUNT,
    metadata_body_skip=BODY_SKIP,
    embedded_header_rva=EMBEDDED_HEADER_RVA,
    embedded_header_size=EMBEDDED_HEADER_SIZE,
    type_array_pointer_rva=TYPE_ARRAY_POINTER_RVA,
    method_pointer_table_rva=METHOD_POINTER_TABLE_RVA,
    runtime_type_count=683_574,
    runtime_type_boundary_rva=0x388CD80,
    runtime_type_anchor=RuntimeTypeAnchor(
        type_index=405_772,
        kind=0x12,
        type_definition_index=84_249,
        type_name="DMMJNICDOHM",
    ),
    getcmdid_anchor=GetCmdIdAnchor(
        cmd_id=26_105,
        type_name="HJDNCHODGOL",
        rva=0x10587260,
    ),
)


PROFILES = {PROFILE_71.identity: PROFILE_71}


def get_native_profile(identity: str) -> NativeProfile:
    try:
        return PROFILES[identity]
    except KeyError as exc:
        raise KeyError(f"unknown native profile {identity!r}") from exc
