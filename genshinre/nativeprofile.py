from __future__ import annotations

from dataclasses import dataclass


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


# Exact-sample constants live here so current-client generators, validators and
# future version profiles share one explicit target contract. Decoder modules
# may expose implementation-local aliases, but CI crosschecks them against this
# profile and committed artifacts.
PROFILE_71 = NativeProfile(
    version="7.1.0",
    region="global",
    platform="windows-x64",
    exe_sha256="08a3086d5f3fe695f01dab61efa42e442006b18e5e475b2520df356f6a073b7d",
    metadata_sha256="05ae04d7a91b91cc880217a56b0b01f3e67f845b06e894216654ec5d160e0da0",
    type_definition_count=88_904,
    field_count=440_172,
    method_count=733_442,
    metadata_body_skip=0x210,
    embedded_header_rva=0x027D4BD0,
    embedded_header_size=0x210,
    type_array_pointer_rva=0x02870AD0,
    method_pointer_table_rva=0x02870B90,
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
