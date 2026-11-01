"""Pinned Global 7.1 IL2CPP evidence for original world-sector placement and colliders."""
from __future__ import annotations

import csv
import hashlib
from pathlib import Path

from .nativeprofile import PROFILE_71
from .pe import PEImage


# Type-definition indexes independently recovered from the exact 7.1 metadata.
OWNERS = {
    16791: ("SECTR_SceneSplitterConfig", ("colliderLayerConfig", "colliderLayerSceneWhiteList", "colliderInOffsetSectorBlackList")),
    53867: ("SECTR_FinMap", ("voFinInfos", "lodFinInfos")),
    55978: ("SECTR_GlobalConfig", ("keyColliderLayers", "keyRenderLayers")),
    57495: ("NFFDDFHHDHG", ("_x", "_y", "_z")),
    57654: ("SECTR_LayerConfig", ("layerName", "sectorSize", "sectorHeight")),
    58901: ("SECTR_StreamObjectSerialize", ("_gameObjectPathHash", "_position", "_rotation", "_scale")),
    60723: ("SectorBinData", ("datas",)),
    63117: ("SECTR_StreamerRoot", ("configName", "worldName", "SectorNameList")),
    71958: ("SECTR_LODFinInfo", ("colliderPathHash", "simpleColliderPathHash")),
    78003: ("SECTR_AllBigWorld", ("sectorPath", "sectorSize", "loadedSectors")),
    79550: ("SECTR_StreamingProfile", ("colliderLoadRadius",)),
}

TYPE_SIGNATURES = {
    (57495, "_x"): "float32",
    (57495, "_y"): "float32",
    (57495, "_z"): "float32",
    (58901, "_gameObjectPathHash"): "uint64",
    (58901, "_position"): "NFFDDFHHDHG",
    (58901, "_rotation"): "NFFDDFHHDHG",
    (58901, "_scale"): "NFFDDFHHDHG",
    (71958, "colliderPathHash"): "uint64",
    (71958, "simpleColliderPathHash"): "uint64",
    (79550, "colliderLoadRadius"): "float32",
}


def file_sha256(path: Path) -> str:
    hash_value = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(8 * 1024 * 1024), b""):
            hash_value.update(block)
    return hash_value.hexdigest()


def selected_rows(path: Path, key: str) -> dict[int, list[dict[str, str]]]:
    found: dict[int, list[dict[str, str]]] = {idx: [] for idx in OWNERS}
    with path.open("r", newline="", encoding="utf-8-sig") as file:
        for row in csv.DictReader(file):
            idx = int(row["type_definition_index"])
            if idx in found:
                found[idx].append(row)
    return found


def extract_metadata(types: Path, fields: Path, methods: Path) -> dict:
    type_rows = selected_rows(types, "type_definition_index")
    field_rows = selected_rows(fields, "type_definition_index")
    method_rows = selected_rows(methods, "type_definition_index")
    owners = []
    for type_id, (name, required) in OWNERS.items():
        rows = type_rows[type_id]
        if len(rows) != 1 or rows[0]["type_name"] != name:
            raise ValueError(f"original 7.1 owner type missing or changed: {type_id} {name}")
        field_by_name = {r["field_name"]: r for r in field_rows[type_id]}
        if len(field_by_name) != len(field_rows[type_id]):
            raise ValueError(f"duplicate native field name in {name}")
        for field_name in required:
            if field_name not in field_by_name:
                raise ValueError(f"missing original field {name}.{field_name}")
            actual = field_by_name[field_name]["field_type"]
            expected = TYPE_SIGNATURES.get((type_id, field_name))
            if expected and actual != expected:
                raise ValueError(f"{name}.{field_name} native type changed: {actual}")
        owners.append({
            "typeDefinitionIndex": type_id,
            "namespace": rows[0]["namespace"],
            "typeName": name,
            "fieldCount": len(field_rows[type_id]),
            "methods": [
                {"name": r["method_name"], "rva": r["rva"]}
                for r in method_rows[type_id] if r["method_name"] in
                ("Read", "Write", "set_position", "set_rotation", "set_scale", "GetSortedLodInfos")
            ],
            "fields": [
                {"index": int(field_by_name[n]["field_index"]),
                 "name": n, "type": field_by_name[n]["field_type"],
                 "typeIndex": int(field_by_name[n]["field_type_index"])}
                for n in required
            ],
        })
    return {"owners": owners}


def verify_original_exe(exe: Path) -> dict:
    if file_sha256(exe) != PROFILE_71.exe_sha256:
        raise ValueError("GenshinImpact.exe is not the pinned Global 7.1 sample")
    with PEImage(exe) as pe:
        pointer = pe.read_rva(PROFILE_71.type_array_pointer_rva, 8)
        array_rva = int.from_bytes(pointer, "little") - pe.image_base
        record = pe.read_rva(array_rva + 476832 * 16, 16)
        if record[10] != 0x11 or int.from_bytes(record[:4], "little") != 57495:
            raise ValueError("original vector triple type-array anchor does not match")
    return {
        "sha256": PROFILE_71.exe_sha256,
        "vectorTypeIndex": 476832,
        "vectorTypeKind": "valuetype",
        "vectorTypeDefinitionIndex": 57495,
    }


def generate_report(exe: Path, metadata_dir: Path) -> dict:
    names = ("types.csv", "fields.csv", "methods.csv")
    inputs = [metadata_dir / name for name in names]
    report = extract_metadata(*inputs)
    return {
        "schemaVersion": 1,
        "target": "Genshin Impact Global 7.1 Windows x64",
        "nativeExecutable": verify_original_exe(exe),
        "metadataCsvSha256": {p.name: file_sha256(p) for p in inputs},
        **report,
        "evidence": {
            "serializedWorldObjectTransforms": "CONFIRMED_NATIVE_FIELDS",
            "colliderLayerConfiguration": "CONFIRMED_NATIVE_FIELDS",
            "colliderAssetHashes": "CONFIRMED_NATIVE_FIELDS",
            "sectorInstancesOrPlacementPayload": "UNRESOLVED",
            "meshCollisionBindings": "UNRESOLVED",
            "safeServerWorldHeightQuery": False,
            "limit": "Field declarations and native type-anchor are evidence of serialized schema, not decoded sector instances or collision enabled states.",
        },
    }
