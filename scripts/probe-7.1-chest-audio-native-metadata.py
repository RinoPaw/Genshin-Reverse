#!/usr/bin/env python3
"""Cross-check two public 7.1 audio chest field tokens in exact native metadata.

A matching native field token narrows candidate row classes. It does not prove
the table's actual serialized row reader or an official chest payout meaning.
"""
from __future__ import annotations

import argparse
from collections import defaultdict
import csv
import hashlib
import json
from pathlib import Path

from genshinre.nativeprofile import PROFILE_71

FIELDS_GIT_BLOB = "ae01d117f4d884e891a95d529a15302a68715b04"
METHODS_GIT_BLOB = "a9c106a7fdd5fe97ad204d6f4641c1e2c8d5433a"
TARGET_TOKENS = ("AIMCCDKDAKB", "DMNAJDGMHDE")
METHOD_ROWS_LIMIT = 128


def blob_hash(path: Path) -> str:
    hasher = hashlib.sha1()
    hasher.update(f"blob {path.stat().st_size}\0".encode("ascii"))
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            hasher.update(block)
    return hasher.hexdigest()


def inspect(fields_path: Path, methods_path: Path, *, require_original: bool = True) -> dict:
    if require_original:
        for path, expected in ((fields_path, FIELDS_GIT_BLOB), (methods_path, METHODS_GIT_BLOB)):
            if blob_hash(path) != expected:
                raise ValueError(f"original native 7.1 metadata CSV Git blob mismatch: {path.name}")
    hit: dict[str, list[dict]] = {name: [] for name in TARGET_TOKENS}
    owners: dict[str, list[dict]] = defaultdict(list)
    with fields_path.open(encoding="utf-8-sig", newline="") as stream:
        for field in csv.DictReader(stream):
            name = field.get("field_name", "")
            if name not in TARGET_TOKENS:
                continue
            index = field["type_definition_index"]
            row = {
                "fieldIndex": field["field_index"],
                "ownerTypeDefinitionIndex": index,
                "ownerName": field.get("type_name", ""),
                "fieldName": name,
                "fieldType": field.get("field_type", ""),
                "fieldTypeIndex": field.get("field_type_index", ""),
                "nativeMemoryOffsetCandidate": field.get("offset", ""),
            }
            hit[name].append(row)
            owners[index].append(row)
    for index, matched in owners.items():
        if len({row["fieldName"] for row in matched}) == len(TARGET_TOKENS):
            if len(matched) != len(TARGET_TOKENS):
                raise ValueError(f"duplicate source token fields in owner {index}")
    methods: dict[str, list[dict]] = {idx: [] for idx in owners}
    if owners:
        with methods_path.open(encoding="utf-8-sig", newline="") as stream:
            for method in csv.DictReader(stream):
                owner = method["type_definition_index"]
                if owner not in methods:
                    continue
                if len(methods[owner]) >= METHOD_ROWS_LIMIT:
                    raise ValueError(f"unbounded metadata method rows for owner {owner}")
                methods[owner].append({
                    "methodIndex": method["method_index"],
                    "ownerName": method.get("type_name", ""),
                    "methodName": method.get("method_name", ""),
                    "rva": method.get("rva", ""),
                    "returnType": method.get("return_type", ""),
                    "parameterTypes": method.get("parameter_types", ""),
                    "candidateBinReaderSignature": "FNIAHJGHFAK" in method.get("parameter_types", ""),
                })
    paired = [index for index, matched in owners.items()
              if {row["fieldName"] for row in matched} == set(TARGET_TOKENS)]
    return {
        "schemaVersion": 1,
        "status": "ORIGINAL_71_METADATA_AUDIO_CHEST_TOKEN_SEARCH__TABLE_ROW_IDENTITY_UNVERIFIED",
        "sample": PROFILE_71.identity,
        "exactExeSha256": PROFILE_71.exe_sha256,
        "exactMetadataSha256": PROFILE_71.metadata_sha256,
        "fieldsGitBlob": FIELDS_GIT_BLOB if require_original else None,
        "methodsGitBlob": METHODS_GIT_BLOB if require_original else None,
        "communityFieldNameHypotheses": list(TARGET_TOKENS),
        "fieldTokenHitCounts": {name: len(rows) for name, rows in hit.items()},
        "ownerCandidates": {
            index: {"fieldMatches": rows, "methods": methods[index]}
            for index, rows in sorted(owners.items(), key=lambda kv: int(kv[0]))
        },
        "ownerWithBothTokens": sorted(paired, key=int),
        "limitations": [
            "Public CN JSON provides token spelling hypotheses; the exact source-guarded metadata alone establishes original field token identities.",
            "A co-owning type is a candidate; field type/offset and method signature do not prove it represents the audio table.",
            "No source byte-consuming row reader, actual enum strings, native table row count, scene instance, grade or payout is authenticated.",
        ],
    }


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--fields", type=Path, default=Path("versions/7.1.0-global/windows-x64/metadata/fields.csv"))
    p.add_argument("--methods", type=Path, default=Path("versions/7.1.0-global/windows-x64/metadata/methods.csv"))
    p.add_argument("--output", type=Path)
    args = p.parse_args()
    result = inspect(args.fields, args.methods)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(result, indent=2, ensure_ascii=False)+"\n", encoding="utf-8")
    print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
