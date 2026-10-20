#!/usr/bin/env python3
"""Probe *field-name identities* in exact Global 7.1 native IL2CPP metadata.

Keys come from a separate CN-labelled community GadgetExcel projection.
A matching token alone does not validate its semantic label, row placement,
native wire reader or the projection's source integrity.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
from collections import defaultdict
from pathlib import Path

from genshinre.nativeprofile import PROFILE_71

# The three opaque CN-7.1 Chest-only keys whose source-copy presence differs.
TOKENS = ("NGDGAAEHPHB", "MECPCDBEFBG", "OLOLLKJCHHI")
FIELDS_BLOB = "ae01d117f4d884e891a95d529a15302a68715b04"
METHODS_BLOB = "a9c106a7fdd5fe97ad204d6f4641c1e2c8d5433a"


def git_blob(path: Path) -> str:
    digest = hashlib.sha1()
    digest.update(f"blob {path.stat().st_size}\0".encode())
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def locate(fields: Path, methods: Path, *, check_sources: bool = True) -> dict:
    if check_sources:
        for path, expected in ((fields, FIELDS_BLOB), (methods, METHODS_BLOB)):
            actual = git_blob(path)
            if actual != expected:
                raise ValueError(f"{path.name}: pinned metadata Git blob mismatch: {actual}")

    token_hits = defaultdict(list)
    owners = set()
    with fields.open(newline="", encoding="utf-8-sig") as stream:
        for row in csv.DictReader(stream):
            if row.get("field_name") in TOKENS:
                owner_index = row["type_definition_index"]
                owners.add(owner_index)
                token_hits[row["field_name"]].append({
                    "fieldIndex": row["field_index"],
                    "ownerIndex": owner_index,
                    "ownerName": row.get("type_name", ""),
                    "fieldType": row.get("field_type", ""),
                })

    field_records = defaultdict(list)
    method_records = defaultdict(list)
    if owners:
        with fields.open(newline="", encoding="utf-8-sig") as stream:
            for row in csv.DictReader(stream):
                if row["type_definition_index"] in owners:
                    field_records[row["type_definition_index"]].append({
                        "name": row["field_name"], "type": row.get("field_type", ""),
                        "index": row["field_index"],
                    })
        with methods.open(newline="", encoding="utf-8-sig") as stream:
            for row in csv.DictReader(stream):
                if row["type_definition_index"] in owners:
                    method_records[row["type_definition_index"]].append({
                        "name": row.get("method_name", ""),
                        "methodIndex": row["method_index"],
                        "rva": row.get("rva", ""),
                        "parameterTypes": row.get("parameter_types", ""),
                        "binaryReaderSignatureCandidate": "FNIAHJGHFAK" in row.get("parameter_types", ""),
                    })

    return {
        "schemaVersion": 1,
        "sample": PROFILE_71.identity,
        "status": ("NATIVE_METADATA_TOKEN_IDENTITIES_ONLY__WIRE_SCHEMA_UNRESOLVED"
                   if owners else "NO_COMMUNITY_TOKENS_IN_PINNED_NATIVE_METADATA"),
        "metadata": {
            "exeSha256": PROFILE_71.exe_sha256,
            "globalMetadataSha256": PROFILE_71.metadata_sha256,
            "fieldsCsvGitBlob": FIELDS_BLOB if check_sources else None,
            "methodsCsvGitBlob": METHODS_BLOB if check_sources else None,
        },
        "hypothesisSource": "CN 7.1 community GadgetExcel Chest-key presence comparison",
        "tokens": list(TOKENS),
        "tokenHits": {token: token_hits[token] for token in TOKENS},
        "matchedOwnerCount": len(owners),
        "owners": {
            index: {
                "fieldCount": len(field_records[index]),
                "fields": field_records[index],
                "methods": method_records[index],
            } for index in sorted(owners, key=int)
        },
        "limitations": [
            "Matching an obfuscated field token does not identify its GadgetExcel table or row.",
            "A method with a candidate binary-reader parameter is not a verified deserializer.",
            "Field names and types do not establish wire offsets, enum meanings, chest grade or reward roots.",
            "CN community key presence/absence remains an independent cross-source comparison.",
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fields", type=Path, default=Path(
        "versions/7.1.0-global/windows-x64/metadata/fields.csv"))
    parser.add_argument("--methods", type=Path, default=Path(
        "versions/7.1.0-global/windows-x64/metadata/methods.csv"))
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    report = locate(args.fields, args.methods)
    encoded = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(encoded, encoding="utf-8")
    print(encoded, end="")


if __name__ == "__main__":
    main()
