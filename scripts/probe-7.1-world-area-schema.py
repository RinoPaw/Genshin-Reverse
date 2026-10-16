#!/usr/bin/env python3
"""Find metadata-verified owners/readers for obfuscated WorldArea resource keys.

Do not promote key names to native semantics until the exact 7.1 metadata
and deserializer have been independently inspected.
"""
from __future__ import annotations

import argparse
import csv
import json
from collections import defaultdict
from pathlib import Path

FIELDS = (
    "OBKNAJCIHEA",   # world area root array in community source
    "LKBLPFHOAFB",   # area parent record in community source
    "OPHHFKKPLDI",   # child collection
    "JLFEAGHGCLP",   # geometric shape
    "BFLLDPOAJGD",   # polygon vertices
    "BBLLBIOLMHP",   # areaID1
    "EOIFEEDBAFJ",   # areaID2
    "MHLOLALFHHF",   # shape minimum height
    "NFFDCMLAAFO",   # shape maximum height
)
RELATED_OWNER_NAMES = ("CEBMPFCJPGE", "EOFNANCNGFK")


def locate(fields_csv: Path, methods_csv: Path) -> dict:
    matches = defaultdict(list)
    owning_indices: set[int] = set()
    owners_by_index: dict[int, str] = {}
    with fields_csv.open(encoding="utf-8-sig", newline="") as f:
        for row in csv.DictReader(f):
            if row.get("field_name") in FIELDS:
                idx = int(row["type_definition_index"], 0)
                owning_indices.add(idx)
                owners_by_index[idx] = row.get("type_name", "")
    # Recover *all* fields from a located owner, not just the matched names.
    # This is essential to reconstruct its native reader's complete layout.
    with fields_csv.open(encoding="utf-8-sig", newline="") as f:
        for row in csv.DictReader(f):
            owner = row.get("type_name", "")
            index = int(row["type_definition_index"], 0)
            if index not in owning_indices and owner not in RELATED_OWNER_NAMES:
                continue
            name = row.get("field_name", "")
            matches[owner].append({
                "name": name, "fieldType": row.get("field_type", ""),
                "fieldIndex": int(row["field_index"], 0),
                "typeDefinitionIndex": index,
                "matchesCommunityKey": name in FIELDS,
            })

    methods = defaultdict(list)
    with methods_csv.open(encoding="utf-8-sig", newline="") as f:
        for row in csv.DictReader(f):
            index = int(row["type_definition_index"], 0)
            if index not in owning_indices and row.get("type_name") not in RELATED_OWNER_NAMES:
                continue
            methods[row["type_name"]].append({
                "methodIndex": int(row["method_index"], 0),
                "methodName": row["method_name"],
                "rva": row.get("rva", ""),
                "parameters": row.get("parameter_types", ""),
            })
    missing = [name for name in FIELDS if not any(
        field["name"] == name for fields in matches.values() for field in fields
    )]
    return {
        "status": "NATIVE_METADATA_SCHEMA_IDENTITY__FIELD_OFFSETS_NOT_VALIDATED",
        "requestedCommunityFieldTokens": list(FIELDS),
        "unmatchedTokens": missing,
        "matchingOwnerCount": len(owning_indices),
        "ownerIndices": dict(sorted((str(k), v) for k, v in owners_by_index.items())),
        "fieldsByOwner": dict(sorted(matches.items())),
        "methodsByOwner": dict(sorted(methods.items())),
        "limitation": "Metadata names/types/method RVAs are identities only; source layouts, reader transforms and scene payload decode remain unverified.",
    }


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--fields", type=Path, required=True)
    p.add_argument("--methods", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()
    result = locate(args.fields, args.methods)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print("WORLD_AREA_SCHEMA_PROBE_BEGIN")
    print(json.dumps({
        "unmatchedTokens": result["unmatchedTokens"],
        "matchingOwnerCount": result["matchingOwnerCount"],
        "owners": [
            {
                "owner": owner,
                "fieldTokens": [x["name"] for x in fields if x["matchesCommunityKey"]],
                "readerCandidates": [
                    {"method": method["methodName"], "rva": method["rva"]}
                    for method in result["methodsByOwner"].get(owner, [])
                    if "FNIAHJGHFAK" in method["parameters"]
                ],
                "methodCount": len(result["methodsByOwner"].get(owner, [])),
            } for owner, fields in result["fieldsByOwner"].items()
        ],
    }, indent=2))
    print("WORLD_AREA_SCHEMA_PROBE_END")


if __name__ == "__main__":
    main()
