#!/usr/bin/env python3
"""Correlate exact 7.1 Gadget reader stores with metadata field-layout hypotheses.

Reproducible structural evidence only: direct R14 stores alone do not prove an
IL2CPP instance layout, a byte-level on-disk decoder or payout semantics.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from genshinre.nativeprofile import PROFILE_71

ROOT = Path(__file__).resolve().parents[1]
ECONOMY = ROOT / "versions/7.1.0-global/analyses/progression/economy"
SCHEMA = ECONOMY / "7.1-chest-native-gadget-schema-leads.json"
READER = ECONOMY / "7.1-chest-native-gadget-reader-static.json"
OUTPUT = ECONOMY / "7.1-chest-native-gadget-layout-candidate.json"
WIDTHS = {
    "kind_0x1D": 8, "string": 8, "uint64": 8, "bool": 1,
    "uint32": 4, "EEOPHKIFFPL": 4, "CKEFFPHDNBC": 4,
    "IKFOBHFCEOC": 4, "LCKJIPHHGLD": 4,
}
OWNER = "60078"


def align(value: int, width: int) -> int:
    return (value + width - 1) // width * width


def offsets(fields: list[dict], start: int) -> list[dict]:
    result = []
    current = start
    for record in fields:
        kind = record["type"]
        if kind not in WIDTHS:
            raise ValueError(f"unclassified native metadata type {kind}")
        width = WIDTHS[kind]
        current = align(current, width)
        result.append({
            "fieldName": record["name"], "fieldIndex": int(record["index"]),
            "metadataType": kind, "candidateWidth": width,
            "candidateInstanceOffset": f"0x{current:X}",
        })
        current += width
    return result


def correlate(schema: dict, reader: dict) -> dict:
    if (schema["sample"] != PROFILE_71.identity
            or reader["source"]["sample"] != PROFILE_71.identity
            or schema["metadata"]["exeSha256"] != PROFILE_71.exe_sha256
            or reader["source"]["exeSha256"] != PROFILE_71.exe_sha256
            or schema["metadata"]["globalMetadataSha256"] != PROFILE_71.metadata_sha256
            or reader["source"]["metadataSha256"] != PROFILE_71.metadata_sha256):
        raise ValueError("7.1 native source identity mismatch")
    if (reader["source"]["nativeOwner"] != schema["owners"][OWNER]["methods"][1].get("ownerName",
                                                                                reader["source"]["nativeOwner"])
            or reader["source"]["typeDefinitionIndex"] != int(OWNER)
            or reader["source"]["methodIndex"] != 483590
            or reader["source"]["methodRva"] != "0x10278E50"):
        raise ValueError("unexpected Gadget reader identity")
    owner = schema["owners"][OWNER]
    fields = owner["fields"]
    if owner["fieldCount"] != len(fields) or len(fields) != 22:
        raise ValueError("unexpected Gadget owner field count")
    if len({r["name"] for r in fields}) != len(fields):
        raise ValueError("duplicate Gadget metadata field names")
    if [int(f["index"]) for f in fields] != list(range(298606, 298628)):
        raise ValueError("Gadget metadata declaration order changed")

    direct = reader["directStoresToR14"]
    signature = {(int(offset, 16), int(width)) for width, items in direct.items()
                 for offset in items}
    if sum(len(items) for items in direct.values()) != len(signature):
        raise ValueError("duplicate direct store offset/width")
    matched = []
    for start in range(0x10, 0xC1, 8):
        mapping = offsets(fields, start)
        predicted = {(int(row["candidateInstanceOffset"], 16), row["candidateWidth"])
                     for row in mapping}
        if predicted == signature:
            matched.append((start, mapping))
    if len(matched) != 1:
        raise ValueError(f"Gadget width/alignment model matched {len(matched)} starts")
    start, mapping = matched[0]
    for row in mapping:
        loc = row["candidateInstanceOffset"]
        row["directStoreRvas"] = direct[str(row["candidateWidth"])][loc]

    return {
        "schemaVersion": 1,
        "status": "EXACT_NATIVE_STORE_SIGNATURE_MATCHES_ONE_CANDIDATE_LAYOUT__WIRE_UNRESOLVED",
        "sample": PROFILE_71.identity,
        "owner": reader["source"]["nativeOwner"],
        "ownerTypeDefinitionIndex": int(OWNER),
        "readerMethodIndex": reader["source"]["methodIndex"],
        "readerRva": reader["source"]["methodRva"],
        "sourceReports": [SCHEMA.name, READER.name],
        "assumptions": {
            "objectFieldBaseCandidate": f"0x{start:X}",
            "objectHeaderAndInheritedFieldsBeforeCandidate": "UNRESOLVED",
            "fieldOrder": "exact metadata declaration order",
            "pointerWidth": 8,
            "uint64Alignment": 8,
            "unknownManagedWrappers": "candidate 4-byte storage; native layout and wire transforms unverified",
            "readerRegister": "r14",
            "scanLimit": "first ret in pinned static reader trace",
        },
        "result": {
            "metadataFields": len(fields),
            "matchedDirectStoreOffsets": len(signature),
            "candidateBaseMatches": 1,
            "mapping": mapping,
        },
        "limitations": [
            "The mapping is consistent with all recorded R14 direct stores, conditional on width and alignment assumptions.",
            "This does not independently prove an IL2CPP field-offset table or inherited base layout.",
            "A memory-store mapping is not a serialized GadgetExcel decoder or evidence of all row values.",
            "Opaque native names and bool fields have no authenticated semantic labels yet.",
            "No chest grade, special context, instance drop tag, payout root or probabilities are certified.",
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--schema", type=Path, default=SCHEMA)
    parser.add_argument("--reader", type=Path, default=READER)
    parser.add_argument("--output", type=Path, default=OUTPUT)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    data = correlate(json.loads(args.schema.read_text(encoding="utf-8")),
                     json.loads(args.reader.read_text(encoding="utf-8")))
    if args.check:
        if json.loads(args.output.read_text(encoding="utf-8")) != data:
            raise SystemExit("7.1 Gadget layout candidate diverges from pinned evidence")
        print("PASS: one full 22-field layout matches pinned R14 direct stores")
    else:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
        print(f"Wrote {args.output}")


if __name__ == "__main__":
    main()
