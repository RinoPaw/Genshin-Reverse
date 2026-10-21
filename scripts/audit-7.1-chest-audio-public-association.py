#!/usr/bin/env python3
"""Full original 7.1 audio chest scalar-to-public-label association check.

The exact decoded native table stays authoritative for its numeric fields.
Public CN-labelled JSON supplies the separate string label association.
This does not validate native enum names or server reward-grade semantics.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path

NATIVE_RAW_SHA = "c205c6d4efe69fde2b88800802816afd981a94df35e768746f5692e74febe591"
PUBLIC_BLOB = "f2f2f9c05e6333a9dc302b11a1bc39e16f621f5f"
NATIVE_STATUS = "EXACT_7_1_AUDIO_NATIVE_ROW_CANDIDATE_FULL_WIRE_CONSUMPTION__VTABLE_UNRESOLVED"
ID = "AIMCCDKDAKB"
LABEL = "DMNAJDGMHDE"


def original_public_json(raw: bytes) -> list:
    actual = hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
    if actual != PUBLIC_BLOB:
        raise ValueError("unmodified 7.1-labelled public Audio Git blob mismatch")
    return json.loads(raw)


def compare(native: dict, public_rows: list[dict]) -> dict:
    if (native.get("sourceRawSha256") != NATIVE_RAW_SHA
            or native.get("status") != NATIVE_STATUS
            or native.get("nativeHeaderCount") != 56
            or native.get("decodedRecords") != 56
            or native.get("uniquePreWrapperGadgetKeyScalars") != 56
            or native.get("payloadBytes") != 480
            or native.get("unparsedBytes") != 0
            or len(native.get("rows", [])) != 56):
        raise ValueError("source-pinned original 7.1 Audio decoded table evidence changed")
    if len(public_rows) != 56:
        raise ValueError("public Audio row count changed")
    key_labels = {}
    for row in public_rows:
        if not isinstance(row, dict) or set(row) - {ID, LABEL}:
            raise ValueError("unexpected public Audio row schema")
        key = row.get(ID)
        if type(key) is not int or key in key_labels:
            raise ValueError("duplicate or missing public Audio gadget scalar")
        label = row.get(LABEL)
        if label is not None and (not isinstance(label, str) or not label):
            raise ValueError("invalid public Audio classification")
        key_labels[key] = label
    pairs = Counter()
    native_keys = set()
    key_mismatches = []
    by_scalar: dict[str, set[str]] = defaultdict(set)
    for row in native["rows"]:
        key = row["gadgetIdPreWrapperScalar"]
        if type(key) is not int or key in native_keys:
            raise ValueError("invalid or duplicate original decoded key")
        native_keys.add(key)
        if key not in key_labels:
            key_mismatches.append(key)
            continue
        scalar = row["nativeClassScalar"]
        if scalar is not None and type(scalar) is not int:
            raise ValueError("invalid original native numeric class field")
        if (row["nativeClassFieldPresent"] != (scalar is not None)):
            raise ValueError("original presence status differs from scalar")
        raw_value = "(absent)" if scalar is None else str(scalar)
        public_value = "(absent)" if key_labels[key] is None else key_labels[key]
        pairs[(raw_value, public_value)] += 1
        by_scalar[raw_value].add(public_value)
    if key_mismatches or native_keys != set(key_labels):
        raise ValueError("original and public chest key sets differ")
    return {
        "schemaVersion": 1,
        "status": "EXACT_71_NATIVE_AUDIO_56_ROW_VALUES_JOIN_PUBLIC_LABELS__LABEL_AUTHORITY_UNVERIFIED",
        "nativeRawSha256": NATIVE_RAW_SHA,
        "publicGitBlob": PUBLIC_BLOB,
        "matchedDistinctNativePreWrapperGadgetScalars": len(native_keys),
        "nativeValueToPublicLabelPairs": [
            {"nativeNumericScalar": scalar, "publicAudioLabel": label, "matchingRows": n}
            for (scalar, label), n in sorted(pairs.items())
        ],
        "nativeScalarsWithMultiplePublicLabels": sorted(
            [scalar for scalar, labels in by_scalar.items() if len(labels) > 1]
        ),
        "limitations": [
            "The native byte-perfect source establishes numeric values and field presence; the public JSON is a separate label projection.",
            "Exact one-to-one numerical correspondence with public Mid/Hi/Top does not independently recover original IL2CPP enum symbolic names.",
            "The key is the native pre-wrapper scalar; runtime substitution/getter equivalence is not independently proved.",
            "Audio classification cannot be promoted into chest reward grade, scene placement, drop_tag, payout, item count or probability.",
        ],
    }


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--native-report", type=Path, required=True)
    p.add_argument("--public-audio", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()
    r = compare(json.loads(args.native_report.read_text(encoding="utf-8")),
                original_public_json(args.public_audio.read_bytes()))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(r, indent=2, ensure_ascii=False)+"\n",encoding="utf-8")
    print(json.dumps(r, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
