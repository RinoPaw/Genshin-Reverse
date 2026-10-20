#!/usr/bin/env python3
"""Read-only original Global 7.1 chest prefab name/field controls.

This audits 20 specific Gadget definitions present in the SHA-256-pinned
GadgetExcelConfigData export: Default/Locked/Bramble/Frozen x Lv1..Lv5.
"Lv" comes from the literal original-client name; this code does not assert
an official reward-grade enum, chest placement or a server payout table.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path

from genshinre.assetindex import unwrap_mihoyo_bin_data
from genshinre.gadgetbin import scan_gadget_payload

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = (ROOT / "versions/7.1.0-global/analyses/progression/economy"
          / "7.1-chest-native-gadget-prefab-controls.json")
RAW_BYTES = 2854888
RAW_SHA256 = "a35e3f3ed04f950cb6302099d12aa71e23ece21d8fe578950347d9318f769e35"
PAYLOAD_SHA256 = "b8f35d6f3fe1aec90398ccbbe205335fe0d9ae45245b206096be5e434746c354"
COUNT = 30599
KINDS = ("Default", "Locked", "Bramble", "Frozen")
ICON = "UI_Icon_Intee_TreasureBox"
BOOL_PRESENT_TRUE = (0x78, 0x7D, 0x7E)
OTHER_BOOL = (0x79, 0x7A, 0x7B, 0x7C, 0x7F)


def controls(scan, payload: bytes) -> dict:
    by_id = {row.id_candidate: row for row in scan.rows}
    if len(by_id) != len(scan.rows):
        raise ValueError("duplicate Gadget candidate ID in prefab audit")
    findings = []
    for level in range(1, 6):
        for variant_id, style in enumerate(KINDS, start=1):
            candidate_id = 70210000 + level * 10 + variant_id
            name = f"SceneObj_Chest_{style}_Lv{level}"
            row = by_id.get(candidate_id)
            if row is None:
                raise ValueError(f"original chest prefab candidate {candidate_id} missing")
            fields = row.fields
            if (fields.get(0x58) != name or fields.get(0x6C) != 26
                    or fields.get(0x50) != ICON
                    or fields.get(0x84) != 2
                    or any(fields.get(off) is not True for off in BOOL_PRESENT_TRUE)
                    or any(off in fields for off in OTHER_BOOL)):
                raise ValueError(f"original prefab fields differ at {candidate_id}")
            observed_list = fields.get(0x48)
            if (observed_list != ["item"]) if level == 1 else (0x48 in fields):
                raise ValueError(f"original prefab list-presence differs at {candidate_id}")
            prefix = payload[row.prefix_start:row.id_wire_offset]
            if (len(prefix) != 18
                    or prefix[:2] != b"\x91\xab"
                    or row.inner_start - row.prefix_start != 22):
                raise ValueError(f"original prefab outer prefix differs at {candidate_id}")
            findings.append({
                "gadgetIdCandidate": candidate_id,
                "nativeNameString": name,
                "nameSuffixLevel": level,
                "nameVariant": style,
                "sourceTypeCandidate": 26,
                "outerControlFirstTwoBytes": "91ab",
                "outerPrefixBytesIncludingCandidateId": 22,
                "nativeIconString": ICON,
                "offset0x84Scalar": 2,
                "booleanTrueOffsets": ["0x78", "0x7D", "0x7E"],
                "offset0x48StringArray": observed_list if observed_list is not None else None,
                "offset0x48PresentOnWire": 0x48 in fields,
            })
    return {
        "schemaVersion": 1,
        "status": "EXACT_7_1_CLIENT_CHEST_PREFAB_NAME_CONTROLS__GRADE_AND_PAYOUT_UNRESOLVED",
        "source": {
            "sample": "7.1.0-global/windows-x64",
            "assetName": "GadgetExcelConfigData",
            "officialClientBlock": "00/25539185.blk",
            "rawExportSha256": RAW_SHA256,
            "payloadSha256": PAYLOAD_SHA256,
            "innerReaderRva": "0x10278E50",
        },
        "controls": {
            "nameVariants": list(KINDS),
            "literalNameSuffixLevels": [1, 2, 3, 4, 5],
            "verifiedGadgetDefinitionCount": len(findings),
            "nativeNameFields": findings,
            "offset0x48List": {
                "presentWithExactlyItem": 4,
                "absentOnWire": 16,
            },
        },
        "limitations": [
            "These 20 definitions are authenticated literal original-client names and candidate row fields.",
            "Lv1..Lv5 are name suffixes, not a proved server chest-grade enum or a payout-tier mapping.",
            "Absent field 0x48 is kept distinct from an empty list; its purpose is not confirmed.",
            "Candidate Gadget IDs still await independent native loader/key-consumer confirmation.",
            "The original 7.1 server scene selectors, reward root ownership, item quantities and rates remain unresolved.",
        ],
    }


def audit(raw: bytes) -> dict:
    if len(raw) != RAW_BYTES or sha256(raw).hexdigest() != RAW_SHA256:
        raise ValueError("original 7.1 Gadget raw SHA-256/size mismatch")
    payload = unwrap_mihoyo_bin_data(raw)
    if sha256(payload).hexdigest() != PAYLOAD_SHA256:
        raise ValueError("original 7.1 Gadget payload SHA-256 mismatch")
    scan = scan_gadget_payload(payload, expected_rows=COUNT)
    return controls(scan, payload)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--raw-export", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=OUTPUT)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    result = audit(args.raw_export.read_bytes())
    if args.check:
        if result != json.loads(args.output.read_text(encoding="utf-8")):
            raise SystemExit("original 7.1 chest prefab observations diverged")
        print("PASS: 20 original chest name/field controls from exact 7.1 client")
    else:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n",
                               encoding="utf-8")
        print("Recorded 20 exact native 7.1 chest prefab name controls")


if __name__ == "__main__":
    main()
