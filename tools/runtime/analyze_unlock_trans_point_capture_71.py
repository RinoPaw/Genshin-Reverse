from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from genshinre.capture import correlate_capture, load_packet_probe_capture


REQUEST_CMD = 9369
CANDIDATE_CMDS = {36641, 20290}
NOTIFY_CMD = 25567
SEQUENCE_FIELD = 3
EXPECTED_S2C_RVA = "0xA01846A"
EXPECTED_C2S_RVA = "0xA01A0EF"


def validate_probe(ready: list[dict[str, Any]]) -> dict[str, Any]:
    exact = [
        row
        for row in ready
        if str(row.get("s2c_post_xor_rva", "")).upper() == EXPECTED_S2C_RVA.upper()
        and str(row.get("c2s_pre_xor_rva", "")).upper() == EXPECTED_C2S_RVA.upper()
    ]
    return {
        "ready_events": len(ready),
        "expected_s2c_post_xor_rva": EXPECTED_S2C_RVA,
        "expected_c2s_pre_xor_rva": EXPECTED_C2S_RVA,
        "matching_ready_events": len(exact),
        "validated": bool(exact),
    }


def _compat_packet(row: dict[str, Any]) -> dict[str, Any]:
    result = dict(row)
    result["client_sequence_id"] = result.pop("sequence_value", None)
    return result


def _compat_transaction(transaction: dict[str, Any]) -> dict[str, Any]:
    result = dict(transaction)
    result["request"] = _compat_packet(transaction["request"])
    result["candidate_responses"] = [
        _compat_packet(row) for row in transaction["candidate_responses"]
    ]
    result["same_sequence_candidates"] = [
        _compat_packet(row) for row in transaction["same_sequence_candidates"]
    ]
    result["window"] = [_compat_packet(row) for row in transaction["window"]]
    result["scene_point_unlock_notifies"] = [
        row
        for row in result["window"][1:]
        if row["direction"] == "S2C" and row["cmd_id"] == NOTIFY_CMD
    ]
    return result


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Correlate current-7.1 decrypted packet captures around UnlockTransPointReq "
            "and determine whether CmdId 36641 or 20290 is the matching response."
        )
    )
    parser.add_argument("capture", type=Path)
    parser.add_argument("--after-events", type=int, default=24)
    parser.add_argument("--json", dest="json_output", type=Path)
    args = parser.parse_args()

    if args.after_events <= 0:
        raise SystemExit("--after-events must be positive")

    packets, ready = load_packet_probe_capture(
        args.capture,
        sequence_field=SEQUENCE_FIELD,
    )
    transactions = [
        _compat_transaction(transaction)
        for transaction in correlate_capture(
            packets,
            request_cmd=REQUEST_CMD,
            candidate_cmds=CANDIDATE_CMDS,
            sequence_field=SEQUENCE_FIELD,
            after_events=args.after_events,
        )
    ]
    result = {
        "capture": str(args.capture),
        "probe_validation": validate_probe(ready),
        "packet_count": len(packets),
        "request_count": len(transactions),
        "transactions": transactions,
        "promotion_rule": (
            "promote only when a confirmed C2S 9369 request has exactly one S2C "
            "candidate with the same PacketHead field 3 clientSequenceId; otherwise "
            "preserve the capture and review surrounding traffic"
        ),
    }

    if args.json_output:
        args.json_output.parent.mkdir(parents=True, exist_ok=True)
        args.json_output.write_text(
            json.dumps(result, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )

    probe_validation = result["probe_validation"]
    print(
        "probe:",
        "validated" if probe_validation["validated"] else "unvalidated",
        f"ready={probe_validation['ready_events']}",
        f"matching={probe_validation['matching_ready_events']}",
    )
    print("packets:", len(packets), "unlock requests:", len(transactions))
    for index, transaction in enumerate(transactions, 1):
        request = transaction["request"]
        print(
            f"[{index}] C2S {REQUEST_CMD} packet#{request['packet_index']} "
            f"seq={request['client_sequence_id']} -> "
            f"{transaction['verdict']}"
            + (
                f" cmd={transaction['mapped_cmd_id']}"
                if transaction["mapped_cmd_id"] is not None
                else ""
            )
        )
        print("    ", transaction["reason"])
        if transaction["candidate_responses"]:
            print(
                "     candidates:",
                ", ".join(
                    f"{packet['cmd_id']}@#{packet['packet_index']}/seq={packet['client_sequence_id']}"
                    for packet in transaction["candidate_responses"]
                ),
            )
        if transaction["scene_point_unlock_notifies"]:
            print(
                "     notify:",
                ", ".join(
                    f"25567@#{packet['packet_index']}/seq={packet['client_sequence_id']}"
                    for packet in transaction["scene_point_unlock_notifies"]
                ),
            )


if __name__ == "__main__":
    main()
