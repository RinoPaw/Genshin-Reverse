from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


REQUEST_CMD = 9369
CANDIDATE_CMDS = {36641, 20290}
NOTIFY_CMD = 25567
EXPECTED_S2C_RVA = "0xA01846A"
EXPECTED_C2S_RVA = "0xA01A0EF"


def read_varint(data: bytes, pos: int) -> tuple[int, int]:
    value = 0
    shift = 0
    for _ in range(10):
        if pos >= len(data):
            raise ValueError("truncated varint")
        byte = data[pos]
        pos += 1
        value |= (byte & 0x7F) << shift
        if not (byte & 0x80):
            return value, pos
        shift += 7
    raise ValueError("varint too long")


def decode_packet_head_varints(head_hex: str) -> dict[int, list[int]]:
    """Decode enough protobuf wire format to recover PacketHead varint fields.

    Same-version public 7.1 protocol controls retain client_sequence_id as field 3.
    Unknown length/fixed fields are skipped so this does not depend on a full
    PacketHead schema.
    """

    if not head_hex:
        return {}
    data = bytes.fromhex(head_hex)
    out: dict[int, list[int]] = {}
    pos = 0
    while pos < len(data):
        key, pos = read_varint(data, pos)
        field = key >> 3
        wire = key & 7
        if field == 0:
            raise ValueError("invalid protobuf field 0")
        if wire == 0:
            value, pos = read_varint(data, pos)
            out.setdefault(field, []).append(value)
        elif wire == 1:
            pos += 8
        elif wire == 2:
            size, pos = read_varint(data, pos)
            pos += size
        elif wire == 5:
            pos += 4
        else:
            raise ValueError(f"unsupported protobuf wire type {wire}")
        if pos > len(data):
            raise ValueError("truncated protobuf field")
    return out


def client_sequence_id(payload: dict[str, Any]) -> int | None:
    try:
        fields = decode_packet_head_varints(str(payload.get("head_hex") or ""))
    except (ValueError, TypeError):
        return None
    values = fields.get(3) or []
    return values[-1] if values else None


@dataclass
class PacketEvent:
    record_index: int
    packet_index: int
    timestamp_utc: str | None
    direction: str
    cmd_id: int
    payload: dict[str, Any]
    client_sequence_id: int | None

    def compact(self) -> dict[str, Any]:
        return {
            "record_index": self.record_index,
            "packet_index": self.packet_index,
            "timestamp_utc": self.timestamp_utc,
            "direction": self.direction,
            "cmd_id": self.cmd_id,
            "client_sequence_id": self.client_sequence_id,
            "head_size": self.payload.get("head_size"),
            "body_size": self.payload.get("body_size"),
            "frame_size": self.payload.get("frame_size"),
        }


def load_capture(path: Path) -> tuple[list[PacketEvent], list[dict[str, Any]]]:
    packets: list[PacketEvent] = []
    ready: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as capture:
        for record_index, line in enumerate(capture):
            line = line.strip()
            if not line:
                continue
            row = json.loads(line)
            if row.get("kind") != "packet_probe":
                continue
            payload = row.get("payload")
            if not isinstance(payload, dict):
                continue
            if payload.get("ready"):
                ready.append(payload)
                continue
            if "cmd_id" not in payload:
                continue
            try:
                cmd_id = int(payload["cmd_id"])
            except (TypeError, ValueError):
                continue
            packets.append(
                PacketEvent(
                    record_index=record_index,
                    packet_index=len(packets),
                    timestamp_utc=row.get("timestamp_utc"),
                    direction=str(payload.get("direction") or "?"),
                    cmd_id=cmd_id,
                    payload=payload,
                    client_sequence_id=client_sequence_id(payload),
                )
            )
    return packets, ready


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


def analyze_transaction(
    packets: list[PacketEvent],
    request_index: int,
    after_events: int,
) -> dict[str, Any]:
    request = packets[request_index]
    end = min(len(packets), request_index + 1 + after_events)
    for index in range(request_index + 1, end):
        packet = packets[index]
        if packet.direction == "C2S" and packet.cmd_id == REQUEST_CMD:
            end = index
            break

    window = packets[request_index:end]
    responses = [
        packet
        for packet in window[1:]
        if packet.direction == "S2C" and packet.cmd_id in CANDIDATE_CMDS
    ]
    notifies = [
        packet
        for packet in window[1:]
        if packet.direction == "S2C" and packet.cmd_id == NOTIFY_CMD
    ]
    request_sequence = request.client_sequence_id
    same_sequence = [
        packet
        for packet in responses
        if request_sequence is not None and packet.client_sequence_id == request_sequence
    ]

    distinct_all = sorted({packet.cmd_id for packet in responses})
    distinct_same = sorted({packet.cmd_id for packet in same_sequence})

    if len(distinct_same) == 1:
        verdict = "promotable"
        mapped_cmd_id = distinct_same[0]
        reason = (
            "exactly one response candidate shares PacketHead field 3 "
            "(clientSequenceId) with the confirmed C2S 9369 request"
        )
    elif len(distinct_same) > 1:
        verdict = "ambiguous"
        mapped_cmd_id = None
        reason = "both response candidates share the request clientSequenceId"
    elif request_sequence is None:
        if len(distinct_all) == 1:
            verdict = "candidate-observed-no-sequence"
            mapped_cmd_id = distinct_all[0]
            reason = (
                "exactly one candidate appears in the narrow event window, "
                "but request PacketHead field 3 was unavailable"
            )
        elif len(distinct_all) > 1:
            verdict = "ambiguous"
            mapped_cmd_id = None
            reason = "both candidates appear and no request sequence id is available"
        else:
            verdict = "no-candidate"
            mapped_cmd_id = None
            reason = "no response candidate appears in the narrow event window"
    else:
        if len(distinct_all) == 1:
            verdict = "candidate-observed-sequence-mismatch"
            mapped_cmd_id = distinct_all[0]
            reason = (
                "one candidate appears, but its PacketHead field 3 does not match "
                "the request; do not promote without reviewing the capture"
            )
        elif len(distinct_all) > 1:
            verdict = "ambiguous"
            mapped_cmd_id = None
            reason = "both candidates appear, but neither uniquely matches request sequence"
        else:
            verdict = "no-candidate"
            mapped_cmd_id = None
            reason = "no response candidate appears in the narrow event window"

    return {
        "request": request.compact(),
        "window_packet_count": len(window),
        "candidate_responses": [packet.compact() for packet in responses],
        "same_sequence_candidates": [packet.compact() for packet in same_sequence],
        "scene_point_unlock_notifies": [packet.compact() for packet in notifies],
        "verdict": verdict,
        "mapped_cmd_id": mapped_cmd_id,
        "reason": reason,
        "window": [packet.compact() for packet in window],
    }


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

    packets, ready = load_capture(args.capture)
    transactions = [
        analyze_transaction(packets, index, args.after_events)
        for index, packet in enumerate(packets)
        if packet.direction == "C2S" and packet.cmd_id == REQUEST_CMD
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
