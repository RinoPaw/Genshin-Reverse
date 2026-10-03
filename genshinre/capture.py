from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from .wire import parse_message


def decode_head_varints(head_hex: str) -> dict[int, list[int]]:
    """Decode varint fields from a protobuf packet-head hex string."""

    if not head_hex:
        return {}
    fields: dict[int, list[int]] = {}
    for item in parse_message(bytes.fromhex(head_hex)):
        if item.get("wire_type") != 0:
            continue
        field_number = int(item["field_number"])
        fields.setdefault(field_number, []).append(int(item["value"]))
    return fields


def sequence_value(payload: dict[str, Any], field_number: int = 3) -> int | None:
    """Return the last varint value for the selected packet-head field."""

    try:
        values = decode_head_varints(str(payload.get("head_hex") or "")).get(field_number, [])
    except (TypeError, ValueError):
        return None
    return values[-1] if values else None


@dataclass(frozen=True)
class PacketEvent:
    record_index: int
    packet_index: int
    timestamp_utc: str | None
    direction: str
    cmd_id: int
    payload: dict[str, Any]
    sequence_value: int | None

    def compact(self) -> dict[str, Any]:
        return {
            "record_index": self.record_index,
            "packet_index": self.packet_index,
            "timestamp_utc": self.timestamp_utc,
            "direction": self.direction,
            "cmd_id": self.cmd_id,
            "sequence_value": self.sequence_value,
            "head_size": self.payload.get("head_size"),
            "body_size": self.payload.get("body_size"),
            "frame_size": self.payload.get("frame_size"),
        }


def load_packet_probe_capture(
    path: Path,
    *,
    sequence_field: int = 3,
    event_kind: str = "packet_probe",
) -> tuple[list[PacketEvent], list[dict[str, Any]]]:
    """Load packet events and probe-ready records from an NDJSON capture."""

    if sequence_field <= 0:
        raise ValueError("sequence_field must be positive")

    packets: list[PacketEvent] = []
    ready: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as capture:
        for record_index, line in enumerate(capture):
            line = line.strip()
            if not line:
                continue
            row = json.loads(line)
            if row.get("kind") != event_kind:
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
                    sequence_value=sequence_value(payload, sequence_field),
                )
            )
    return packets, ready


def correlate_transaction(
    packets: list[PacketEvent],
    request_index: int,
    *,
    request_cmd: int,
    candidate_cmds: Iterable[int],
    sequence_field: int = 3,
    after_events: int = 24,
    request_direction: str = "C2S",
    response_direction: str = "S2C",
) -> dict[str, Any]:
    """Correlate one request with response candidates in a bounded event window."""

    if after_events <= 0:
        raise ValueError("after_events must be positive")
    candidate_set = {int(value) for value in candidate_cmds}
    if not candidate_set:
        raise ValueError("candidate_cmds must not be empty")
    if not (0 <= request_index < len(packets)):
        raise IndexError("request_index is outside packet list")

    request = packets[request_index]
    if request.direction != request_direction or request.cmd_id != request_cmd:
        raise ValueError("request_index does not point at the requested transaction start")

    end = min(len(packets), request_index + 1 + after_events)
    for index in range(request_index + 1, end):
        packet = packets[index]
        if packet.direction == request_direction and packet.cmd_id == request_cmd:
            end = index
            break

    window = packets[request_index:end]
    responses = [
        packet
        for packet in window[1:]
        if packet.direction == response_direction and packet.cmd_id in candidate_set
    ]
    request_sequence = request.sequence_value
    same_sequence = [
        packet
        for packet in responses
        if request_sequence is not None and packet.sequence_value == request_sequence
    ]

    distinct_all = sorted({packet.cmd_id for packet in responses})
    distinct_same = sorted({packet.cmd_id for packet in same_sequence})

    if len(distinct_same) == 1:
        verdict = "promotable"
        mapped_cmd_id = distinct_same[0]
        reason = (
            f"exactly one response candidate shares packet-head field {sequence_field} "
            "with the request"
        )
    elif len(distinct_same) > 1:
        verdict = "ambiguous"
        mapped_cmd_id = None
        reason = f"multiple response candidates share packet-head field {sequence_field}"
    elif request_sequence is None:
        if len(distinct_all) == 1:
            verdict = "candidate-observed-no-sequence"
            mapped_cmd_id = distinct_all[0]
            reason = (
                "exactly one candidate appears in the bounded event window, "
                f"but request packet-head field {sequence_field} is unavailable"
            )
        elif len(distinct_all) > 1:
            verdict = "ambiguous"
            mapped_cmd_id = None
            reason = (
                "multiple candidates appear and the request sequence field is unavailable"
            )
        else:
            verdict = "no-candidate"
            mapped_cmd_id = None
            reason = "no response candidate appears in the bounded event window"
    else:
        if len(distinct_all) == 1:
            verdict = "candidate-observed-sequence-mismatch"
            mapped_cmd_id = distinct_all[0]
            reason = (
                "one candidate appears, but its sequence field does not match the request"
            )
        elif len(distinct_all) > 1:
            verdict = "ambiguous"
            mapped_cmd_id = None
            reason = "multiple candidates appear, but none uniquely matches the request sequence"
        else:
            verdict = "no-candidate"
            mapped_cmd_id = None
            reason = "no response candidate appears in the bounded event window"

    return {
        "request": request.compact(),
        "window_packet_count": len(window),
        "candidate_responses": [packet.compact() for packet in responses],
        "same_sequence_candidates": [packet.compact() for packet in same_sequence],
        "verdict": verdict,
        "mapped_cmd_id": mapped_cmd_id,
        "reason": reason,
        "window": [packet.compact() for packet in window],
    }


def correlate_capture(
    packets: list[PacketEvent],
    *,
    request_cmd: int,
    candidate_cmds: Iterable[int],
    sequence_field: int = 3,
    after_events: int = 24,
    request_direction: str = "C2S",
    response_direction: str = "S2C",
) -> list[dict[str, Any]]:
    """Correlate every matching request in an already-loaded packet capture."""

    candidate_values = tuple(int(value) for value in candidate_cmds)
    if not candidate_values:
        raise ValueError("candidate_cmds must not be empty")

    return [
        correlate_transaction(
            packets,
            index,
            request_cmd=request_cmd,
            candidate_cmds=candidate_values,
            sequence_field=sequence_field,
            after_events=after_events,
            request_direction=request_direction,
            response_direction=response_direction,
        )
        for index, packet in enumerate(packets)
        if packet.direction == request_direction and packet.cmd_id == request_cmd
    ]
