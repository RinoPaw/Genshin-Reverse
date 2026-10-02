from __future__ import annotations

import argparse
import json
from datetime import datetime
from pathlib import Path

from parse_decrypted_game_packet import parse_frames

REQUEST_CMD = 9369
CANDIDATE_CMDS = {36641, 20290}
UNLOCK_NOTIFY_CMD = 25567


def parse_timestamp(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def load_events(path: Path) -> list[dict[str, object]]:
    events = []
    with path.open("r", encoding="utf-8") as f:
        for line_no, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            row = json.loads(line)
            if row.get("kind") != "packet_probe":
                continue
            payload = row.get("payload")
            if not isinstance(payload, dict) or "cmd_id" not in payload:
                continue
            event = {
                "line": line_no,
                "timestamp": parse_timestamp(str(row["timestamp_utc"])),
                "direction": payload.get("direction"),
                "cmd_id": int(payload["cmd_id"]),
                "head_hex": payload.get("head_hex") or "",
                "frame_hex": payload.get("frame_hex"),
                "frame_size": payload.get("frame_size"),
                "head_size": payload.get("head_size"),
                "body_size": payload.get("body_size"),
            }
            frame_hex = event["frame_hex"]
            if frame_hex:
                packets = parse_frames(bytes.fromhex(str(frame_hex)))
                if len(packets) != 1:
                    raise ValueError(f"line {line_no}: watched frame contains {len(packets)} packets")
                packet = packets[0]
                if packet.cmd_id != event["cmd_id"]:
                    raise ValueError(
                        f"line {line_no}: event CmdId {event['cmd_id']} != framed CmdId {packet.cmd_id}"
                    )
                if event["frame_size"] is not None and packet.size != int(event["frame_size"]):
                    raise ValueError(
                        f"line {line_no}: event frame size {event['frame_size']} != parsed {packet.size}"
                    )
            events.append(event)
    return events


def summarize_event(event: dict[str, object], request_time: datetime) -> dict[str, object]:
    return {
        "line": event["line"],
        "delta_ms": round((event["timestamp"] - request_time).total_seconds() * 1000, 3),
        "direction": event["direction"],
        "cmd_id": event["cmd_id"],
        "frame_size": event["frame_size"],
        "head_size": event["head_size"],
        "body_size": event["body_size"],
        "head_hex": event["head_hex"],
        "full_frame_preserved": bool(event["frame_hex"]),
    }


def main() -> None:
    p = argparse.ArgumentParser(
        description=(
            "Correlate a maintained 7.1 decrypted-packet capture around C2S UnlockTransPointReq "
            "and report which surviving S2C response candidate occurs."
        )
    )
    p.add_argument("capture", type=Path)
    p.add_argument("--window-seconds", type=float, default=5.0)
    p.add_argument("--max-events", type=int, default=120)
    args = p.parse_args()

    events = load_events(args.capture)
    requests = [
        (i, event)
        for i, event in enumerate(events)
        if event["direction"] == "C2S" and event["cmd_id"] == REQUEST_CMD
    ]

    transactions = []
    for request_number, (index, request) in enumerate(requests, 1):
        start = request["timestamp"]
        window = [request]
        for event in events[index + 1 :]:
            delta = (event["timestamp"] - start).total_seconds()
            if delta < 0:
                continue
            if delta > args.window_seconds or len(window) >= args.max_events:
                break
            if event["direction"] == "C2S" and event["cmd_id"] == REQUEST_CMD:
                break
            window.append(event)

        candidate_events = [
            event for event in window
            if event["direction"] == "S2C" and event["cmd_id"] in CANDIDATE_CMDS
        ]
        candidate_ids = sorted({int(event["cmd_id"]) for event in candidate_events})
        notify_events = [
            event for event in window
            if event["direction"] == "S2C" and event["cmd_id"] == UNLOCK_NOTIFY_CMD
        ]

        if len(candidate_ids) == 1:
            verdict = "unique_candidate_observed"
        elif len(candidate_ids) > 1:
            verdict = "ambiguous_both_candidates_observed"
        else:
            verdict = "no_candidate_observed"

        transactions.append(
            {
                "request_number": request_number,
                "request_line": request["line"],
                "request_timestamp": request["timestamp"].isoformat(),
                "verdict": verdict,
                "candidate_cmd_ids": candidate_ids,
                "scene_point_unlock_notify_seen": bool(notify_events),
                "watched_candidate_events": [
                    summarize_event(event, start) for event in candidate_events
                ],
                "window": [summarize_event(event, start) for event in window],
            }
        )

    result = {
        "capture": str(args.capture),
        "window_seconds": args.window_seconds,
        "packet_event_count": len(events),
        "unlock_request_count": len(requests),
        "transactions": transactions,
        "promotion_note": (
            "unique_candidate_observed is a packet-level observation only. Promote the semantic mapping "
            "only when the capture source is a known-correct pinned 7.1 client/server transaction."
        ),
    }
    print(json.dumps(result, indent=2, ensure_ascii=False, default=str))


if __name__ == "__main__":
    main()
